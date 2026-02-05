"""
Tech Stack Detection API

High-performance FastAPI application that detects website technology
stacks using 3,700+ Wappalyzer fingerprints. Self-contained — no Redis,
no PostgreSQL, no Celery.

Usage:
    uvicorn main:app --host 0.0.0.0 --port 8000 --workers 4
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
import uuid
from collections import defaultdict
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from wappalyzer import WappalyzerEngine
from scanner import scan_domains, normalize_domain
from cache import TTLCache

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger("techstack-api")

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    domains: list[str] = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="List of domains to scan (max 5000 per request)",
        examples=[["example.com", "github.com"]],
    )
    max_concurrency: int = Field(
        default=50,
        ge=1,
        le=200,
        description="Max parallel HTTP fetches",
    )
    timeout: int = Field(
        default=15,
        ge=5,
        le=60,
        description="HTTP timeout per domain in seconds",
    )
    skip_cache: bool = Field(
        default=False,
        description="Bypass cache and force re-scan",
    )


class TechnologyMatch(BaseModel):
    name: str
    slug: str
    confidence: int
    version: str | None = None
    categories: list[dict] = []
    website: str | None = None
    description: str | None = None
    icon: str | None = None
    cpe: str | None = None


class DomainResult(BaseModel):
    domain: str
    url: str | None = None
    status: str = "success"
    technologies: list[TechnologyMatch] = []
    technology_count: int = 0
    error: str | None = None
    scan_duration_ms: int = 0
    cached: bool = False


class ScanResponse(BaseModel):
    total_domains: int
    successful: int
    failed: int
    duration_ms: int
    results: list[DomainResult]


class HealthResponse(BaseModel):
    status: str
    technologies_loaded: int
    conditional_technologies: int
    categories: int
    cache_size: int
    uptime_seconds: float
    version: str


# ---------------------------------------------------------------------------
# Rate limiter (simple in-memory, per-IP)
# ---------------------------------------------------------------------------

class RateLimiter:
    """Sliding-window rate limiter per client IP."""

    def __init__(self, requests_per_minute: int = 30):
        self.rpm = requests_per_minute
        self._buckets: dict[str, list[float]] = defaultdict(list)
        self._last_cleanup = time.monotonic()

    def _maybe_cleanup(self, now: float) -> None:
        """Periodically remove stale IPs that haven't been seen in 5+ minutes."""
        if now - self._last_cleanup < 300:
            return
        self._last_cleanup = now
        window = now - 300
        stale = [ip for ip, ts in self._buckets.items() if not ts or ts[-1] < window]
        for ip in stale:
            del self._buckets[ip]

    def check(self, client_ip: str) -> bool:
        """Returns True if the request is allowed."""
        now = time.monotonic()
        self._maybe_cleanup(now)
        window = now - 60
        bucket = self._buckets[client_ip]
        # Prune old entries
        self._buckets[client_ip] = [t for t in bucket if t > window]
        if len(self._buckets[client_ip]) >= self.rpm:
            return False
        self._buckets[client_ip].append(now)
        return True

    def remaining(self, client_ip: str) -> int:
        now = time.monotonic()
        window = now - 60
        bucket = [t for t in self._buckets.get(client_ip, []) if t > window]
        return max(0, self.rpm - len(bucket))


# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
engine: WappalyzerEngine | None = None
cache = TTLCache(default_ttl=3600)
rate_limiter = RateLimiter(requests_per_minute=300)
start_time = 0.0

# ---------------------------------------------------------------------------
# API Key Authentication
# ---------------------------------------------------------------------------
API_KEY = os.environ.get("API_KEY")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def require_api_key(api_key: str | None = Depends(api_key_header)) -> str:
    """Dependency that validates the API key from X-API-Key header."""
    if not API_KEY:
        raise HTTPException(
            status_code=500,
            detail="API_KEY environment variable not configured",
        )
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="Missing API key. Provide X-API-Key header.",
        )
    if api_key != API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid API key",
        )
    return api_key


@asynccontextmanager
async def lifespan(app: FastAPI):
    global engine, start_time
    start_time = time.monotonic()

    logger.info("Loading Wappalyzer fingerprints...")
    engine = WappalyzerEngine()
    total = len(engine.technologies) + len(engine._conditional_techs)
    logger.info(
        "Ready — %d technologies (%d conditional), %d categories",
        total,
        len(engine._conditional_techs),
        len(engine.categories),
    )

    # Background cache cleanup
    async def _cleanup():
        while True:
            await asyncio.sleep(300)
            cache.clear_expired()

    cleanup_task = asyncio.create_task(_cleanup())
    yield
    cleanup_task.cancel()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Tech Stack Detection API",
    description=(
        "High-performance API for detecting website technology stacks. "
        "Powered by 3,700+ Wappalyzer fingerprints with async parallelism. "
        "Submit up to 5,000 domains per request — they're scanned concurrently."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Middleware: request logging + rate limiting
# ---------------------------------------------------------------------------

@app.middleware("http")
async def request_middleware(request: Request, call_next):
    request_id = str(uuid.uuid4())[:8]
    client_ip = request.client.host if request.client else "unknown"
    start = time.monotonic()

    # Rate limit on scan endpoint
    if request.url.path == "/scan" and request.method == "POST":
        if not rate_limiter.check(client_ip):
            return Response(
                content='{"detail":"Rate limit exceeded. Max 300 requests/minute."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": "60"},
            )

    response = await call_next(request)

    elapsed = int((time.monotonic() - start) * 1000)
    logger.info(
        "[%s] %s %s %s — %dms",
        request_id,
        client_ip,
        request.method,
        request.url.path,
        elapsed,
    )

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Rate-Limit-Remaining"] = str(rate_limiter.remaining(client_ip))
    return response


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health(_: str = Depends(require_api_key)):
    """Health check with system stats."""
    total = 0
    conditional = 0
    cats = 0
    if engine:
        total = len(engine.technologies) + len(engine._conditional_techs)
        conditional = len(engine._conditional_techs)
        cats = len(engine.categories)

    return HealthResponse(
        status="healthy",
        technologies_loaded=total,
        conditional_technologies=conditional,
        categories=cats,
        cache_size=cache.size,
        uptime_seconds=round(time.monotonic() - start_time, 1),
        version="1.0.0",
    )


@app.post("/scan", response_model=ScanResponse, tags=["Scanning"])
async def scan(request: ScanRequest, _: str = Depends(require_api_key)):
    """
    Scan one or more domains for their technology stack.

    - Accepts up to **5,000 domains** per request
    - Domains are fetched in parallel (configurable concurrency, default 50)
    - Results cached for 1 hour (use `skip_cache: true` to bypass)
    - HTTPS first, HTTP fallback
    - Returns detected technologies with name, version, confidence, and categories
    """
    if engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    scan_start = time.monotonic()

    # Deduplicate and normalize
    seen: set[str] = set()
    unique_domains: list[str] = []
    for d in request.domains:
        normalized = normalize_domain(d)
        if normalized and normalized not in seen:
            seen.add(normalized)
            unique_domains.append(normalized)

    if not unique_domains:
        raise HTTPException(status_code=400, detail="No valid domains provided")

    # Clear cache for these domains if skip_cache
    if request.skip_cache:
        for d in unique_domains:
            cache.delete(f"scan:{d}")

    # Run scan with an overall timeout so one request can't hold a worker forever.
    # Formula: allow ~(timeout) seconds per batch of (concurrency) domains, plus buffer.
    n_batches = (len(unique_domains) + request.max_concurrency - 1) // request.max_concurrency
    overall_timeout = min(n_batches * request.timeout + 30, 600)  # cap at 10 minutes

    try:
        raw_results = await asyncio.wait_for(
            scan_domains(
                unique_domains,
                engine,
                cache,
                max_concurrency=request.max_concurrency,
                timeout=request.timeout,
            ),
            timeout=overall_timeout,
        )
    except asyncio.TimeoutError:
        raise HTTPException(
            status_code=504,
            detail=f"Scan timed out after {overall_timeout}s. Try fewer domains or a shorter per-domain timeout.",
        )

    # Build response
    domain_results: list[DomainResult] = []
    successful = 0
    failed = 0

    for r in raw_results:
        techs = [TechnologyMatch(**t) for t in r.get("technologies", [])]
        error = r.get("error")
        dr = DomainResult(
            domain=r["domain"],
            url=r.get("url"),
            status="error" if error else "success",
            technologies=techs,
            technology_count=len(techs),
            error=error,
            scan_duration_ms=r.get("scan_duration_ms", 0),
            cached=r.get("cached", False),
        )
        domain_results.append(dr)
        if error:
            failed += 1
        else:
            successful += 1

    total_ms = int((time.monotonic() - scan_start) * 1000)

    return ScanResponse(
        total_domains=len(domain_results),
        successful=successful,
        failed=failed,
        duration_ms=total_ms,
        results=domain_results,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        workers=4,
        log_level="info",
    )
