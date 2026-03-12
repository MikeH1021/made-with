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
from fastapi.responses import HTMLResponse
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
demo_rate_limiter = RateLimiter(requests_per_minute=3)
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

@app.get("/", response_class=HTMLResponse, tags=["System"])
async def root():
    """Public landing page with live demo."""
    tech_count = 0
    cat_count = 0
    if engine:
        tech_count = len(engine.technologies) + len(engine._conditional_techs)
        cat_count = len(engine.categories)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Made With — Tech Stack Detection API</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e5e5e5; min-height: 100vh; }}
  a {{ color: #60a5fa; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}

  .container {{ max-width: 720px; margin: 0 auto; padding: 60px 24px; }}

  h1 {{ font-size: 2.5rem; font-weight: 700; color: #fff; margin-bottom: 8px; }}
  h1 span {{ color: #60a5fa; }}
  .subtitle {{ font-size: 1.1rem; color: #888; margin-bottom: 48px; line-height: 1.5; }}

  .stats {{ display: flex; gap: 32px; margin-bottom: 48px; }}
  .stat {{ text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; color: #60a5fa; }}
  .stat-label {{ font-size: 0.8rem; color: #666; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px; }}

  .demo {{ background: #141414; border: 1px solid #262626; border-radius: 12px; padding: 32px; margin-bottom: 48px; }}
  .demo h2 {{ font-size: 1.1rem; color: #fff; margin-bottom: 16px; }}
  .input-row {{ display: flex; gap: 12px; }}
  .input-row input {{ flex: 1; padding: 12px 16px; background: #0a0a0a; border: 1px solid #333; border-radius: 8px; color: #fff; font-size: 1rem; outline: none; transition: border-color 0.2s; }}
  .input-row input:focus {{ border-color: #60a5fa; }}
  .input-row input::placeholder {{ color: #555; }}
  .input-row button {{ padding: 12px 24px; background: #60a5fa; color: #000; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: opacity 0.2s; white-space: nowrap; }}
  .input-row button:hover {{ opacity: 0.85; }}
  .input-row button:disabled {{ opacity: 0.5; cursor: not-allowed; }}

  #results {{ margin-top: 20px; }}
  .result-loading {{ color: #888; font-size: 0.9rem; padding: 16px 0; }}
  .result-error {{ color: #f87171; font-size: 0.9rem; padding: 16px 0; }}
  .result-meta {{ color: #666; font-size: 0.8rem; margin-bottom: 12px; }}

  .tech-grid {{ display: flex; flex-wrap: wrap; gap: 8px; }}
  .tech-tag {{ display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; background: #1a1a2e; border: 1px solid #2a2a4a; border-radius: 6px; font-size: 0.85rem; color: #c5c5e0; transition: border-color 0.2s; }}
  .tech-tag:hover {{ border-color: #60a5fa; }}
  .tech-conf {{ font-size: 0.7rem; color: #60a5fa; font-weight: 600; }}
  .tech-ver {{ font-size: 0.7rem; color: #888; }}
  .tech-cat {{ font-size: 0.65rem; color: #555; display: block; margin-top: 2px; }}

  .features {{ margin-bottom: 48px; }}
  .features h2 {{ font-size: 1.3rem; color: #fff; margin-bottom: 20px; }}
  .feature-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .feature {{ background: #141414; border: 1px solid #262626; border-radius: 10px; padding: 20px; }}
  .feature-title {{ font-size: 0.95rem; color: #fff; font-weight: 600; margin-bottom: 6px; }}
  .feature-desc {{ font-size: 0.8rem; color: #777; line-height: 1.5; }}

  .api-section {{ background: #141414; border: 1px solid #262626; border-radius: 12px; padding: 32px; margin-bottom: 48px; }}
  .api-section h2 {{ font-size: 1.1rem; color: #fff; margin-bottom: 16px; }}
  pre {{ background: #0a0a0a; border: 1px solid #262626; border-radius: 8px; padding: 16px; overflow-x: auto; font-size: 0.8rem; line-height: 1.6; color: #a5b4c4; }}
  .code-comment {{ color: #555; }}
  .code-string {{ color: #a5d6a7; }}
  .code-key {{ color: #90caf9; }}

  footer {{ text-align: center; color: #444; font-size: 0.8rem; padding-top: 16px; border-top: 1px solid #1a1a1a; }}

  @media (max-width: 600px) {{
    .feature-grid {{ grid-template-columns: 1fr; }}
    .stats {{ gap: 20px; }}
    .input-row {{ flex-direction: column; }}
    h1 {{ font-size: 2rem; }}
  }}
</style>
</head>
<body>
<div class="container">
  <h1>Made <span>With</span></h1>
  <p class="subtitle">Detect the tech stack behind any website. Powered by {tech_count:,}+ fingerprints, async parallelism, and zero external dependencies.</p>

  <div class="stats">
    <div class="stat"><div class="stat-num">{tech_count:,}</div><div class="stat-label">Technologies</div></div>
    <div class="stat"><div class="stat-num">{cat_count}</div><div class="stat-label">Categories</div></div>
    <div class="stat"><div class="stat-num">5,000</div><div class="stat-label">Domains / Request</div></div>
  </div>

  <div class="demo">
    <h2>Try it</h2>
    <div class="input-row">
      <input type="text" id="domain-input" placeholder="Enter a domain, e.g. stripe.com" autocomplete="off" spellcheck="false">
      <button id="scan-btn" onclick="doScan()">Scan</button>
    </div>
    <div id="results"></div>
  </div>

  <div class="features">
    <h2>Features</h2>
    <div class="feature-grid">
      <div class="feature">
        <div class="feature-title">Bulk Scanning</div>
        <div class="feature-desc">Submit up to 5,000 domains in one request. All scanned concurrently with configurable parallelism.</div>
      </div>
      <div class="feature">
        <div class="feature-title">Deep Detection</div>
        <div class="feature-desc">Matches HTML, headers, cookies, meta tags, script sources, URL patterns, and page text.</div>
      </div>
      <div class="feature">
        <div class="feature-title">Version Extraction</div>
        <div class="feature-desc">Resolves version numbers from regex capture groups — know exactly which version is running.</div>
      </div>
      <div class="feature">
        <div class="feature-title">Zero Dependencies</div>
        <div class="feature-desc">No Redis, no Postgres, no Celery. In-memory caching and rate limiting, ready to deploy anywhere.</div>
      </div>
    </div>
  </div>

  <div class="api-section">
    <h2>Quick Start</h2>
    <pre><span class="code-comment"># Scan a domain</span>
curl -X POST {_request_url()}/scan \\
  -H <span class="code-string">"X-API-Key: YOUR_KEY"</span> \\
  -H <span class="code-string">"Content-Type: application/json"</span> \\
  -d '<span class="code-string">{{"domains": ["github.com", "shopify.com"]}}</span>'</pre>
  </div>

  <footer>
    <a href="/docs">API Docs</a> &nbsp;&middot;&nbsp;
    <a href="https://github.com/MikeH1021/made-with">GitHub</a>
  </footer>
</div>

<script>
const input = document.getElementById('domain-input');
const btn = document.getElementById('scan-btn');
const results = document.getElementById('results');

input.addEventListener('keydown', e => {{ if (e.key === 'Enter') doScan(); }});

async function doScan() {{
  const domain = input.value.trim();
  if (!domain) return;

  btn.disabled = true;
  btn.textContent = 'Scanning...';
  results.innerHTML = '<div class="result-loading">Scanning ' + domain.replace(/</g,'&lt;') + '...</div>';

  try {{
    const resp = await fetch('/demo-scan?domain=' + encodeURIComponent(domain));
    const data = await resp.json();

    if (!resp.ok) {{
      results.innerHTML = '<div class="result-error">' + (data.detail || 'Request failed') + '</div>';
      return;
    }}

    const r = data;
    if (r.status === 'error') {{
      results.innerHTML = '<div class="result-error">Error: ' + (r.error || 'Unknown error') + '</div>';
      return;
    }}

    let html = '<div class="result-meta">' + r.technology_count + ' technologies detected in ' + r.scan_duration_ms + 'ms</div>';
    html += '<div class="tech-grid">';
    for (const t of r.technologies) {{
      const ver = t.version ? ' <span class="tech-ver">v' + t.version + '</span>' : '';
      const cat = t.categories.length ? '<span class="tech-cat">' + t.categories[0].name + '</span>' : '';
      html += '<div class="tech-tag"><span>' + t.name + ver + '</span><span class="tech-conf">' + t.confidence + '%</span></div>';
    }}
    html += '</div>';
    results.innerHTML = html;
  }} catch (err) {{
    results.innerHTML = '<div class="result-error">Request failed: ' + err.message + '</div>';
  }} finally {{
    btn.disabled = false;
    btn.textContent = 'Scan';
  }}
}}
</script>
</body>
</html>"""


def _request_url():
    """Return the base URL for display in examples."""
    return "https://madewith.mikehernandez.co"


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


@app.get("/demo-scan", tags=["Demo"])
async def demo_scan(domain: str, request: Request):
    """Single-domain scan for the homepage demo (no API key required, brutally rate limited)."""
    client_ip = request.client.host if request.client else "unknown"
    if not demo_rate_limiter.check(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Slow down — demo is limited to 3 scans per minute. Use the API with a key for more.",
        )

    if engine is None:
        raise HTTPException(status_code=503, detail="Engine not initialized")

    normalized = normalize_domain(domain)
    if not normalized:
        raise HTTPException(status_code=400, detail="Invalid domain")

    # Use the same cache
    cached = cache.get(f"scan:{normalized}")
    if cached is not None:
        return {**cached, "cached": True}

    raw_results = await scan_domains(
        [normalized], engine, cache, max_concurrency=5, timeout=20,
    )
    return raw_results[0]


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
