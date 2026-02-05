"""
Async domain scanner.

Fetches domains with httpx (async, connection-pooled, HTTP/2), parses
HTML with BeautifulSoup/lxml, and feeds the extracted page data into
the WappalyzerEngine for fingerprint matching.

Supports massive parallelism via asyncio.Semaphore + gather.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx
from bs4 import BeautifulSoup

from wappalyzer import WappalyzerEngine
from cache import TTLCache

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    ),
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;"
        "q=0.9,image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-User": "?1",
}

MAX_HTML_SIZE = 2 * 1024 * 1024  # 2 MB cap
MAX_RESPONSE_BYTES = 5 * 1024 * 1024  # 5 MB — drop responses larger than this
MAX_CONCURRENCY = 100


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def normalize_domain(domain: str) -> str:
    """Strip protocol, www prefix, and trailing slashes."""
    domain = domain.strip().lower()
    for prefix in ("https://", "http://", "//"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    domain = domain.rstrip("/")
    return domain



# ---------------------------------------------------------------------------
# Core scanning
# ---------------------------------------------------------------------------

def _parse_and_analyze(
    engine: WappalyzerEngine,
    response_url: str,
    raw_html: str,
    headers: dict[str, list[str]],
    cookies: dict[str, list[str]],
) -> list[dict]:
    """CPU-bound: parse HTML with BS4 and run fingerprint matching.

    Runs in a thread-pool executor so it never blocks the event loop.
    """
    if len(raw_html) > MAX_HTML_SIZE:
        raw_html = raw_html[:MAX_HTML_SIZE]

    soup = BeautifulSoup(raw_html, "lxml")

    meta: dict[str, list[str]] = {}
    for tag in soup.find_all("meta"):
        key = tag.get("name") or tag.get("property") or tag.get("http-equiv") or ""
        content = tag.get("content", "")
        if key and content:
            meta.setdefault(key.lower(), []).append(content)

    script_src: list[str] = []
    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "")
        if src:
            script_src.append(src)

    text = soup.get_text(separator=" ", strip=True)[:100_000]

    page_data = {
        "url": response_url,
        "html": raw_html,
        "headers": headers,
        "cookies": cookies,
        "meta": meta,
        "script_src": script_src,
        "text": text,
    }
    return engine.analyze(page_data)


async def fetch_and_analyze(
    client: httpx.AsyncClient,
    engine: WappalyzerEngine,
    domain: str,
    timeout: int = 15,
) -> dict[str, Any]:
    """
    Fetch a single domain and run fingerprint analysis.

    Returns a result dict with keys: domain, url, technologies, error, scan_duration_ms
    """
    normalized = normalize_domain(domain)
    start = time.monotonic()
    last_error = None

    for scheme in ("https", "http"):
        url = f"{scheme}://{normalized}"
        try:
            response = await client.get(
                url,
                timeout=httpx.Timeout(
                    connect=min(10, timeout),
                    read=timeout,
                    write=timeout,
                    pool=timeout,
                ),
                follow_redirects=True,
            )

            # Only analyze HTML responses
            ct = response.headers.get("content-type", "")
            if "html" not in ct and "text" not in ct:
                last_error = f"Non-HTML content-type: {ct}"
                continue

            # Guard against absurdly large response bodies
            content_length = response.headers.get("content-length")
            if content_length and int(content_length) > MAX_RESPONSE_BYTES:
                last_error = f"Response too large: {content_length} bytes"
                continue

            # Decode body — truncate early if huge
            raw_bytes = response.content
            if len(raw_bytes) > MAX_RESPONSE_BYTES:
                raw_bytes = raw_bytes[:MAX_RESPONSE_BYTES]

            encoding = response.encoding or "utf-8"
            try:
                html = raw_bytes.decode(encoding, errors="replace")
            except (LookupError, UnicodeDecodeError):
                html = raw_bytes.decode("utf-8", errors="replace")

            # Extract headers and cookies (lightweight, stays on event loop)
            headers: dict[str, list[str]] = {}
            for name, value in response.headers.items():
                headers.setdefault(name.lower(), []).append(value)

            cookies: dict[str, list[str]] = {}
            for name, value in response.cookies.items():
                cookies.setdefault(name.lower(), []).append(value)

            # Run BS4 parsing + fingerprint matching in thread pool
            loop = asyncio.get_running_loop()
            technologies = await loop.run_in_executor(
                None,
                _parse_and_analyze,
                engine,
                str(response.url),
                html,
                headers,
                cookies,
            )

            elapsed = int((time.monotonic() - start) * 1000)
            return {
                "domain": normalized,
                "url": str(response.url),
                "technologies": technologies,
                "technology_count": len(technologies),
                "error": None,
                "scan_duration_ms": elapsed,
                "cached": False,
            }

        except httpx.TimeoutException:
            last_error = "Connection timed out"
            logger.debug("Timeout: %s", url)
        except httpx.ConnectError as e:
            last_error = f"Connection failed: {e}"
            logger.debug("Connect error: %s — %s", url, e)
        except Exception as e:
            last_error = str(e)
            logger.debug("Error fetching %s: %s", url, e)

    elapsed = int((time.monotonic() - start) * 1000)
    return {
        "domain": normalized,
        "url": None,
        "technologies": [],
        "technology_count": 0,
        "error": last_error or "Unknown error",
        "scan_duration_ms": elapsed,
        "cached": False,
    }


async def scan_domains(
    domains: list[str],
    engine: WappalyzerEngine,
    cache: TTLCache,
    max_concurrency: int = MAX_CONCURRENCY,
    timeout: int = 15,
) -> list[dict[str, Any]]:
    """
    Scan multiple domains concurrently with bounded parallelism.

    - Uses an asyncio.Semaphore to limit parallel HTTP fetches
    - Checks the in-memory cache before fetching
    - Caches successful results
    """
    sem = asyncio.Semaphore(max_concurrency)

    limits = httpx.Limits(
        max_connections=max_concurrency,
        max_keepalive_connections=max_concurrency // 2,
        keepalive_expiry=30,
    )

    results: dict[str, dict] = {}

    async with httpx.AsyncClient(
        headers=DEFAULT_HEADERS,
        limits=limits,
        http2=True,
        verify=False,
    ) as client:

        async def _scan_one(domain: str) -> None:
            normalized = normalize_domain(domain)

            # Check cache
            cached = cache.get(f"scan:{normalized}")
            if cached is not None:
                results[normalized] = {**cached, "cached": True}
                return

            try:
                async with sem:
                    result = await fetch_and_analyze(client, engine, domain, timeout)
            except Exception as e:
                logger.error("Unhandled error scanning %s: %s", domain, e)
                result = {
                    "domain": normalized,
                    "url": None,
                    "technologies": [],
                    "technology_count": 0,
                    "error": f"Internal error: {e}",
                    "scan_duration_ms": 0,
                    "cached": False,
                }

            results[normalized] = result

            # Cache successful results
            if result["error"] is None:
                results[normalized]["cached"] = False
                cache.set(f"scan:{normalized}", result)

        tasks = [asyncio.create_task(_scan_one(d)) for d in domains]
        await asyncio.gather(*tasks)

    # Return in original domain order
    ordered = []
    for domain in domains:
        normalized = normalize_domain(domain)
        if normalized in results:
            ordered.append(results[normalized])
        else:
            ordered.append({
                "domain": normalized,
                "url": None,
                "technologies": [],
                "technology_count": 0,
                "error": "Unexpected scan error",
                "scan_duration_ms": 0,
                "cached": False,
            })

    return ordered
