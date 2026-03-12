# Made With

A high-performance API for detecting website technology stacks. Powered by **3,700+ Wappalyzer fingerprints** with async parallelism — scan up to 5,000 domains per request.

Self-contained. No Redis, no PostgreSQL, no Celery.

## Features

- **Bulk scanning** — submit up to 5,000 domains in a single request, scanned concurrently
- **3,700+ technology fingerprints** — detects frameworks, CMS platforms, analytics tools, CDNs, JavaScript libraries, and more
- **Fast** — async HTTP fetching with `httpx` (HTTP/2, connection pooling), HTML parsing offloaded to thread pool
- **Smart detection** — matches against HTML, headers, cookies, meta tags, script sources, URL patterns, and visible text
- **Version extraction** — resolves version numbers from regex capture groups using Wappalyzer's back-reference syntax
- **Relationship resolution** — handles `implies`, `excludes`, `requires`, and `requiresCategory` between technologies
- **In-memory caching** — results cached for 1 hour with automatic background cleanup (no external dependencies)
- **Rate limiting** — per-IP sliding window rate limiter (300 req/min on `/scan`)
- **API key authentication** — all endpoints secured via `X-API-Key` header

## Quick Start

### Prerequisites

- Python 3.10+

### Installation

```bash
git clone https://github.com/MikeH1021/made-with.git
cd made-with
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running

Set your API key and start the server:

```bash
export API_KEY="your-secret-key"
python run.py
```

The server starts on port `9000` by default. Configuration via environment variables:

| Variable    | Default                  | Description                        |
|-------------|--------------------------|------------------------------------|
| `API_KEY`   | *(required)*             | API key for authentication         |
| `HOST`      | `0.0.0.0`               | Bind address                       |
| `PORT`      | `9000`                   | Bind port                          |
| `WORKERS`   | `2 × CPU cores + 1`     | Number of uvicorn workers (max 40) |
| `LOG_LEVEL` | `info`                   | Log level                          |

## API Reference

### `POST /scan`

Scan one or more domains for their technology stack.

**Headers:**
```
X-API-Key: your-secret-key
Content-Type: application/json
```

**Request body:**

```json
{
  "domains": ["github.com", "shopify.com"],
  "max_concurrency": 50,
  "timeout": 15,
  "skip_cache": false
}
```

| Field             | Type     | Default | Description                              |
|-------------------|----------|---------|------------------------------------------|
| `domains`         | string[] | —       | Domains to scan (1–5,000)                |
| `max_concurrency` | int      | `50`    | Max parallel HTTP fetches (1–200)        |
| `timeout`         | int      | `15`    | Per-domain HTTP timeout in seconds (5–60)|
| `skip_cache`      | bool     | `false` | Bypass cache and force re-scan           |

**Response:**

```json
{
  "total_domains": 2,
  "successful": 2,
  "failed": 0,
  "duration_ms": 1423,
  "results": [
    {
      "domain": "github.com",
      "url": "https://github.com/",
      "status": "success",
      "technologies": [
        {
          "name": "React",
          "slug": "react",
          "confidence": 100,
          "version": "18.2.0",
          "categories": [
            { "id": 12, "name": "JavaScript frameworks", "slug": "javascript-frameworks" }
          ],
          "website": "https://reactjs.org",
          "description": "React is a JavaScript library for building user interfaces.",
          "icon": "React.png",
          "cpe": "cpe:2.3:a:facebook:react:*:*:*:*:*:*:*:*"
        }
      ],
      "technology_count": 12,
      "error": null,
      "scan_duration_ms": 834,
      "cached": false
    }
  ]
}
```

### `GET /health`

Health check with system stats.

**Headers:**
```
X-API-Key: your-secret-key
```

**Response:**

```json
{
  "status": "healthy",
  "technologies_loaded": 3742,
  "conditional_technologies": 184,
  "categories": 109,
  "cache_size": 42,
  "uptime_seconds": 3600.5,
  "version": "1.0.0"
}
```

## How It Works

1. **Fetch** — Domains are fetched concurrently using `httpx` with HTTP/2 support. HTTPS is tried first, falling back to HTTP. Responses are capped at 5 MB.

2. **Parse** — HTML is parsed with BeautifulSoup/lxml in a thread pool to avoid blocking the async event loop. Meta tags, script sources, headers, and cookies are extracted into structured data.

3. **Match** — The extracted page data is matched against 3,700+ Wappalyzer fingerprints. Each fingerprint can define patterns for HTML content, HTTP headers, cookies, meta tags, script URLs, page text, CSS, and URL patterns.

4. **Resolve** — Technology relationships are resolved: `implies` adds implied technologies, `excludes` removes conflicting ones, and `requires`/`requiresCategory` gates conditional detections. Confidence scores are aggregated and versions are extracted from regex capture groups.

## Project Structure

```
├── main.py            # FastAPI app, routes, auth, rate limiting
├── scanner.py         # Async domain fetching and HTML parsing
├── wappalyzer.py      # Technology fingerprint engine
├── cache.py           # In-memory TTL cache
├── run.py             # Production launcher (uvicorn)
├── test_scan.py       # Integration test suite
├── fingerprints/      # 3,700+ Wappalyzer technology fingerprints
│   ├── categories.json
│   ├── _.json
│   └── [a-z].json
└── requirements.txt
```

## Running Tests

Start the server, then run the test suite against it:

```bash
export API_KEY="your-secret-key"
python run.py &
python test_scan.py
```

The test suite covers health checks, single/multi-domain scans, error handling, deduplication, caching, and rate limit headers.

## Tech Stack

- [FastAPI](https://fastapi.tiangolo.com/) — async web framework
- [uvicorn](https://www.uvicorn.org/) — ASGI server
- [httpx](https://www.python-httpx.org/) — async HTTP client with HTTP/2
- [BeautifulSoup](https://www.crummy.com/software/BeautifulSoup/) + [lxml](https://lxml.de/) — HTML parsing
- [Wappalyzer](https://www.wappalyzer.com/) — technology fingerprint database
