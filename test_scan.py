#!/usr/bin/env python3
"""Comprehensive API test suite — run against a live server on port 8000."""

import json
import sys
import time
import urllib.request

BASE = "http://127.0.0.1:8000"


def post_json(path, data):
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=json.dumps(data).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


def test_health():
    with urllib.request.urlopen(f"{BASE}/health", timeout=5) as resp:
        data = json.loads(resp.read())
    assert data["status"] == "healthy"
    assert data["technologies_loaded"] > 3000
    assert data["categories"] > 100
    print(f"  PASS: health — {data['technologies_loaded']} techs, {data['categories']} cats")


def test_single_domain():
    result = post_json("/scan", {"domains": ["github.com"]})
    assert result["total_domains"] == 1
    assert result["successful"] == 1
    r = result["results"][0]
    assert r["status"] == "success"
    assert r["technology_count"] > 0
    names = [t["name"] for t in r["technologies"]]
    print(f"  PASS: single domain — {r['technology_count']} techs detected on github.com")
    print(f"        → {', '.join(names)}")


def test_error_handling():
    result = post_json("/scan", {"domains": ["nonexistent.invalidtld999"]})
    assert result["total_domains"] == 1
    assert result["failed"] == 1
    r = result["results"][0]
    assert r["status"] == "error"
    assert r["error"] is not None
    print(f"  PASS: error handling — got error: {r['error'][:50]}")


def test_deduplication():
    result = post_json("/scan", {
        "domains": ["github.com", "GITHUB.COM", "https://github.com", "http://github.com/"]
    })
    assert result["total_domains"] == 1
    print(f"  PASS: deduplication — 4 inputs → {result['total_domains']} unique domain")


def test_caching():
    # First scan (may be cached from earlier)
    post_json("/scan", {"domains": ["stripe.com"], "skip_cache": True})

    # Second scan should be cached
    t0 = time.monotonic()
    result = post_json("/scan", {"domains": ["stripe.com"]})
    elapsed = time.monotonic() - t0
    r = result["results"][0]
    assert r["cached"] is True
    print(f"  PASS: caching — cached response in {elapsed*1000:.0f}ms")


def test_skip_cache():
    result = post_json("/scan", {"domains": ["stripe.com"], "skip_cache": True})
    r = result["results"][0]
    assert r["cached"] is False
    print(f"  PASS: skip_cache — forced re-scan ({r['scan_duration_ms']}ms)")


def test_multi_domain_parallel():
    domains = [
        "github.com", "shopify.com", "wordpress.org", "stripe.com",
        "cloudflare.com", "vercel.com", "netlify.com", "stackoverflow.com",
        "digitalocean.com", "twilio.com", "heroku.com", "netflix.com",
        "airbnb.com", "dropbox.com", "slack.com", "notion.so",
        "figma.com", "linear.app", "discord.com", "reddit.com",
    ]
    result = post_json("/scan", {
        "domains": domains,
        "skip_cache": True,
        "max_concurrency": 50,
        "timeout": 30,
    })
    print(f"\n  === 20-DOMAIN PARALLEL SCAN ===")
    print(f"  Total: {result['total_domains']} | Success: {result['successful']} | Failed: {result['failed']} | Duration: {result['duration_ms']}ms")
    print()

    total_techs = 0
    for r in result["results"]:
        status = "OK" if r["status"] == "success" else f"ERR: {r['error']}"
        cached = " (cached)" if r["cached"] else ""
        total_techs += r["technology_count"]
        techs = ", ".join(t["name"] for t in r["technologies"][:6])
        extra = f" +{r['technology_count']-6} more" if r["technology_count"] > 6 else ""
        print(f"  {r['domain']:25s} {r['technology_count']:2d} techs {r['scan_duration_ms']:5d}ms{cached}  {status}")
        if techs:
            print(f"  {'':25s}  → {techs}{extra}")

    print(f"\n  Total technologies detected: {total_techs} across {result['successful']} sites")
    avg_per_site = total_techs / max(result['successful'], 1)
    print(f"  Average per site: {avg_per_site:.1f}")
    throughput = result['successful'] / max(result['duration_ms'] / 1000, 0.001)
    print(f"  Throughput: {throughput:.1f} domains/second")


def test_rate_limit_header():
    with urllib.request.urlopen(f"{BASE}/health", timeout=5) as resp:
        remaining = resp.headers.get("X-Rate-Limit-Remaining")
        request_id = resp.headers.get("X-Request-ID")
    assert request_id is not None
    print(f"  PASS: rate limit headers — X-Request-ID={request_id}, remaining={remaining}")


if __name__ == "__main__":
    print("\n=== Tech Stack API — Test Suite ===\n")

    tests = [
        ("Health check", test_health),
        ("Single domain scan", test_single_domain),
        ("Error handling", test_error_handling),
        ("Domain deduplication", test_deduplication),
        ("Cache hit", test_caching),
        ("Skip cache", test_skip_cache),
        ("Rate limit headers", test_rate_limit_header),
        ("20-domain parallel scan", test_multi_domain_parallel),
    ]

    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            print(f"\n[TEST] {name}")
            fn()
            passed += 1
        except Exception as e:
            print(f"  FAIL: {e}")
            failed += 1

    print(f"\n{'='*50}")
    print(f"Results: {passed} passed, {failed} failed out of {len(tests)} tests")
    sys.exit(1 if failed else 0)
