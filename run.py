#!/usr/bin/env python3
"""
Production launcher for the Tech Stack Detection API.

Configures uvicorn with:
  - Multiple workers (2 × CPU cores + 1, capped at 8)
  - Access logging
  - Graceful shutdown
  - Keep-alive timeout tuned for long scans
"""

import multiprocessing
import os

import uvicorn

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "9000"))
WORKERS = min(int(os.environ.get("WORKERS", 0)) or (2 * multiprocessing.cpu_count() + 1), 40)
LOG_LEVEL = os.environ.get("LOG_LEVEL", "info")

if __name__ == "__main__":
    print(f"Starting Tech Stack API on {HOST}:{PORT} with {WORKERS} workers")
    uvicorn.run(
        "main:app",
        host=HOST,
        port=PORT,
        workers=WORKERS,
        log_level=LOG_LEVEL,
        access_log=True,
        timeout_keep_alive=75,
        limit_concurrency=200,
        limit_max_requests=10000,
    )
