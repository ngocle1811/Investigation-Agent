"""Smoke-check a running backend and its dependencies."""

import argparse
import sys

import httpx


def main() -> int:
    """Return zero only when the backend reports all dependencies ready."""

    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://localhost:18000")
    args = parser.parse_args()
    response = httpx.get(f"{args.url.rstrip('/')}/health", timeout=10)
    response.raise_for_status()
    payload = response.json()
    print(payload)
    return 0 if payload.get("status") == "ok" else 1


if __name__ == "__main__":
    sys.exit(main())
