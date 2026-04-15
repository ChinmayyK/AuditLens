#!/usr/bin/env python3
"""
Test PR Trigger — Tests POST /api/v1/review/github-pr

Sends a real request to the local FastAPI server to test
the PR ingestion endpoint. Uses a public repo so no
private access is needed.

Usage:
    # Set env vars first:
    set WEBHOOK_SECRET=your_secret_here

    # Run:
    python scripts/test_pr_trigger.py

    # Or with custom params:
    python scripts/test_pr_trigger.py --repo https://github.com/octocat/Hello-World --pr 1
"""
import os
import sys
import argparse
import json

try:
    import httpx
except ImportError:
    import requests as httpx  # fallback

API_BASE = os.getenv(
    "AUDITLENS_API_URL",
    "http://localhost:8000",
)
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dev-secret")


def test_pr_trigger(repo_url: str, pr_number: int):
    """Send a PR review request to the local API."""
    url = f"{API_BASE}/api/v1/review/github-pr"
    payload = {
        "repo_url": repo_url,
        "pr_number": pr_number,
    }
    headers = {
        "Content-Type": "application/json",
        "X-Webhook-Secret": WEBHOOK_SECRET,
    }

    print("=" * 60)
    print("  AuditLens PR Review — Trigger Test")
    print("=" * 60)
    print(f"\n📡 Target:  {url}")
    print(f"📦 Payload: {json.dumps(payload, indent=2)}")
    print(f"🔑 Secret:  {WEBHOOK_SECRET[:4]}...{WEBHOOK_SECRET[-4:]}")
    print()

    try:
        if hasattr(httpx, 'post') and hasattr(httpx, 'Client'):
            # httpx
            resp = httpx.post(
                url, json=payload, headers=headers,
                timeout=30,
            )
            status = resp.status_code
            body = resp.json() if resp.status_code < 500 else resp.text
        else:
            # requests fallback
            resp = httpx.post(
                url, json=payload, headers=headers,
                timeout=30,
            )
            status = resp.status_code
            body = resp.json() if resp.status_code < 500 else resp.text

        print(f"📬 Status: {status}")
        print(f"📄 Response:")
        if isinstance(body, dict):
            print(json.dumps(body, indent=2))
        else:
            print(body[:500])

        if status == 200:
            print("\n✅ PR review trigger SUCCESS")
            review_id = body.get("review_id", "N/A") if isinstance(body, dict) else "N/A"
            print(f"   Review ID: {review_id}")
        elif status == 401:
            print("\n❌ AUTH FAILED — check WEBHOOK_SECRET")
        elif status == 400:
            print("\n❌ BAD REQUEST — check repo_url format")
        elif status == 422:
            print("\n❌ VALIDATION ERROR — check payload schema")
        else:
            print(f"\n⚠️ Unexpected status: {status}")

    except Exception as e:
        print(f"\n❌ Connection failed: {e}")
        print("   Is the FastAPI server running?")
        print(f"   Try: cd api && uvicorn main:app --reload")
        sys.exit(1)


def test_health():
    """Quick health check before the actual test."""
    url = f"{API_BASE}/api/v1/health"
    print(f"🏥 Health check: {url}")
    try:
        if hasattr(httpx, 'get') and hasattr(httpx, 'Client'):
            resp = httpx.get(url, timeout=5)
        else:
            resp = httpx.get(url, timeout=5)

        if resp.status_code == 200:
            print(f"   ✅ Server is healthy\n")
            return True
        else:
            print(f"   ⚠️ Server returned {resp.status_code}\n")
            return True  # Still try the main test
    except Exception:
        print(f"   ❌ Server not reachable at {API_BASE}\n")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test AuditLens PR review trigger"
    )
    parser.add_argument(
        "--repo",
        default="https://github.com/fastapi/fastapi",
        help="GitHub repo URL (default: fastapi/fastapi)",
    )
    parser.add_argument(
        "--pr",
        type=int,
        default=1,
        help="PR number (default: 1)",
    )
    parser.add_argument(
        "--skip-health",
        action="store_true",
        help="Skip health check",
    )
    args = parser.parse_args()

    if not args.skip_health:
        if not test_health():
            print("Aborting — server not reachable.")
            sys.exit(1)

    test_pr_trigger(args.repo, args.pr)
