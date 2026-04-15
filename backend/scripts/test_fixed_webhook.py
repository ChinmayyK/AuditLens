#!/usr/bin/env python3
"""
Test Fixed Webhook — Simulates a GitHub issue_comment event.

Constructs a realistic GitHub webhook payload with:
  - action: "created"
  - comment body containing "fixed"
  - issue with pull_request key (it's a PR)
  - Valid HMAC-SHA256 signature

Usage:
    # Set env vars first:
    set WEBHOOK_SECRET=your_secret_here

    # Run:
    python scripts/test_fixed_webhook.py

    # With custom PR:
    python scripts/test_fixed_webhook.py --repo octocat/Hello-World --pr 42
"""
import os
import sys
import hmac
import hashlib
import json
import argparse

try:
    import httpx
except ImportError:
    import requests as httpx

API_BASE = os.getenv(
    "AUDITLENS_API_URL",
    "http://localhost:8000",
)
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "dev-secret")


def build_github_payload(
    owner: str, repo: str, pr_number: int,
    commenter: str = "test-user",
) -> dict:
    """Build a realistic GitHub issue_comment webhook payload."""
    return {
        "action": "created",
        "issue": {
            "number": pr_number,
            "title": f"Test PR #{pr_number}",
            "html_url": (
                f"https://github.com/{owner}/{repo}"
                f"/pull/{pr_number}"
            ),
            "pull_request": {
                "url": (
                    f"https://api.github.com/repos/"
                    f"{owner}/{repo}/pulls/{pr_number}"
                ),
            },
            "user": {
                "login": "pr-author",
            },
        },
        "comment": {
            "id": 999999,
            "body": (
                "I've addressed the security findings. "
                "The SQL injection is fixed and I've "
                "rotated the leaked API key. "
                "Please re-review."
            ),
            "user": {
                "login": commenter,
            },
            "created_at": "2026-04-15T08:00:00Z",
            "html_url": (
                f"https://github.com/{owner}/{repo}"
                f"/pull/{pr_number}#issuecomment-999999"
            ),
        },
        "repository": {
            "id": 123456,
            "name": repo,
            "full_name": f"{owner}/{repo}",
            "html_url": (
                f"https://github.com/{owner}/{repo}"
            ),
            "private": False,
            "owner": {
                "login": owner,
            },
        },
        "sender": {
            "login": commenter,
        },
    }


def compute_hmac_signature(
    payload_bytes: bytes, secret: str
) -> str:
    """Compute GitHub-style HMAC-SHA256 signature."""
    signature = hmac.new(
        secret.encode(),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()
    return f"sha256={signature}"


def test_webhook(
    owner: str, repo: str, pr_number: int
):
    """Send a simulated GitHub webhook to the local API."""
    url = f"{API_BASE}/api/v1/webhooks/github"

    # Build payload
    payload = build_github_payload(
        owner, repo, pr_number
    )
    payload_bytes = json.dumps(payload).encode()

    # Compute signature
    signature = compute_hmac_signature(
        payload_bytes, WEBHOOK_SECRET
    )

    headers = {
        "Content-Type": "application/json",
        "X-GitHub-Event": "issue_comment",
        "X-Hub-Signature-256": signature,
        "X-GitHub-Delivery": "test-delivery-123",
    }

    print("=" * 60)
    print("  AuditLens Webhook — Fixed Comment Test")
    print("=" * 60)
    print(f"\n📡 Target:     {url}")
    print(f"📦 Event:      issue_comment")
    print(f"📝 Comment:    contains 'fixed'")
    print(f"🔑 HMAC:       {signature[:30]}...")
    print(f"📂 Repo:       {owner}/{repo}")
    print(f"🔢 PR:         #{pr_number}")
    print()

    try:
        resp = httpx.post(
            url,
            content=payload_bytes,
            headers=headers,
            timeout=30,
        )
        status = resp.status_code
        body = resp.json() if status < 500 else resp.text

        print(f"📬 Status: {status}")
        print(f"📄 Response:")
        if isinstance(body, dict):
            print(json.dumps(body, indent=2))
        else:
            print(body[:500])

        if status == 200:
            if isinstance(body, dict):
                webhook_status = body.get("status", "")
                if webhook_status == "re_scan_queued":
                    print("\n✅ WEBHOOK SUCCESS — Re-scan queued!")
                    print(f"   Review ID: {body.get('review_id', 'N/A')}")
                    print(f"   Triggered by: {body.get('triggered_by', 'N/A')}")
                elif webhook_status == "ignored":
                    print(f"\n⚠️ Webhook ignored: {body.get('reason', 'unknown')}")
                elif webhook_status == "error":
                    print(f"\n⚠️ Webhook error: {body.get('message', 'unknown')}")
                else:
                    print(f"\n📋 Status: {webhook_status}")
        elif status == 401:
            print("\n❌ HMAC VERIFICATION FAILED")
            print("   Check that WEBHOOK_SECRET matches server config")
        else:
            print(f"\n⚠️ Unexpected status: {status}")

    except Exception as e:
        print(f"\n❌ Connection failed: {e}")
        print("   Is the FastAPI server running?")
        sys.exit(1)

    # ── Additional tests ───────────────────────────────
    print("\n" + "─" * 60)
    print("  Additional Webhook Tests")
    print("─" * 60)

    # Test 1: Wrong signature
    print("\n🧪 Test: Invalid HMAC signature")
    bad_headers = {**headers, "X-Hub-Signature-256": "sha256=bad"}
    try:
        resp = httpx.post(
            url,
            content=payload_bytes,
            headers=bad_headers,
            timeout=10,
        )
        if resp.status_code == 401:
            print("   ✅ Correctly rejected (401)")
        else:
            print(f"   ⚠️ Got {resp.status_code} instead of 401")
    except Exception as e:
        print(f"   ❌ {e}")

    # Test 2: Non-fixed comment
    print("\n🧪 Test: Comment without 'fixed'")
    no_fix_payload = build_github_payload(
        owner, repo, pr_number
    )
    no_fix_payload["comment"]["body"] = (
        "Looks good to me, nice work!"
    )
    no_fix_bytes = json.dumps(no_fix_payload).encode()
    no_fix_sig = compute_hmac_signature(
        no_fix_bytes, WEBHOOK_SECRET
    )
    try:
        resp = httpx.post(
            url,
            content=no_fix_bytes,
            headers={
                **headers,
                "X-Hub-Signature-256": no_fix_sig,
            },
            timeout=10,
        )
        body = resp.json()
        if body.get("status") == "ignored":
            print(f"   ✅ Correctly ignored: {body.get('reason')}")
        else:
            print(f"   ⚠️ Got: {body}")
    except Exception as e:
        print(f"   ❌ {e}")

    # Test 3: Regular issue (not PR)
    print("\n🧪 Test: Comment on issue (not PR)")
    issue_payload = build_github_payload(
        owner, repo, pr_number
    )
    issue_payload["comment"]["body"] = "This is fixed now"
    del issue_payload["issue"]["pull_request"]
    issue_bytes = json.dumps(issue_payload).encode()
    issue_sig = compute_hmac_signature(
        issue_bytes, WEBHOOK_SECRET
    )
    try:
        resp = httpx.post(
            url,
            content=issue_bytes,
            headers={
                **headers,
                "X-Hub-Signature-256": issue_sig,
            },
            timeout=10,
        )
        body = resp.json()
        if body.get("status") == "ignored":
            print(f"   ✅ Correctly ignored: {body.get('reason')}")
        else:
            print(f"   ⚠️ Got: {body}")
    except Exception as e:
        print(f"   ❌ {e}")

    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Test AuditLens webhook (fixed comment)"
    )
    parser.add_argument(
        "--repo",
        default="octocat/Hello-World",
        help="owner/repo format (default: octocat/Hello-World)",
    )
    parser.add_argument(
        "--pr",
        type=int,
        default=1,
        help="PR number (default: 1)",
    )
    args = parser.parse_args()

    parts = args.repo.split("/")
    if len(parts) != 2:
        print("❌ --repo must be in owner/repo format")
        sys.exit(1)

    test_webhook(parts[0], parts[1], args.pr)
