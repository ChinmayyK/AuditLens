#!/usr/bin/env python3
"""
GitHub Token Validator — Checks if GITHUB_TOKEN has
the required scopes for AuditLens PR reviews.

Required scopes:
  - repo (read PR data, post reviews/comments)
  - For public repos only: public_repo is sufficient

Usage:
    # Set env var:
    set GITHUB_TOKEN=ghp_xxxxxxxxxxxx

    # Or load from .env:
    python scripts/check_github_token.py

    # With explicit token:
    python scripts/check_github_token.py --token ghp_xxxx
"""
import os
import sys
import argparse

try:
    import httpx
except ImportError:
    import requests as httpx


def load_env_file():
    """Try to load .env from common locations."""
    env_paths = [
        os.path.join(os.path.dirname(__file__), "..", ".env"),
        os.path.join(os.path.dirname(__file__), "..", "api", ".env"),
        ".env",
    ]
    for path in env_paths:
        path = os.path.abspath(path)
        if os.path.exists(path):
            print(f"📄 Loading .env from: {path}")
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key and value:
                            os.environ.setdefault(key, value)
            return True
    return False


def check_token(token: str):
    """Validate GitHub token and check scopes."""
    print("=" * 60)
    print("  GitHub Token Validator")
    print("=" * 60)

    if not token:
        print("\n❌ No token provided!")
        print("   Set GITHUB_TOKEN env var or pass --token")
        sys.exit(1)

    # Mask token for display
    masked = token[:4] + "..." + token[-4:]
    print(f"\n🔑 Token: {masked}")
    print(f"📏 Length: {len(token)} chars")

    # Token type detection
    if token.startswith("ghp_"):
        print(f"📋 Type: Classic Personal Access Token")
    elif token.startswith("github_pat_"):
        print(f"📋 Type: Fine-grained Personal Access Token")
    elif token.startswith("ghs_"):
        print(f"📋 Type: GitHub App Installation Token")
    elif token.startswith("gho_"):
        print(f"📋 Type: OAuth Token")
    else:
        print(f"📋 Type: Unknown format")

    # Ping GitHub API
    print(f"\n🌐 Checking token against GitHub API...")
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github.v3+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        resp = httpx.get(
            "https://api.github.com/user",
            headers=headers,
            timeout=10,
        )
    except Exception as e:
        print(f"\n❌ Connection failed: {e}")
        sys.exit(1)

    if resp.status_code == 401:
        print("\n❌ TOKEN IS INVALID")
        print("   The token was rejected by GitHub.")
        print("   Generate a new one at:")
        print("   https://github.com/settings/tokens/new")
        sys.exit(1)

    if resp.status_code == 403:
        print("\n⚠️ TOKEN IS RATE-LIMITED")
        print(f"   Rate limit remaining: {resp.headers.get('x-ratelimit-remaining', '?')}")
        sys.exit(1)

    if resp.status_code != 200:
        print(f"\n❌ Unexpected response: {resp.status_code}")
        print(f"   {resp.text[:200]}")
        sys.exit(1)

    # Token is valid — check user info
    user_data = resp.json()
    print(f"\n✅ TOKEN IS VALID")
    print(f"   👤 User: {user_data.get('login', '?')}")
    print(f"   📧 Name: {user_data.get('name', 'N/A')}")

    # Check scopes from response headers
    scopes_header = resp.headers.get("x-oauth-scopes", "")
    scopes = [
        s.strip() for s in scopes_header.split(",")
        if s.strip()
    ]

    print(f"\n📋 Scopes: {scopes_header or '(none / fine-grained)'}")

    # Required scopes check
    print(f"\n🔍 Scope Analysis:")

    has_repo = "repo" in scopes
    has_public_repo = "public_repo" in scopes
    has_write_discussion = "write:discussion" in scopes

    if scopes:
        # Classic token — check scopes
        if has_repo:
            print(f"   ✅ repo — Full repository access (private + public)")
        elif has_public_repo:
            print(f"   ⚠️ public_repo — Public repos only (no private repos)")
        else:
            print(f"   ❌ Missing 'repo' scope — cannot access PR data")

        # Check for specific capabilities
        if has_repo or has_public_repo:
            print(f"\n   Capabilities for AuditLens:")
            print(f"   ✅ Read PR metadata")
            print(f"   ✅ Fetch PR diff")
            print(f"   ✅ Post PR review comments")
            print(f"   ✅ Post issue comments (summaries)")
            if not has_repo:
                print(f"   ⚠️ Private repos NOT accessible")
        else:
            print(f"\n   ❌ Token lacks required permissions!")
            print(f"   Generate a new token with 'repo' scope:")
            print(f"   https://github.com/settings/tokens/new?scopes=repo")
    else:
        # Fine-grained token or GitHub App — no x-oauth-scopes header
        print(f"   ℹ️ No classic scopes (fine-grained or App token)")
        print(f"   Verifying via API call...")

        # Test by accessing a public repo PR
        test_resp = httpx.get(
            "https://api.github.com/repos/octocat/Hello-World/pulls/1",
            headers=headers,
            timeout=10,
        )
        if test_resp.status_code == 200:
            print(f"   ✅ Can read public PR data")
        else:
            print(f"   ❌ Cannot read public PR data ({test_resp.status_code})")

    # Rate limit info
    print(f"\n📊 Rate Limit:")
    print(f"   Remaining: {resp.headers.get('x-ratelimit-remaining', '?')}")
    print(f"   Limit: {resp.headers.get('x-ratelimit-limit', '?')}")

    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Validate GitHub token for AuditLens"
    )
    parser.add_argument(
        "--token",
        help="GitHub token (overrides env var)",
    )
    args = parser.parse_args()

    # Try to load .env
    load_env_file()

    token = args.token or os.getenv("GITHUB_TOKEN", "")
    check_token(token)
