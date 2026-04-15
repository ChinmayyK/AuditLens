import subprocess
import requests
import time
import threading
import json
from datetime import datetime
from urllib.parse import urlparse
import urllib3
urllib3.disable_warnings()

import logging
logger = logging.getLogger(__name__)


class StressTestService:
    """
    HTTP load testing to find rate limiting
    weaknesses and performance-based vulnerabilities.
    Tests: rate limit enforcement, auth endpoint
    abuse, session handling under load.
    """

    def test_rate_limiting(
        self,
        target_url: str,
        scan_id: str,
        on_progress,
    ) -> list:
        findings = []
        on_progress(
            "⚡ Testing rate limit enforcement...",
            77, tool="stress",
        )

        # Test 1: Rapid requests to detect rate limit
        result = self._rapid_fire_test(
            target_url, count=30, window_secs=10
        )
        findings += self._analyse_rate_limit(
            result, target_url, scan_id
        )

        # Test 2: Auth endpoint brute force simulation
        auth_paths = [
            "/login", "/api/login",
            "/api/auth", "/api/v1/login",
            "/wp-login.php", "/admin/login",
        ]
        for path in auth_paths[:3]:
            test_url = (
                target_url.rstrip("/") + path
            )
            try:
                r = requests.get(
                    test_url, timeout=5,
                    verify=False,
                )
                if r.status_code in [200, 302, 405]:
                    auth_result = \
                        self._test_auth_endpoint(
                            test_url, scan_id,
                        )
                    findings += auth_result
                    break
            except Exception:
                pass

        on_progress(
            "✅ Stress test complete",
            80, tool="stress",
        )
        return findings

    def _rapid_fire_test(
        self,
        url: str,
        count: int,
        window_secs: int,
    ) -> dict:
        results = {
            "total":     count,
            "success":   0,
            "blocked":   0,
            "errors":    0,
            "rate_limited": False,
            "status_codes": [],
        }

        session = requests.Session()
        session.verify = False

        start = time.time()
        for i in range(count):
            try:
                r = session.get(
                    url, timeout=5,
                    allow_redirects=False,
                )
                results["status_codes"].append(
                    r.status_code
                )
                if r.status_code == 429:
                    results["rate_limited"] = True
                    results["blocked"] += 1
                elif r.status_code < 400:
                    results["success"] += 1
                else:
                    results["errors"] += 1
            except Exception:
                results["errors"] += 1

        results["duration_secs"] = (
            time.time() - start
        )
        results["rps"] = count / max(
            results["duration_secs"], 0.1
        )
        return results

    def _analyse_rate_limit(
        self,
        result: dict,
        url: str,
        scan_id: str,
    ) -> list:
        findings = []

        if not result["rate_limited"] and \
           result["success"] > 25:
            findings.append({
                "scan_id":      scan_id,
                "vuln_type":
                    "Missing Rate Limiting",
                "severity":     "medium",
                "category":     "config",
                "url":          url,
                "evidence":
                    f"{result['success']}/{result['total']}"
                    f" requests succeeded in "
                    f"{result['duration_secs']:.1f}s "
                    f"({result['rps']:.0f} req/s). "
                    f"No HTTP 429 received.",
                "description":
                    "No rate limiting detected. "
                    "The endpoint accepts unlimited "
                    "requests per second. This enables "
                    "credential brute-force attacks, "
                    "account enumeration, and "
                    "resource exhaustion.",
                "attack_worked":  True,
                "was_attempted":  True,
                "tool_source":    "stress_test",
                "owasp_category":
                    "A07:2021 - Identification "
                    "Failures",
                "money_loss_min": 10000,
                "money_loss_max": 1000000,
                "attack_name":
                    "Brute Force / Rate Limit Bypass",
                "quick_fix":
                    "Implement rate limiting: "
                    "max 10 req/min per IP on "
                    "auth endpoints. Use Redis "
                    "or nginx limit_req.",
            })
        elif result["rate_limited"]:
            findings.append({
                "scan_id":      scan_id,
                "vuln_type":
                    "Missing Rate Limiting",
                "severity":     "info",
                "category":     "config",
                "url":          url,
                "evidence":
                    f"Rate limiting active — "
                    f"HTTP 429 received after "
                    f"{result['success']} requests",
                "description":
                    "Rate limiting is active.",
                "attack_worked": False,
                "was_attempted": True,
                "tool_source":   "stress_test",
                "owasp_category":
                    "A07:2021 - Identification "
                    "Failures",
            })

        return findings

    def _test_auth_endpoint(
        self, url: str, scan_id: str
    ) -> list:
        findings = []
        session = requests.Session()
        session.verify = False

        # Try common default credentials
        DEFAULT_CREDS = [
            {"username": "admin",
             "password": "admin"},
            {"username": "admin",
             "password": "password"},
            {"username": "admin",
             "password": "123456"},
            {"username": "test",
             "password": "test"},
            {"email": "admin@admin.com",
             "password": "admin"},
        ]

        blocked_count = 0
        success_count = 0

        for creds in DEFAULT_CREDS:
            try:
                r = session.post(
                    url, json=creds,
                    timeout=5,
                    allow_redirects=False,
                )
                if r.status_code == 429:
                    blocked_count += 1
                elif r.status_code in [200, 302]:
                    # Check if actually logged in
                    if any(kw in r.text.lower()
                           for kw in [
                               "dashboard", "welcome",
                               "logout", "profile",
                               "token", "access_token",
                           ]):
                        success_count += 1
                        findings.append({
                            "scan_id":   scan_id,
                            "vuln_type":
                                "Default Credentials",
                            "severity":  "critical",
                            "category":  "auth",
                            "url":       url,
                            "evidence":
                                f"Login succeeded with: "
                                f"{list(creds.keys())[0]}"
                                f"={list(creds.values())[0]}",
                            "description":
                                "Default credentials "
                                "accepted. Attacker "
                                "gains immediate "
                                "admin access.",
                            "attack_worked": True,
                            "was_attempted": True,
                            "tool_source":
                                "stress_test",
                            "owasp_category":
                                "A07:2021 - "
                                "Identification "
                                "Failures",
                            "cvss_score":    9.8,
                            "money_loss_min": 500000,
                            "money_loss_max": 100000000,
                            "attack_name":
                                "Default Credential Login",
                        })
                        break
            except Exception:
                pass

        return findings
