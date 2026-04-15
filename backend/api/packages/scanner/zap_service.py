import requests
import time
import os
import json
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)

ZAP_BASE = os.getenv("ZAP_URL", "http://zap:8090")
ZAP_KEY = os.getenv("ZAP_API_KEY",
                    "shieldsentinel_zap_key")

OWASP_MAP = {
    "SQL Injection":
        "A03:2021 - Injection",
    "Cross Site Scripting (Reflected)":
        "A03:2021 - Injection",
    "Cross Site Scripting (Persistent)":
        "A03:2021 - Injection",
    "Cross-Site Request Forgery":
        "A01:2021 - Broken Access Control",
    "Path Traversal":
        "A01:2021 - Broken Access Control",
    "Remote File Inclusion":
        "A03:2021 - Injection",
    "Server Side Request Forgery":
        "A10:2021 - SSRF",
    "Missing Anti-clickjacking Header":
        "A05:2021 - Security Misconfiguration",
    "Content Security Policy (CSP) Header Not Set":
        "A05:2021 - Security Misconfiguration",
    "Strict-Transport-Security Header Not Set":
        "A05:2021 - Security Misconfiguration",
    "X-Content-Type-Options Header Missing":
        "A05:2021 - Security Misconfiguration",
    "Application Error Disclosure":
        "A05:2021 - Security Misconfiguration",
    "Cookie Without Secure Flag":
        "A02:2021 - Cryptographic Failures",
    "Cookie No HttpOnly Flag":
        "A02:2021 - Cryptographic Failures",
    "Insecure HTTP Method":
        "A05:2021 - Security Misconfiguration",
    "Remote OS Command Injection":
        "A03:2021 - Injection",
    "External Redirect":
        "A01:2021 - Broken Access Control",
    "Directory Browsing":
        "A05:2021 - Security Misconfiguration",
    "Source Code Disclosure":
        "A02:2021 - Cryptographic Failures",
    "Weak Authentication Method":
        "A07:2021 - Identification Failures",
    "Session ID in URL Rewrite":
        "A07:2021 - Identification Failures",
    "Absence of Anti-CSRF Tokens":
        "A01:2021 - Broken Access Control",
    "LDAP Injection":
        "A03:2021 - Injection",
    "XPath Injection":
        "A03:2021 - Injection",
    "XML External Entity Attack":
        "A05:2021 - Security Misconfiguration",
}

SEVERITY_MAP = {
    "High":          "high",
    "Medium":        "medium",
    "Low":           "low",
    "Informational": "info",
}

MONEY_LOSS = {
    "SQL Injection":
        (100000, 10000000),
    "Cross Site Scripting (Reflected)":
        (10000, 2000000),
    "Cross Site Scripting (Persistent)":
        (50000, 5000000),
    "Cross-Site Request Forgery":
        (25000, 5000000),
    "Path Traversal":
        (50000, 5000000),
    "Remote OS Command Injection":
        (500000, 100000000),
    "Server Side Request Forgery":
        (200000, 50000000),
    "Application Error Disclosure":
        (5000, 200000),
    "Cookie Without Secure Flag":
        (5000, 500000),
    "Directory Browsing":
        (10000, 1000000),
}


class ZAPService:

    def _get(self, path: str, params: dict = None):
        p = params or {}
        p["apikey"] = ZAP_KEY
        try:
            r = requests.get(
                f"{ZAP_BASE}/JSON/{path}/",
                params=p,
                timeout=30,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.warning(f"ZAP {path} failed: {e}")
            return {}

    def wait_for_zap(self, timeout: int = 180):
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = requests.get(
                    f"{ZAP_BASE}/JSON/"
                    f"core/view/version/",
                    params={"apikey": ZAP_KEY},
                    timeout=5,
                )
                if r.status_code == 200:
                    logger.info("ZAP is ready")
                    return True
            except Exception:
                pass
            time.sleep(4)
        raise TimeoutError(
            "ZAP did not respond within timeout"
        )

    def new_session(self):
        self._get("core/action/newSession",
                  {"overwrite": "true"})

    def spider(
        self,
        target_url: str,
        scan_id: str,
        on_progress,
        max_children: int = 15,
        intensity: str = "standard",
    ) -> list:
        depth_map = {
            "quick":      12,
            "standard":   25,
            "deep":       50,
            "aggressive": 100,
        }
        mc = max_children if max_children != 15 else depth_map.get(
            intensity, 25
        )
        resp = self._get(
            "spider/action/scan",
            {
                "url":          target_url,
                "maxChildren":  str(mc),
                "recurse":      "true",
                "subtreeOnly":  "false",
            },
        )
        spider_id = resp.get("scan", "0")

        while True:
            status = self._get(
                "spider/view/status",
                {"scanId": spider_id},
            ).get("status", "100")
            pct = int(status)
            on_progress(
                f"🕷️ Crawling target: {pct}%",
                30 + int(pct * 0.05),
                tool="zap_spider",
            )
            if pct >= 100:
                break
            time.sleep(3)

        urls = self._get(
            "spider/view/results",
            {"scanId": spider_id},
        ).get("results", [])
        return urls

    def active_scan(
        self,
        target_url: str,
        scan_id: str,
        on_progress,
        intensity: str = "standard",
    ) -> str:
        # Set scan strength based on intensity
        strength_map = {
            "quick":      "LOW",
            "standard":   "MEDIUM",
            "deep":       "HIGH",
            "aggressive": "INSANE",
        }
        strength = strength_map.get(
            intensity, "MEDIUM"
        )

        try:
            self._get(
                "ascan/action/"
                "setScannerAttackStrength",
                {
                    "id":       "0",
                    "attackStrength": strength,
                },
            )
        except Exception:
            pass

        resp = self._get(
            "ascan/action/scan",
            {
                "url":     target_url,
                "recurse": "true",
                "inScopeOnly": "false",
            },
        )
        ascan_id = resp.get("scan", "0")

        ATTACK_MESSAGES = [
            "💉 Testing SQL injection vectors...",
            "🎯 Testing XSS injection points...",
            "🔒 Testing authentication controls...",
            "🗂️ Testing path traversal attacks...",
            "🔗 Testing SSRF vulnerabilities...",
            "💻 Testing command injection...",
            "🔑 Testing session management...",
            "🌐 Testing HTTP method abuse...",
        ]
        msg_idx = 0
        last_pct = -1
        last_msg = ""

        while True:
            status = self._get(
                "ascan/view/status",
                {"scanId": ascan_id},
            ).get("status", "100")
            pct = int(status)

            if pct > last_pct and pct % 15 == 0:
                msg_idx += 1

            msg = ATTACK_MESSAGES[
                msg_idx % len(ATTACK_MESSAGES)
            ]

            if pct != last_pct or msg != last_msg:
                on_progress(
                    msg,
                    35 + int(pct * 0.25),
                    tool="zap_ascan",
                    event_type="attack",
                )
                last_pct = pct
                last_msg = msg
            if pct >= 100:
                break
            time.sleep(5)

        return ascan_id

    def get_alerts(self, target_url: str) -> list:
        alerts = self._get(
            "core/view/alerts",
            {
                "baseurl": target_url,
                "start":   "0",
                "count":   "2000",
            },
        ).get("alerts", [])
        return alerts

    def get_all_urls(self) -> list:
        return self._get(
            "core/view/urls"
        ).get("urls", [])

    def parse_alerts(
        self, alerts: list, scan_id: str
    ) -> list:
        findings = []
        seen = set()

        for alert in alerts:
            vuln_type = alert.get("alert", "Unknown")
            url       = alert.get("url", "")
            param     = alert.get("param", "")
            evidence  = alert.get("evidence", "")

            # Deduplicate same issue at same URL
            key = f"{vuln_type}:{url}:{param}"
            if key in seen:
                continue
            seen.add(key)

            risk = alert.get("risk", "Low")
            severity = SEVERITY_MAP.get(risk, "info")

            money = MONEY_LOSS.get(
                vuln_type, (1000, 100000)
            )

            findings.append({
                "scan_id":      scan_id,
                "vuln_type":    vuln_type,
                "severity":     severity,
                "category":     "web",
                "url":          url,
                "parameter":    param or None,
                "http_method":  alert.get("method"),
                "evidence":
                    (evidence or "")[:500],
                "description":
                    alert.get("description",
                               "")[:1000],
                "attack_payload":
                    alert.get("attack", "")[:300],
                "attack_worked":
                    severity in [
                        "critical", "high", "medium"
                    ],
                "was_attempted": True,
                "owasp_category":
                    OWASP_MAP.get(
                        vuln_type,
                        "A05:2021 - Security "
                        "Misconfiguration",
                    ),
                "tool_source":  "zap",
                "money_loss_min": money[0],
                "money_loss_max": money[1],
                "attack_name":
                    f"ZAP: {vuln_type}",
                "cwe_id":
                    f"CWE-{alert.get('cweid', '')}"
                    if alert.get("cweid") else None,
            })

        return findings
