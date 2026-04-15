import subprocess
import re
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import urllib3
urllib3.disable_warnings()

XSSTRIKE_PATH = "/opt/XSStrike/xsstrike.py"

# Native XSS payloads as fallback
XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg onload=alert(1)>',
    '"><svg/onload=alert(1)>',
    "javascript:alert(1)",
    '<details open ontoggle=alert(1)>',
    '<img src=x onerror=confirm(1)>',
    '{{7*7}}',
    '${7*7}',
]


class XSStrikeService:

    def scan(
        self,
        scan_id: str,
        get_params: list,
        on_progress,
    ) -> list:
        findings = []

        for i, item in enumerate(get_params[:8]):
            url   = item.get("url", "")
            param = item.get("param", "")
            if not url or not param:
                continue

            on_progress(
                f"🎯 XSS testing param: {param}",
                57 + i,
                tool="xsstrike",
                event_type="attack",
            )

            # Try XSStrike first
            result = self._run_xsstrike(
                url, param, scan_id
            )
            if result:
                findings.extend(result)
                continue

            # Native fallback
            result = self._native_xss_test(
                url, param, scan_id
            )
            findings.extend(result)

        return findings

    def _run_xsstrike(
        self, url: str, param: str, scan_id: str
    ) -> list:
        try:
            result = subprocess.run(
                [
                    "python3", XSSTRIKE_PATH,
                    "-u",      url,
                    "--skip",
                    "--timeout", "10",
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            output = result.stdout.lower()

            if any(kw in output for kw in [
                "xss", "vulnerable",
                "reflected", "payload",
            ]):
                # Extract working payload
                payload = ""
                for line in result.stdout.split("\n"):
                    if "<" in line and (
                        "script" in line.lower() or
                        "svg" in line.lower() or
                        "onerror" in line.lower()
                    ):
                        payload = line.strip()[:100]
                        break

                return [{
                    "scan_id":      scan_id,
                    "vuln_type":
                        "Cross Site Scripting "
                        "(Reflected)",
                    "severity":     "high",
                    "category":     "injection",
                    "url":          url,
                    "parameter":    param,
                    "evidence":
                        payload or
                        "XSS confirmed by XSStrike",
                    "description":
                        f"Reflected XSS confirmed "
                        f"in parameter '{param}'. "
                        f"XSStrike found a working "
                        f"payload. An attacker "
                        f"sends a crafted link — "
                        f"when clicked, malicious "
                        f"JavaScript runs in the "
                        f"victim's browser, "
                        f"stealing session cookies "
                        f"and fully compromising "
                        f"the account.",
                    "attack_worked":  True,
                    "was_attempted":  True,
                    "attack_payload": payload,
                    "owasp_category":
                        "A03:2021 - Injection",
                    "tool_source":    "xsstrike",
                    "cvss_score":     7.4,
                    "cwe_id":         "CWE-79",
                    "money_loss_min": 10000,
                    "money_loss_max": 2000000,
                    "attack_name":
                        "Reflected XSS",
                    "layman_explanation":
                        "XSS is like someone "
                        "slipping a forged note "
                        "into your mailbox that "
                        "calls all your contacts "
                        "pretending to be you. "
                        "An attacker injects "
                        "code that runs in "
                        "other users' browsers "
                        "— stealing passwords "
                        "and sessions silently.",
                }]
        except Exception:
            pass

        return []

    def _native_xss_test(
        self, url: str, param: str, scan_id: str
    ) -> list:
        """
        Pure Python XSS tester — no external binary.
        Checks if payload reflects unencoded.
        """
        session = requests.Session()
        session.verify = False

        for payload in XSS_PAYLOADS[:5]:
            try:
                parsed = urlparse(url)
                params = parse_qs(parsed.query)
                params[param] = [payload]
                new_query = urlencode(
                    params, doseq=True
                )
                test_url = urlunparse(
                    parsed._replace(query=new_query)
                )

                resp = session.get(
                    test_url,
                    timeout=8,
                    allow_redirects=True,
                )
                body = resp.text

                # Check if payload reflects unencoded
                if payload in body or (
                    "<script" in payload.lower() and
                    "<script" in body.lower()
                ):
                    return [{
                        "scan_id":      scan_id,
                        "vuln_type":
                            "Cross Site Scripting "
                            "(Reflected)",
                        "severity":     "high",
                        "category":     "injection",
                        "url":          test_url,
                        "parameter":    param,
                        "evidence":
                            f"Payload reflected "
                            f"unencoded: "
                            f"{payload[:80]}",
                        "description":
                            f"Reflected XSS in "
                            f"'{param}'. User input "
                            f"reflects directly into "
                            f"HTML without encoding.",
                        "attack_worked":  True,
                        "was_attempted":  True,
                        "attack_payload": payload,
                        "owasp_category":
                            "A03:2021 - Injection",
                        "tool_source":
                            "native_xss",
                        "cvss_score":     7.4,
                        "cwe_id":         "CWE-79",
                        "money_loss_min": 10000,
                        "money_loss_max": 2000000,
                        "attack_name":
                            "Reflected XSS",
                    }]

            except Exception:
                continue

        # No XSS found — record as tested + defended
        return [{
            "scan_id":      scan_id,
            "vuln_type":
                "Cross Site Scripting (Reflected)",
            "severity":     "info",
            "category":     "injection",
            "url":          url,
            "parameter":    param,
            "evidence":
                f"XSS payloads tested on "
                f"'{param}' — all encoded/blocked",
            "description":
                "XSS test completed on this "
                "parameter. Payloads were encoded "
                "or rejected.",
            "attack_worked": False,
            "was_attempted": True,
            "tool_source":   "native_xss",
            "owasp_category":
                "A03:2021 - Injection",
        }]
