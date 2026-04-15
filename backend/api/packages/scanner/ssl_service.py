import subprocess
import requests
import re
import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)


class SSLService:

    def scan(self, target_url: str,
             scan_id: str) -> list:
        findings = []

        if not target_url.startswith("https://"):
            findings.append({
                "scan_id":       scan_id,
                "vuln_type":     "No HTTPS Encryption",
                "severity":      "high",
                "category":      "crypto",
                "url":           target_url,
                "evidence":
                    "Site uses HTTP — all traffic "
                    "is transmitted in plaintext",
                "description":
                    "Site does not use HTTPS. Every "
                    "request and response — including "
                    "passwords, session tokens, and "
                    "personal data — can be read by "
                    "anyone on the network. A simple "
                    "packet capture reveals everything.",
                "attack_worked":  True,
                "was_attempted":  True,
                "tool_source":    "ssl_audit",
                "owasp_category":
                    "A02:2021 - Cryptographic Failures",
                "money_loss_min": 50000,
                "money_loss_max": 2000000,
                "attack_name":    "Network Eavesdropping / MITM",
            })
            return findings

        hostname = urlparse(target_url).netloc.split(":")[0]

        # ── Certificate checks via ssl module ────────
        findings += self._check_certificate(
            hostname, scan_id
        )

        # ── testssl.sh (if available) ────────────────
        findings += self._run_testssl(
            target_url, scan_id
        )

        # ── Security headers ─────────────────────────
        findings += self._check_security_headers(
            target_url, scan_id
        )

        return findings

    def _check_certificate(self, hostname: str,
                            scan_id: str) -> list:
        findings = []
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(
                socket.socket(),
                server_hostname=hostname,
            ) as s:
                s.settimeout(10)
                s.connect((hostname, 443))
                cert = s.getpeercert()

            # Expiry check
            not_after = datetime.strptime(
                cert["notAfter"],
                "%b %d %H:%M:%S %Y %Z",
            ).replace(tzinfo=timezone.utc)

            days_left = (
                not_after - datetime.now(timezone.utc)
            ).days

            if days_left < 0:
                findings.append({
                    "scan_id":      scan_id,
                    "vuln_type":    "SSL Certificate Expired",
                    "severity":     "critical",
                    "category":     "crypto",
                    "url":          hostname,
                    "evidence":
                        f"Certificate expired "
                        f"{abs(days_left)} days ago "
                        f"on {not_after.date()}",
                    "description":
                        "SSL certificate has expired. "
                        "HTTPS provides no protection. "
                        "Browsers show security warnings "
                        "blocking users from the site.",
                    "attack_worked":  True,
                    "was_attempted":  True,
                    "tool_source":    "ssl_audit",
                    "owasp_category":
                        "A02:2021 - Cryptographic Failures",
                    "money_loss_min": 10000,
                    "money_loss_max": 500000,
                    "attack_name":    "Certificate Expiry",
                })
            elif days_left < 30:
                findings.append({
                    "scan_id":      scan_id,
                    "vuln_type":
                        "SSL Certificate Expiring Soon",
                    "severity":     "medium",
                    "category":     "crypto",
                    "url":          hostname,
                    "evidence":
                        f"Certificate expires in "
                        f"{days_left} days",
                    "description":
                        f"SSL certificate expires in "
                        f"{days_left} days. Users will "
                        f"see browser warnings after "
                        f"expiry.",
                    "attack_worked":  True,
                    "was_attempted":  True,
                    "tool_source":    "ssl_audit",
                    "owasp_category":
                        "A02:2021 - Cryptographic Failures",
                    "money_loss_min": 5000,
                    "money_loss_max": 100000,
                    "attack_name":    "Certificate Expiry Warning",
                })

        except ssl.SSLError as e:
            findings.append({
                "scan_id":      scan_id,
                "vuln_type":
                    "SSL Handshake Failed",
                "severity":     "high",
                "category":     "crypto",
                "url":          hostname,
                "evidence":     str(e)[:200],
                "description":
                    "SSL/TLS handshake failed. "
                    "Certificate may be invalid, "
                    "self-signed, or misconfigured.",
                "attack_worked":  True,
                "was_attempted":  True,
                "tool_source":    "ssl_audit",
                "owasp_category":
                    "A02:2021 - Cryptographic Failures",
                "money_loss_min": 10000,
                "money_loss_max": 200000,
                "attack_name":    "SSL Configuration Failure",
            })
        except Exception as e:
            logger.warning(f"Cert check error: {e}")

        return findings

    def _run_testssl(self, target_url: str,
                     scan_id: str) -> list:
        findings = []
        testssl = "/opt/testssl/testssl.sh"
        if not os.path.exists(testssl):
            return []

        try:
            result = subprocess.run(
                [testssl, "--fast",
                 "--severity", "MEDIUM",
                 "--jsonfile",
                 f"/tmp/{scan_id}_testssl.json",
                 target_url],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired,
                FileNotFoundError):
            return []

        try:
            import json
            with open(
                f"/tmp/{scan_id}_testssl.json"
            ) as f:
                data = json.load(f)

            for item in data:
                sev_map = {
                    "CRITICAL": "critical",
                    "HIGH":     "high",
                    "MEDIUM":   "medium",
                    "LOW":      "low",
                    "INFO":     "info",
                }
                raw_sev = item.get("severity", "INFO")
                sev = sev_map.get(raw_sev, "info")

                if sev in ["critical", "high", "medium"]:
                    findings.append({
                        "scan_id":      scan_id,
                        "vuln_type":
                            item.get("id",
                                     "SSL Issue"),
                        "severity":     sev,
                        "category":     "crypto",
                        "url":          target_url,
                        "evidence":
                            item.get("finding",
                                     "")[:300],
                        "description":
                            item.get("finding",
                                     "")[:500],
                        "attack_worked": True,
                        "was_attempted": True,
                        "tool_source":   "testssl",
                        "owasp_category":
                            "A02:2021 - Cryptographic "
                            "Failures",
                        "money_loss_min": 10000,
                        "money_loss_max": 500000,
                        "attack_name":
                            f"TLS: "
                            f"{item.get('id','Unknown')}",
                    })
        except Exception as e:
            logger.warning(f"testssl parse error: {e}")

        return findings

    def _check_security_headers(
        self, target_url: str, scan_id: str
    ) -> list:
        findings = []
        REQUIRED_HEADERS = {
            "x-frame-options": {
                "vuln_type":
                    "Missing X-Frame-Options Header",
                "severity":   "medium",
                "desc":
                    "X-Frame-Options missing. Attackers "
                    "can embed your site in an invisible "
                    "iframe and trick users into clicking "
                    "buttons they cannot see "
                    "(clickjacking).",
                "attack_name": "Clickjacking",
                "loss_min":    10000,
                "loss_max":    500000,
            },
            "content-security-policy": {
                "vuln_type":
                    "Missing Content-Security-Policy",
                "severity":   "medium",
                "desc":
                    "No CSP set. Any injected JavaScript "
                    "executes without restriction. XSS "
                    "attacks are significantly more "
                    "impactful — session theft, "
                    "credential harvesting, crypto "
                    "mining.",
                "attack_name":
                    "XSS Amplification via Missing CSP",
                "loss_min": 5000,
                "loss_max": 1000000,
            },
            "strict-transport-security": {
                "vuln_type":   "Missing HSTS Header",
                "severity":    "medium",
                "desc":
                    "HSTS not set. Browsers may connect "
                    "via HTTP first, allowing attackers "
                    "on the network to intercept and "
                    "downgrade to plaintext "
                    "(SSL stripping).",
                "attack_name": "SSL Stripping / MITM",
                "loss_min":    50000,
                "loss_max":    2000000,
            },
            "x-content-type-options": {
                "vuln_type":
                    "Missing X-Content-Type-Options",
                "severity":   "low",
                "desc":
                    "MIME sniffing enabled. Uploaded "
                    "files with wrong MIME types may be "
                    "executed as scripts by the browser.",
                "attack_name": "MIME Sniffing Attack",
                "loss_min":    1000,
                "loss_max":    50000,
            },
            "referrer-policy": {
                "vuln_type":
                    "Missing Referrer-Policy Header",
                "severity":   "low",
                "desc":
                    "Full referrer URL sent to external "
                    "sites. Session tokens or IDs in "
                    "query params may leak to third "
                    "parties.",
                "attack_name": "Referrer Leakage",
                "loss_min":    500,
                "loss_max":    50000,
            },
            "permissions-policy": {
                "vuln_type":
                    "Missing Permissions-Policy Header",
                "severity":   "low",
                "desc":
                    "No Permissions-Policy set. "
                    "Injected scripts can access camera, "
                    "microphone, and geolocation APIs.",
                "attack_name": "Browser API Abuse",
                "loss_min":    500,
                "loss_max":    25000,
            },
        }

        try:
            resp = requests.get(
                target_url,
                timeout=10,
                verify=False,
                allow_redirects=True,
            )
            headers_lower = {
                k.lower(): v
                for k, v in resp.headers.items()
            }
        except Exception as e:
            logger.warning(f"Header check failed: {e}")
            return []

        for hdr_key, info in REQUIRED_HEADERS.items():
            if hdr_key not in headers_lower:
                findings.append({
                    "scan_id":      scan_id,
                    "vuln_type":    info["vuln_type"],
                    "severity":     info["severity"],
                    "category":     "config",
                    "url":          target_url,
                    "evidence":
                        f"Header '{hdr_key}' absent. "
                        f"Response headers: "
                        f"{list(headers_lower.keys())[:8]}",
                    "description":  info["desc"],
                    "attack_worked": True,
                    "was_attempted": True,
                    "tool_source":
                        "native_header_check",
                    "owasp_category":
                        "A05:2021 - Security "
                        "Misconfiguration",
                    "money_loss_min": info["loss_min"],
                    "money_loss_max": info["loss_max"],
                    "attack_name":    info["attack_name"],
                    "quick_fix":
                        f"Add to your web server: "
                        f"{hdr_key}: [value]",
                })
            else:
                # Header present — actively defended
                findings.append({
                    "scan_id":      scan_id,
                    "vuln_type":    info["vuln_type"],
                    "severity":     "info",
                    "category":     "config",
                    "url":          target_url,
                    "evidence":
                        f"Present: "
                        f"{headers_lower[hdr_key][:80]}",
                    "description":
                        "Security header correctly set.",
                    "attack_worked": False,
                    "was_attempted": True,
                    "tool_source":
                        "native_header_check",
                    "owasp_category":
                        "A05:2021 - Security "
                        "Misconfiguration",
                })

        return findings


import os
