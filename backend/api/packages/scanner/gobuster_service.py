import csv
import logging
import subprocess
from urllib.parse import urlparse

from packages.scanner.wordlist_paths import (
    resolve_scanner_wordlist,
)

logger = logging.getLogger(__name__)

# Align with FFUF sensitive-path heuristics
SENSITIVE_KEYWORDS = [
    ".env", ".git", "admin", "backup", "config",
    "wp-admin", "phpmyadmin", ".htaccess", "debug",
    "secret", "password", "credentials", "token",
    "api_key", "database", "db", "test", "staging",
    ".ds_store", "error_log", "access_log", "phpinfo",
    "info.php", "server-status", "server-info",
    "crossdomain.xml", "sitemap.xml", "robots.txt",
    "swagger", "api-docs", "graphql", "console",
    "actuator", "health", "metrics", "env", "dump",
]


class GobusterService:

    def scan(
        self,
        target_url: str,
        scan_id: str,
        on_progress,
        intensity: str = "standard",
    ) -> list:
        on_progress(
            "📁 Gobuster directory brute-force...",
            28, tool="gobuster",
        )

        wordlist = resolve_scanner_wordlist()
        if not wordlist:
            on_progress(
                "⚠️ Wordlist not found, skipping Gobuster",
                29, tool="gobuster",
            )
            return []

        base = target_url.rstrip("/") + "/"
        out_csv = f"/tmp/{scan_id}_gobuster.csv"

        threads = {
            "quick":      "12",
            "standard":   "20",
            "deep":       "28",
            "aggressive": "35",
        }.get(intensity, "20")

        timeout_sec = {
            "quick":      45,
            "standard":   75,
            "deep":       100,
            "aggressive": 130,
        }.get(intensity, 75)

        cmd = [
            "gobuster", "dir",
            "-u", base,
            "-w", wordlist,
            "-o", out_csv,
            "-of", "csv",
            "-t", threads,
            "-q",
            "--timeout", "10s",
            "-k",
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_sec,
            )
        except subprocess.TimeoutExpired:
            on_progress(
                "⚠️ Gobuster timed out",
                29, tool="gobuster",
            )
            return []
        except FileNotFoundError:
            on_progress(
                "⚠️ Gobuster not available",
                29, tool="gobuster",
            )
            return []

        findings = self._parse_csv(
            out_csv, scan_id, target_url,
        )
        return findings

    def _parse_csv(
        self,
        csv_path: str,
        scan_id: str,
        target_url: str,
    ) -> list:
        findings = []
        try:
            with open(csv_path, newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    url = (
                        row.get("URL")
                        or row.get("Url")
                        or row.get("url")
                        or ""
                    ).strip()
                    if not url:
                        continue
                    try:
                        status = int(
                            row.get("Status")
                            or row.get("status")
                            or 0
                        )
                    except (TypeError, ValueError):
                        status = 0
                    try:
                        size = int(
                            row.get("Size")
                            or row.get("size")
                            or 0
                        )
                    except (TypeError, ValueError):
                        size = 0

                    if status not in (
                        200, 201, 204, 301, 302,
                        307, 308, 401, 403, 405,
                    ):
                        continue

                    path = urlparse(url).path.lower()
                    url_l = url.lower()
                    is_sensitive = any(
                        kw in url_l or kw in path
                        for kw in SENSITIVE_KEYWORDS
                    )

                    if not is_sensitive and status not in (
                        401, 403, 405,
                    ):
                        continue

                    if is_sensitive:
                        severity = "high"
                        vuln_type = "Sensitive Path (Gobuster)"
                        desc = (
                            f"Gobuster found path '{url}' "
                            f"(HTTP {status}). May expose "
                            f"admin, config, backups, or APIs."
                        )
                        money = (8000, 800000)
                    else:
                        severity = "medium"
                        vuln_type = "Restricted Path (Gobuster)"
                        desc = (
                            f"Gobuster: '{url}' returns HTTP "
                            f"{status}. Possible hidden endpoint."
                        )
                        money = (1000, 100000)

                    findings.append({
                        "scan_id":       scan_id,
                        "vuln_type":     vuln_type,
                        "severity":      severity,
                        "category":      "exposure",
                        "url":           url,
                        "evidence":
                            f"HTTP {status}, size={size}b",
                        "description":   desc,
                        "attack_worked": True,
                        "was_attempted": True,
                        "tool_source":   "gobuster",
                        "owasp_category":
                            "A05:2021 - Security "
                            "Misconfiguration",
                        "money_loss_min": money[0],
                        "money_loss_max": money[1],
                        "attack_name":
                            "Directory Enumeration",
                    })
        except OSError as e:
            logger.debug("Gobuster csv read: %s", e)

        return findings
