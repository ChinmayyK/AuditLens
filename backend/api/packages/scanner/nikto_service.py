import subprocess
import json
import logging

logger = logging.getLogger(__name__)


class NiktoService:

    def scan(
        self,
        target_url: str,
        scan_id: str,
        on_progress,
    ) -> list:
        on_progress(
            "🔎 Nikto web server audit...",
            82, tool="nikto",
        )
        output_file = f"/tmp/{scan_id}_nikto.json"

        cmd = [
            "nikto",
            "-h",             target_url,
            "-o",             output_file,
            "-Format",        "json",
            "-timeout",       "8",
            "-maxtime",       "90s",
            "-nointeractive",
            "-C", "all",
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            on_progress(
                "⚠️ Nikto timed out",
                86, tool="nikto",
            )
            return []
        except FileNotFoundError:
            on_progress(
                "⚠️ Nikto not available",
                86, tool="nikto",
            )
            return []

        return self._parse(output_file, scan_id)

    def _parse(
        self, output_file: str, scan_id: str
    ) -> list:
        findings = []

        try:
            with open(output_file) as f:
                data = json.load(f)
        except Exception:
            return []

        for item in data.get(
            "vulnerabilities", []
        ):
            msg  = item.get("msg", "")
            uri  = item.get("uri", "")
            osvdb = item.get("OSVDB", "0")

            msg_lower = msg.lower()

            if any(k in msg_lower for k in [
                "default password",
                "backdoor", "rce",
                "command exec",
                "remote code",
            ]):
                severity = "critical"
            elif any(k in msg_lower for k in [
                "outdated", "vulnerable",
                "version", "exposed",
                "allowed", "cve",
            ]):
                severity = "high"
            elif any(k in msg_lower for k in [
                "found", "backup",
                "test", "debug",
                "accessible",
            ]):
                severity = "medium"
            else:
                severity = "low"

            if severity in ["low"] and \
               "osvdb-0" in f"osvdb-{osvdb}".lower():
                continue

            findings.append({
                "scan_id":      scan_id,
                "vuln_type":
                    "Server Misconfiguration",
                "severity":     severity,
                "category":     "config",
                "url":          uri or "",
                "evidence":
                    msg[:300],
                "description":
                    f"Nikto: {msg[:500]} "
                    f"(OSVDB-{osvdb})",
                "attack_worked":
                    severity in [
                        "critical", "high", "medium"
                    ],
                "was_attempted": True,
                "tool_source":   "nikto",
                "owasp_category":
                    "A05:2021 - Security "
                    "Misconfiguration",
                "money_loss_min": 5000,
                "money_loss_max": 500000,
                "attack_name":
                    "Server Misconfiguration",
            })

        return findings
