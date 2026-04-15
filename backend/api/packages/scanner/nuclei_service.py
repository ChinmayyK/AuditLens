import subprocess
import json
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

TEMPLATES = os.getenv(
    "NUCLEI_TEMPLATES",
    "/scanner-tools/nuclei-templates",
)

OWASP_TAG_MAP = {
    "sqli":       "A03:2021 - Injection",
    "sql":        "A03:2021 - Injection",
    "xss":        "A03:2021 - Injection",
    "ssrf":       "A10:2021 - SSRF",
    "lfi":        "A01:2021 - Broken Access Control",
    "traversal":  "A01:2021 - Broken Access Control",
    "auth":       "A07:2021 - Identification Failures",
    "jwt":        "A07:2021 - Identification Failures",
    "cve":        "A06:2021 - Vulnerable Components",
    "rce":        "A03:2021 - Injection",
    "misconfig":  "A05:2021 - Security Misconfiguration",
    "exposure":   "A05:2021 - Security Misconfiguration",
    "default":    "A05:2021 - Security Misconfiguration",
    "takeover":   "A05:2021 - Security Misconfiguration",
}


class NucleiService:

    def scan(
        self,
        target_url: str,
        scan_id: str,
        on_progress,
        intensity: str = "standard",
    ) -> list:
        output_file = f"/tmp/{scan_id}_nuclei.jsonl"

        severities = {
            "quick":      "high,critical",
            "standard":   "medium,high,critical",
            "deep":       "low,medium,high,critical",
            "aggressive": "info,low,medium,high,critical",
        }.get(intensity, "medium,high,critical")

        cmd = [
            "nuclei",
            "-u",            target_url,
            "-json-export",  output_file,
            "-severity",     severities,
            "-tags",
                "cve,sqli,xss,ssrf,lfi,rce,"
                "misconfig,auth,exposure,default,"
                "takeover,jwt,xxe",
            "-timeout",      "12",
            "-rate-limit",   "60",
            "-silent",
            "-no-interactsh",
            "-retries",      "1",
        ]

        # Empty template dir makes Nuclei run zero checks — only use -t when
        # the directory actually contains template files (or subdirs with yaml).
        tpl_root = Path(TEMPLATES)
        has_templates = False
        if tpl_root.exists():
            try:
                has_templates = any(
                    tpl_root.rglob("*.yaml")
                ) or any(tpl_root.rglob("*.yml"))
            except OSError:
                has_templates = False
        if has_templates:
            cmd.extend(["-t", TEMPLATES])

        on_progress(
            "🔍 Running Nuclei CVE template scan...",
            56, tool="nuclei",
        )

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=360,
            )
        except subprocess.TimeoutExpired:
            on_progress(
                "⚠️ Nuclei timed out — partial results",
                63, tool="nuclei",
            )
        except FileNotFoundError:
            on_progress(
                "⚠️ Nuclei not available",
                63, tool="nuclei",
            )
            return []

        return self._parse(output_file, scan_id)

    def _parse(
        self, output_file: str, scan_id: str
    ) -> list:
        findings = []

        try:
            with open(output_file) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    info     = item.get("info", {})
                    severity = info.get(
                        "severity", "info"
                    ).lower()
                    if severity == "unknown":
                        severity = "info"

                    vuln_name = info.get(
                        "name",
                        item.get("template-id",
                                 "Unknown"),
                    )

                    tags = info.get("tags", [])
                    if isinstance(tags, str):
                        tags = [tags]
                    tag_str = " ".join(tags).lower()

                    owasp = "A05:2021 - Security " \
                            "Misconfiguration"
                    for tag_key, cat in \
                            OWASP_TAG_MAP.items():
                        if tag_key in tag_str:
                            owasp = cat
                            break

                    refs = info.get("reference", [])
                    cve_id = None
                    if isinstance(refs, list):
                        for r in refs:
                            if "CVE-" in str(r):
                                import re
                                m = re.search(
                                    r"CVE-\d{4}-\d+",
                                    str(r)
                                )
                                if m:
                                    cve_id = m.group()
                                    break

                    findings.append({
                        "scan_id":   scan_id,
                        "vuln_type": vuln_name,
                        "severity":  severity,
                        "category":  "vuln",
                        "url":
                            item.get("matched-at")
                            or item.get("host",
                                        ""),
                        "evidence":
                            str(item.get(
                                "extracted-results",
                                ""
                            ))[:300],
                        "description":
                            info.get(
                                "description", ""
                            )[:600],
                        "attack_worked":
                            severity in [
                                "critical", "high",
                                "medium",
                            ],
                        "was_attempted": True,
                        "owasp_category":  owasp,
                        "tool_source":     "nuclei",
                        "cve_id":          cve_id,
                        "money_loss_min":   10000,
                        "money_loss_max":   1000000,
                        "attack_name":
                            f"Nuclei: {vuln_name}",
                    })
        except FileNotFoundError:
            pass
        except Exception as e:
            logger.warning(f"Nuclei parse error: {e}")

        return findings
