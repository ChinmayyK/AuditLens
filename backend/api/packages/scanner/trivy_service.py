import subprocess
import json
import logging

logger = logging.getLogger(__name__)

SEV_MAP = {
    "CRITICAL": "critical",
    "HIGH":     "high",
    "MEDIUM":   "medium",
    "LOW":      "low",
}


class TrivyService:

    def scan(
        self,
        code_path: str,
        scan_id: str,
        on_progress,
    ) -> list:
        on_progress(
            "📦 Trivy dependency CVE scan...",
            70, tool="trivy",
        )
        output_file = f"/tmp/{scan_id}_trivy.json"

        cmd = [
            "trivy",
            "fs",
            "--format",   "json",
            "--output",   output_file,
            "--severity", "CRITICAL,HIGH,MEDIUM",
            "--quiet",
            "--no-progress",
            "--skip-db-update",
            code_path,
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            on_progress(
                "⚠️ Trivy timed out",
                78, tool="trivy",
            )
            return []
        except FileNotFoundError:
            on_progress(
                "⚠️ Trivy not available",
                78, tool="trivy",
            )
            return []

        return self._parse(
            output_file, scan_id, on_progress
        )

    def _parse(
        self,
        output_file: str,
        scan_id: str,
        on_progress,
    ) -> list:
        findings = []

        try:
            with open(output_file) as f:
                data = json.load(f)
        except Exception:
            return []

        for result in data.get("Results", []):
            target = result.get("Target", "")
            for vuln in result.get(
                "Vulnerabilities", []
            ):
                cve_id   = vuln.get(
                    "VulnerabilityID", "UNKNOWN"
                )
                pkg      = vuln.get(
                    "PkgName", "unknown"
                )
                installed = vuln.get(
                    "InstalledVersion", "unknown"
                )
                fixed     = vuln.get(
                    "FixedVersion", "latest"
                )
                severity  = SEV_MAP.get(
                    vuln.get("Severity", "MEDIUM"),
                    "medium",
                )
                title     = vuln.get(
                    "Title", "Vulnerability found"
                )
                cvss = vuln.get("CVSS", {})
                cvss_score = None
                for source in cvss.values():
                    v3 = source.get("V3Score")
                    if v3:
                        cvss_score = float(v3)
                        break

                desc = (
                    f"Package {pkg} v{installed} has "
                    f"known vulnerability {cve_id}: "
                    f"{title}. "
                    f"Fix: upgrade to {fixed}."
                )

                findings.append({
                    "scan_id":      scan_id,
                    "vuln_type":
                        "Vulnerable Dependency",
                    "severity":     severity,
                    "category":     "dependency",
                    "file_path":    target,
                    "evidence":
                        f"{cve_id}: "
                        f"{pkg}@{installed}",
                    "description":  desc,
                    "attack_worked":
                        severity in [
                            "critical", "high"
                        ],
                    "was_attempted": True,
                    "owasp_category":
                        "A06:2021 - Vulnerable "
                        "and Outdated Components",
                    "tool_source":   "trivy",
                    "cve_id":        cve_id,
                    "cvss_score":    cvss_score,
                    "money_loss_min": 10000,
                    "money_loss_max": 1000000,
                    "attack_name":
                        f"CVE Exploit: {cve_id}",
                    "quick_fix":
                        f"Update {pkg} to "
                        f"v{fixed} or later",
                })

        vuln_count = len([
            f for f in findings
            if f.get("attack_worked")
        ])
        if vuln_count:
            on_progress(
                f"🚨 Trivy: {vuln_count} "
                f"vulnerable dependencies!",
                78, tool="trivy",
            )
        else:
            on_progress(
                "✅ Trivy: No known CVEs found",
                78, tool="trivy",
            )

        return findings
