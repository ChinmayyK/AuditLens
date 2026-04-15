import subprocess
import json
import logging

logger = logging.getLogger(__name__)


class GitleaksService:

    def scan(
        self,
        code_path: str,
        scan_id: str,
        on_progress,
    ) -> list:
        on_progress(
            "🔑 Scanning for hardcoded secrets...",
            40, tool="gitleaks",
        )
        output_file = f"/tmp/{scan_id}_gitleaks.json"

        cmd = [
            "gitleaks",
            "detect",
            "--source",        code_path,
            "--report-format", "json",
            "--report-path",   output_file,
            "--no-git",
            "--exit-code",     "0",
            "--redact",
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=90,
            )
        except subprocess.TimeoutExpired:
            on_progress(
                "⚠️ Gitleaks timed out",
                48, tool="gitleaks",
            )
            return []
        except FileNotFoundError:
            on_progress(
                "⚠️ Gitleaks not available",
                48, tool="gitleaks",
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
                content = f.read().strip()
            if not content or content == "null":
                on_progress(
                    "✅ No hardcoded secrets found",
                    48, tool="gitleaks",
                )
                return []
            leaks = json.loads(content)
        except Exception:
            return []

        if not leaks:
            on_progress(
                "✅ No hardcoded secrets found",
                48, tool="gitleaks",
            )
            return []

        on_progress(
            f"🚨 {len(leaks)} hardcoded secrets found!",
            48, tool="gitleaks",
        )

        for leak in leaks:
            rule_id   = leak.get("RuleID", "secret")
            file_path = leak.get("File", "")
            line_num  = leak.get("StartLine", 0)
            match     = leak.get("Match", "")

            # Redact — never store actual secret
            redacted = self._redact(match)

            desc = (
                f"Hardcoded secret detected matching "
                f"rule '{rule_id}' in {file_path} "
                f"line {line_num}. Secret value "
                f"redacted. This credential may "
                f"allow attackers to authenticate "
                f"to external services directly."
            )

            findings.append({
                "scan_id":      scan_id,
                "vuln_type":    "Hardcoded Secret",
                "severity":     "critical",
                "category":     "secrets",
                "file_path":    file_path,
                "line_number":  line_num,
                "evidence":
                    f"Rule: {rule_id} | "
                    f"Match: {redacted}",
                "description":  desc,
                "attack_worked":  True,
                "was_attempted":  True,
                "owasp_category":
                    "A07:2021 - Identification "
                    "and Authentication Failures",
                "tool_source":   "gitleaks",
                "cvss_score":    9.1,
                "cwe_id":        "CWE-798",
                "money_loss_min": 50000,
                "money_loss_max": 5000000,
                "attack_name":
                    f"Exposed Credential: {rule_id}",
                "layman_explanation":
                    "A password or API key was found "
                    "written directly in the source "
                    "code. This is like leaving your "
                    "house key taped to the front "
                    "door — anyone who reads the "
                    "code can use it immediately.",
                "quick_fix":
                    "Move to environment variables: "
                    "os.getenv('SECRET_KEY'). "
                    "Add .env to .gitignore. "
                    "Rotate the exposed credential "
                    "immediately.",
            })

        return findings

    def _redact(self, match: str) -> str:
        if len(match) <= 4:
            return "****"
        visible = match[:4]
        stars = "*" * min(len(match) - 4, 12)
        return f"{visible}{stars}...[REDACTED]"
