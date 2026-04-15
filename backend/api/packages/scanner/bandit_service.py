import subprocess
import json
import logging

logger = logging.getLogger(__name__)

SEV_MAP  = {"HIGH": "high", "MEDIUM": "medium",
            "LOW":  "low"}
CONF_MAP = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _bandit_vuln_type(test_id: str,
                       text: str) -> str:
    t = (test_id + text).lower()
    if "sql"       in t: return "SQL Injection"
    if "shell"     in t: return "Command Injection"
    if "subprocess"in t: return "Command Injection"
    if "pickle"    in t: return "Insecure Deserialization"
    if "md5"       in t: return "Weak Cryptography"
    if "sha1"      in t: return "Weak Cryptography"
    if "hardcoded" in t: return "Hardcoded Secret"
    if "password"  in t: return "Hardcoded Secret"
    if "assert"    in t: return "Debug Code"
    if "yaml.load" in t: return "Insecure YAML Load"
    if "xml"       in t: return "XML Injection"
    if "jinja2"    in t: return "SSTI"
    if "eval"      in t: return "Code Injection"
    if "exec"      in t: return "Code Injection"
    return "Python Security Issue"


class BanditService:

    def scan(
        self,
        code_path: str,
        scan_id: str,
        on_progress,
    ) -> list:
        on_progress(
            "🐍 Bandit Python security analysis...",
            58, tool="bandit",
        )
        output_file = f"/tmp/{scan_id}_bandit.json"

        cmd = [
            "bandit",
            "-r", code_path,
            "-f", "json",
            "-o", output_file,
            "-ll",
            "--quiet",
            "--exclude",
            ".git,node_modules,venv,.venv,dist",
        ]

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
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

        for r in data.get("results", []):
            sev  = SEV_MAP.get(
                r.get("issue_severity", "LOW"), "low"
            )
            conf = CONF_MAP.get(
                r.get("issue_confidence", "LOW"), 1
            )

            # Skip low-confidence + low-severity
            if sev == "low" and conf < 2:
                continue

            vuln_type = _bandit_vuln_type(
                r.get("test_id", ""),
                r.get("issue_text", ""),
            )

            findings.append({
                "scan_id":      scan_id,
                "vuln_type":    vuln_type,
                "severity":     sev,
                "category":     "sast",
                "file_path":    r.get("filename", ""),
                "line_number":  r.get("line_number"),
                "code_snippet":
                    r.get("code", "")[:300],
                "evidence":
                    r.get("code", "")[:300],
                "description":
                    f"{r.get('issue_text', '')} "
                    f"[Bandit: {r.get('test_id', '')}]",
                "attack_worked":
                    sev in ["high", "medium"],
                "was_attempted": True,
                "owasp_category":
                    "A03:2021 - Injection",
                "tool_source":   "bandit",
                "cwe_id":
                    r.get("issue_cwe", {})
                     .get("id"),
                "money_loss_min": 5000,
                "money_loss_max": 500000,
                "attack_name":
                    f"Python: {vuln_type}",
            })

        vuln_count = len([
            f for f in findings
            if f.get("attack_worked")
        ])
        return findings
