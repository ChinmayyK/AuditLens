import subprocess
import json
import os
from pathlib import Path
import logging

logger = logging.getLogger(__name__)

SEVERITY_MAP = {
    "ERROR":   "high",
    "WARNING": "medium",
    "INFO":    "low",
}

VULN_TYPE_MAP = {
    "sql":           "SQL Injection",
    "sqli":          "SQL Injection",
    "injection":     "SQL Injection",
    "xss":           "Cross-Site Scripting",
    "ssrf":          "Server-Side Request Forgery",
    "path-traversal": "Path Traversal",
    "traversal":     "Path Traversal",
    "hardcoded":     "Hardcoded Secret",
    "secret":        "Hardcoded Secret",
    "password":      "Hardcoded Secret",
    "weak-crypto":   "Weak Cryptography",
    "md5":           "Weak Cryptography",
    "sha1":          "Weak Cryptography",
    "eval":          "Code Injection",
    "exec":          "Code Injection",
    "deserializ":    "Insecure Deserialization",
    "pickle":        "Insecure Deserialization",
    "xxe":           "XML External Entity",
    "csrf":          "CSRF",
    "open-redirect": "Open Redirect",
    "jwt":           "Broken Authentication",
    "auth":          "Broken Authentication",
    "cors":          "CORS Misconfiguration",
    "prototype":     "Prototype Pollution",
    "nosql":         "NoSQL Injection",
    "ldap":          "LDAP Injection",
    "xpath":         "XPath Injection",
    "ssti":          "Server-Side Template Injection",
    "template":      "Server-Side Template Injection",
    "rce":           "Remote Code Execution",
    "command":       "Command Injection",
    "shell":         "Command Injection",
}

OWASP_MAP = {
    "SQL Injection":                "A03:2021 - Injection",
    "Cross-Site Scripting":         "A03:2021 - Injection",
    "Code Injection":               "A03:2021 - Injection",
    "Command Injection":            "A03:2021 - Injection",
    "NoSQL Injection":              "A03:2021 - Injection",
    "LDAP Injection":               "A03:2021 - Injection",
    "XPath Injection":              "A03:2021 - Injection",
    "Server-Side Template Injection": "A03:2021 - Injection",
    "Remote Code Execution":        "A03:2021 - Injection",
    "Hardcoded Secret":             "A02:2021 - Cryptographic Failures",
    "Weak Cryptography":            "A02:2021 - Cryptographic Failures",
    "Path Traversal":               "A01:2021 - Broken Access Control",
    "CSRF":                         "A01:2021 - Broken Access Control",
    "Open Redirect":                "A01:2021 - Broken Access Control",
    "Broken Authentication":        "A07:2021 - Identification Failures",
    "Insecure Deserialization":     "A08:2021 - Deserialization",
    "Server-Side Request Forgery":  "A10:2021 - SSRF",
    "XML External Entity":          "A05:2021 - Security Misconfiguration",
    "CORS Misconfiguration":        "A05:2021 - Security Misconfiguration",
    "Prototype Pollution":          "A06:2021 - Vulnerable Components",
}

MONEY_MAP = {
    "SQL Injection":         (100000, 10000000),
    "Hardcoded Secret":      (50000,  5000000),
    "Remote Code Execution": (500000, 100000000),
    "Command Injection":     (200000, 50000000),
    "Insecure Deserialization": (100000, 10000000),
    "Server-Side Template Injection": (100000, 10000000),
}


class SemgrepService:

    def scan(
        self,
        code_path: str,
        scan_id: str,
        on_progress,
    ) -> list:
        on_progress(
            "🔍 Running Semgrep static analysis...",
            15, tool="semgrep",
        )

        cmd = [
            "semgrep",
            "--config=auto",
            "--json",
            "--timeout=60",
            "--max-memory=2000",
            "--jobs=2",
            "--no-git-ignore",
            code_path,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=240,
            )
        except subprocess.TimeoutExpired:
            on_progress(
                "⚠️ Semgrep timed out — partial results",
                38, tool="semgrep",
            )
            return []
        except FileNotFoundError:
            on_progress(
                "⚠️ Semgrep not available",
                38, tool="semgrep",
            )
            return []

        if not result.stdout.strip():
            on_progress(
                "✅ Semgrep: No issues found",
                38, tool="semgrep",
            )
            return []

        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError as e:
            logger.warning(
                f"Semgrep JSON parse error: {e}"
            )
            return []

        findings = self._parse(
            data.get("results", []),
            scan_id, code_path,
        )

        vuln_count = len([
            f for f in findings
            if f.get("attack_worked")
        ])
        on_progress(
            f"✅ Semgrep: {vuln_count} issues found",
            38, tool="semgrep",
        )
        return findings

    def _parse(
        self,
        results: list,
        scan_id: str,
        base_path: str,
    ) -> list:
        findings = []

        for r in results:
            check_id = r.get("check_id", "").lower()
            extra    = r.get("extra", {})
            sev_raw  = extra.get("severity", "INFO")
            severity = SEVERITY_MAP.get(sev_raw, "low")

            # Escalate severity for critical patterns
            if any(k in check_id for k in [
                "sql", "sqli", "rce", "command",
                "shell", "hardcoded-password",
                "pickle", "deserializ", "ssti",
            ]):
                severity = "high"
            if any(k in check_id for k in [
                "hardcoded-password",
                "hardcoded-secret",
                "private-key",
            ]):
                severity = "critical"

            vuln_type = self._map_vuln_type(check_id)

            # Relative file path
            full_path = r.get("path", "")
            try:
                rel_path = str(
                    Path(full_path).relative_to(
                        base_path
                    )
                )
            except ValueError:
                rel_path = full_path

            snippet = extra.get("lines", "")[:300]
            message = extra.get("message", "")[:600]

            owasp = OWASP_MAP.get(
                vuln_type,
                "A05:2021 - Security Misconfiguration",
            )
            money = MONEY_MAP.get(
                vuln_type, (5000, 500000)
            )

            findings.append({
                "scan_id":      scan_id,
                "vuln_type":    vuln_type,
                "severity":     severity,
                "category":     "sast",
                "file_path":    rel_path,
                "line_number":
                    r.get("start", {}).get("line"),
                "column_number":
                    r.get("start", {}).get("col"),
                "code_snippet": snippet,
                "evidence":     snippet,
                "description":  message,
                "attack_worked":
                    severity in [
                        "critical", "high", "medium"
                    ],
                "was_attempted": True,
                "owasp_category": owasp,
                "tool_source":   "semgrep",
                "money_loss_min": money[0],
                "money_loss_max": money[1],
                "attack_name":
                    f"Static: {vuln_type}",
                "cwe_id":
                    self._map_cwe(check_id),
            })

        return findings

    def _map_vuln_type(self, check_id: str) -> str:
        for kw, vt in VULN_TYPE_MAP.items():
            if kw in check_id:
                return vt
        return "Security Issue"

    def _map_cwe(self, check_id: str) -> str | None:
        cwe_map = {
            "sql":       "CWE-89",
            "xss":       "CWE-79",
            "ssrf":      "CWE-918",
            "traversal": "CWE-22",
            "command":   "CWE-78",
            "shell":     "CWE-78",
            "hardcoded": "CWE-798",
            "crypto":    "CWE-327",
            "deserializ":"CWE-502",
            "eval":      "CWE-95",
            "xxe":       "CWE-611",
            "csrf":      "CWE-352",
        }
        for k, v in cwe_map.items():
            if k in check_id:
                return v
        return None
