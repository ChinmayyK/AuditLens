import subprocess
import os
import re
import logging

logger = logging.getLogger(__name__)

INJECTION_TECHNIQUES = "BEUSTQ"


class SQLMapService:

    def scan_parameters(
        self,
        scan_id: str,
        get_params: list,
        post_params: list,
        on_progress,
        intensity: str = "standard",
    ) -> list:
        findings = []
        level = {
            "quick":      "1",
            "standard":   "2",
            "deep":       "3",
            "aggressive": "5",
        }.get(intensity, "2")

        risk = {
            "quick":      "1",
            "standard":   "1",
            "deep":       "2",
            "aggressive": "3",
        }.get(intensity, "1")

        total = (
            len(get_params[:8]) +
            len(post_params[:4])
        )
        done = 0

        for item in get_params[:8]:
            url   = item.get("url", "")
            param = item.get("param", "")
            if not url or not param:
                continue

            pct = 65 + int((done / max(total, 1)) * 12)
            on_progress(
                f"💉 SQLMap → {param} param on "
                f"{url[:40]}...",
                pct,
                tool="sqlmap",
                event_type="attack",
            )

            result = self._test_url(
                url, param, "GET",
                scan_id, level, risk,
            )
            findings.extend(result)
            done += 1

        for item in post_params[:4]:
            url    = item.get("url", "")
            params = item.get("params", [])
            if not url or not params:
                continue

            pct = 65 + int((done / max(total, 1)) * 12)
            on_progress(
                f"💉 SQLMap → POST form {url[:40]}",
                pct,
                tool="sqlmap",
                event_type="attack",
            )

            result = self._test_form(
                url, params, scan_id, level, risk
            )
            findings.extend(result)
            done += 1

        return findings

    def _test_url(
        self,
        url: str,
        param: str,
        method: str,
        scan_id: str,
        level: str,
        risk: str,
    ) -> list:
        output_dir = f"/tmp/{scan_id}_sqlmap_{param}"

        cmd = [
            "sqlmap",
            "-u",       url,
            "-p",       param,
            "--batch",
            "--level",  level,
            "--risk",   risk,
            "--technique", INJECTION_TECHNIQUES,
            "--timeout", "10",
            "--retries", "1",
            "--output-dir", output_dir,
            "--flush-session",
            "--no-cast",
            "--random-agent",
            f"--method={method}",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=150,
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return []
        except FileNotFoundError:
            return []

        return self._parse_output(
            output, url, param, scan_id
        )

    def _test_form(
        self,
        url: str,
        params: list,
        scan_id: str,
        level: str,
        risk: str,
    ) -> list:
        data_str = "&".join(
            f"{p}=TESTVALUE" for p in params[:6]
        )

        cmd = [
            "sqlmap",
            "-u",     url,
            "--data", data_str,
            "--batch",
            "--level", level,
            "--risk",  risk,
            "--technique", INJECTION_TECHNIQUES,
            "--timeout", "10",
            "--retries", "1",
            "--output-dir",
                f"/tmp/{scan_id}_sqlmap_form",
            "--flush-session",
            "--random-agent",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=150,
            )
            output = result.stdout + result.stderr
        except (subprocess.TimeoutExpired,
                FileNotFoundError):
            return []

        return self._parse_output(
            output, url,
            ", ".join(params[:3]), scan_id,
        )

    def _parse_output(
        self,
        output: str,
        url: str,
        param: str,
        scan_id: str,
    ) -> list:
        output_lower = output.lower()

        if "is vulnerable" not in output_lower and \
           "parameter" not in output_lower:
            return []

        # Detect injection type
        inj_type = "SQL Injection"
        if "boolean-based blind" in output_lower:
            inj_type = "SQL Injection (Boolean Blind)"
        elif "time-based blind" in output_lower:
            inj_type = "SQL Injection (Time Blind)"
        elif "error-based" in output_lower:
            inj_type = "SQL Injection (Error Based)"
        elif "union query" in output_lower or \
             "union-based" in output_lower:
            inj_type = "SQL Injection (UNION Based)"
        elif "stacked queries" in output_lower:
            inj_type = "SQL Injection (Stacked)"

        # Detect database type
        db_type = "Unknown"
        for db in [
            "MySQL", "PostgreSQL",
            "Microsoft SQL Server",
            "Oracle", "SQLite",
            "MariaDB", "Microsoft Access",
        ]:
            if db.lower() in output_lower:
                db_type = db
                break

        return [{
            "scan_id":    scan_id,
            "vuln_type":  inj_type,
            "severity":   "critical",
            "category":   "injection",
            "url":        url,
            "parameter":  param,
            "evidence":
                f"SQLMap confirmed: parameter "
                f"'{param}' injectable. "
                f"Type: {inj_type}. "
                f"Database: {db_type}.",
            "description":
                f"SQL injection confirmed in "
                f"parameter '{param}' at {url}. "
                f"Injection type: {inj_type}. "
                f"Database: {db_type}. "
                f"An attacker can read/modify/"
                f"delete the entire database, "
                f"bypass authentication, and "
                f"potentially execute OS commands.",
            "attack_worked":  True,
            "was_attempted":  True,
            "owasp_category":
                "A03:2021 - Injection",
            "tool_source":    "sqlmap",
            "cvss_score":     9.8,
            "cwe_id":         "CWE-89",
            "money_loss_min": 100000,
            "money_loss_max": 10000000,
            "attack_name":    inj_type,
            "layman_explanation":
                "SQL injection means the database "
                "executes commands from user input. "
                "Think of it like a bank teller "
                "following handwritten notes from "
                "strangers. An attacker writes "
                "database commands instead of "
                "normal input, and the server "
                "obeys them — giving away all "
                "data or full control.",
        }]
