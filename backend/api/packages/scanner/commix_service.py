import logging
import os
import re
import subprocess
from urllib.parse import urlparse, urlencode, parse_qs, urlunparse

logger = logging.getLogger(__name__)

COMMIX_SCRIPT = os.getenv(
    "COMMIX_PATH",
    "/opt/commix/commix.py",
)


class CommixService:
    """
    OS command injection probing via Commix (batch mode).
    Deep / aggressive only — limited URLs to control runtime.
    """

    def scan_parameters(
        self,
        scan_id: str,
        get_params: list,
        on_progress,
        intensity: str = "deep",
    ) -> list:
        findings = []

        if not os.path.isfile(COMMIX_SCRIPT):
            on_progress(
                "⚠️ Commix not installed, skipping",
                83, tool="commix",
            )
            return findings

        max_urls = 4 if intensity == "deep" else 6
        per_url_timeout = 55 if intensity == "deep" else 75

        tested = 0
        for item in get_params[:max_urls]:
            url = (item.get("url") or "").strip()
            param = (item.get("param") or "").strip()
            if not url or not param:
                continue

            inject_url = self._url_with_probe(url, param)
            if not inject_url:
                continue

            on_progress(
                f"💀 Commix → {param} @ {url[:48]}...",
                83, tool="commix",
                event_type="attack",
            )

            stdout, _stderr = self._run_commix(
                inject_url, per_url_timeout,
            )
            tested += 1

            if self._looks_vulnerable(stdout):
                findings.append({
                    "scan_id":       scan_id,
                    "vuln_type":
                        "OS Command Injection",
                    "severity":      "critical",
                    "category":      "injection",
                    "url":           url,
                    "parameter":     param,
                    "evidence":
                        (stdout[-1200:] if stdout else "")[:800],
                    "description":
                        "Commix reported a likely OS command "
                        "injection on this parameter. An "
                        "attacker may run shell commands on "
                        "the server.",
                    "attack_worked": True,
                    "was_attempted": True,
                    "tool_source":   "commix",
                    "owasp_category":
                        "A03:2021 - Injection",
                    "money_loss_min": 50000,
                    "money_loss_max": 5000000,
                    "attack_name":
                        "OS Command Injection",
                })

        if tested == 0:
            on_progress(
                "⏭️ Commix: no suitable GET parameters",
                84, tool="commix",
            )

        return findings

    def _url_with_probe(self, url: str, param: str) -> str | None:
        """Append a harmless echo-based probe token to one parameter."""
        try:
            parts = urlparse(url)
            q = parse_qs(parts.query, keep_blank_values=True)
            if param not in q:
                q[param] = [""]
            # Probe substring Commix may detect
            q[param] = [
                f"{q[param][0]};echo commix_probe_9f2a",
            ]
            new_q = urlencode(q, doseq=True)
            return urlunparse(
                (
                    parts.scheme, parts.netloc, parts.path,
                    parts.params, new_q, parts.fragment,
                )
            )
        except Exception:
            return None

    def _run_commix(
        self, url: str, timeout: int,
    ) -> tuple[str, str]:
        cmd = [
            "python3",
            COMMIX_SCRIPT,
            "-u", url,
            "--batch",
            "--disable-coloring",
            "--timeout=20",
            "--retries=0",
        ]
        try:
            p = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return p.stdout or "", p.stderr or ""
        except subprocess.TimeoutExpired:
            return "", "timeout"
        except FileNotFoundError:
            return "", "no python"

    _VULN_PATTERNS = re.compile(
        r"(?i)(confirmed vul|successfully inject|command injection confirmed|exploit confirm|(\[v\]ulnerable))",
    )

    def _looks_vulnerable(self, stdout: str) -> bool:
        if not stdout or len(stdout) < 150:
            return False
        
        # Commix often lists "potential" or "testing" which aren't findings
        # We look for high-confidence strings
        has_signal = bool(self._VULN_PATTERNS.search(stdout))
        
        # Additional hygiene: check if commix actually found an injection point
        is_testing = "testing the" in stdout.lower() and "is vulnerable" not in stdout.lower()
        
        return has_signal and not is_testing
