import subprocess
import json
import requests
import random
import string
import urllib3
urllib3.disable_warnings()

from packages.scanner.wordlist_paths import (
    resolve_scanner_wordlist,
)

SENSITIVE_KEYWORDS = [
    ".env", ".git", "admin", "backup", "config",
    "wp-admin", "phpmyadmin", ".htaccess", "debug",
    "secret", "password", "credentials", "token",
    "api_key", "database", "db", "test", "staging",
    ".DS_Store", "Thumbs.db", "error_log",
    "access_log", "phpinfo", "info.php",
    "server-status", "server-info",
    "crossdomain.xml", "sitemap.xml",
    "robots.txt", "swagger", "api-docs",
    "graphql", "console", "actuator",
    "health", "metrics", "env", "dump",
]


class FFUFService:

    def detect_soft_404(
        self, target_url: str
    ) -> tuple:
        """
        Detect if server returns HTTP 200 for all paths.
        Returns (is_soft_404, baseline_size, baseline_text).
        """
        # Next.js / React sites often have custom 404s.
        # We check 3 random paths of varying lengths.
        fake_paths = [
            "antigravity_" + "".join(random.choices(string.ascii_lowercase, k=10)),
            "safety_check_" + "".join(random.choices(string.ascii_lowercase, k=15)),
            "probe_" + "".join(random.choices(string.ascii_lowercase, k=20)),
        ]

        results = []
        try:
            for fp in fake_paths:
                r = requests.get(
                    f"{target_url.rstrip('/')}/{fp}",
                    timeout=8,
                    headers={"User-Agent": "Mozilla/5.0 (ShieldSentinel/1.0)"},
                    verify=False,
                    allow_redirects=True,
                )
                if r.status_code == 200:
                    results.append({"size": len(r.content), "text": r.text[:2000]})
        except Exception:
            return False, 0, ""

        if len(results) >= 2:
            sizes = [r["size"] for r in results]
            avg = sum(sizes) / len(sizes)
            
            # Check if sizes are suspiciously close
            is_consistent_size = True
            for s in sizes:
                if abs(s - avg) > (avg * 0.1): # 10% variance allowed
                    is_consistent_size = False
                    break
            
            if is_consistent_size:
                # If sizes are close, it's likely a soft-404
                return True, int(avg), results[0]["text"]

        return False, 0, ""

    def scan(
        self,
        target_url: str,
        scan_id: str,
        on_progress,
    ) -> list:
        on_progress(
            "📂 Discovering hidden paths and files...",
            17, tool="ffuf",
        )

        wordlist = resolve_scanner_wordlist()
        if not wordlist:
            on_progress(
                "⚠️ Wordlist not found, skipping FFUF",
                19, tool="ffuf",
            )
            return []

        # Detect soft-404
        is_soft404, baseline_size, baseline_text = \
            self.detect_soft_404(target_url)

        output_file = f"/tmp/{scan_id}_ffuf.json"
        base_url = target_url.rstrip("/") + "/FUZZ"

        # Base FFUF command
        cmd = [
            "ffuf",
            "-u",    base_url,
            "-w",    wordlist,
            "-o",    output_file,
            "-of",   "json",
            "-mc",   "200,201,301,302,403,405",
            "-t",    "50",
            "-timeout", "10",
            "-maxtime", "120",
            "-fc",   "404",
            "-fl",   "0", # Filter 0-byte responses
            "-s",         # silent
        ]

        # Sharp filtering for soft-404 servers
        if is_soft404:
            # We filter the exact baseline size and a small range around it
            # Also filter by word count if ffuf supports it, but size is more reliable here
            # Next.js pages often reflect the path, so size changes slightly.
            # We use a broader range but we'll also post-process.
            variance = int(baseline_size * 0.15)
            cmd.extend([
                "-fs",
                f"{baseline_size - variance}-{baseline_size + variance}",
            ])

        try:
            subprocess.run(
                cmd,
                capture_output=True,
                timeout=180,
            )
        except subprocess.TimeoutExpired:
            on_progress("⚠️ FFUF timed out", 21, tool="ffuf")
            return []
        except FileNotFoundError:
            on_progress("⚠️ FFUF not found", 21, tool="ffuf")
            return []

        return self._parse_output(
            output_file, scan_id, target_url,
            baseline_size if is_soft404 else 0,
            baseline_text if is_soft404 else "",
        )

    def _parse_output(
        self,
        output_file: str,
        scan_id: str,
        target_url: str,
        baseline_size: int,
        baseline_text: str = "",
    ) -> list:
        findings = []

        try:
            with open(output_file) as f:
                data = json.load(f)
        except Exception:
            return []

        results = data.get("results", [])
        if not results:
            return []

        # If we have a massive amount of results from FFUF,
        # it almost certainly means we've hit a false-positive wall.
        # We will group them significantly.
        MAX_INDIVIDUAL_FINDINGS = 40
        unique_sizes = set()
        
        raw_findings = []
        for result in results:
            url    = result.get("url", "")
            status = result.get("status", 0)
            size   = result.get("length", 0)
            
        raw_findings = []
        for result in results:
            url    = result.get("url", "")
            status = result.get("status", 0)
            size   = result.get("length", 0)
            
            # 1. Advanced size-based filtering
            if baseline_size > 0:
                if abs(size - baseline_size) < (baseline_size * 0.05):
                    continue
            
            url_lower = url.lower()
            is_sensitive = any(kw in url_lower for kw in SENSITIVE_KEYWORDS)

            if not is_sensitive and status not in [200, 201]:
                continue
            
            raw_findings.append(result)
            unique_sizes.add(size)

        # 2. Content-Similarity Secondary Check
        # If the server is a soft-404 server, we must verify that the content
        # isn't just a slightly different 404 page (e.g. Next.js 404 page).
        verified_results = []
        
        # We only verify the top candidates to save time
        to_verify = raw_findings[:30]
        
        if is_soft404 and baseline_text:
            # Common 404 indicators
            markers = ["404", "not found", "could not be found", "doesn't exist"]
            has_404_marker = any(m in baseline_text.lower() for m in markers)
            
            for res in to_verify:
                url = res.get("url", "")
                try:
                    # Quick fetch to check content
                    verify_r = requests.get(
                        url, timeout=5,
                        headers={"User-Agent": "ShieldSentinel/1.0 Verification"},
                        verify=False
                    )
                    # If the content is basically the same as baseline or has 404 markers, it's a false positive
                    content = verify_r.text[:2000].lower()
                    
                    # Fuzzy match: if it has the same 404 markers as the baseline, skip it
                    is_fake = False
                    if has_404_marker:
                        matches_markers = any(m in content for m in markers if m in baseline_text.lower())
                        if matches_markers:
                            is_fake = True
                    
                    # Size comparison (more strict than the broad ffuf filter)
                    if not is_fake and abs(len(verify_r.content) - baseline_size) < (baseline_size * 0.05):
                        is_fake = True
                        
                    if not is_fake:
                        verified_results.append(res)
                except:
                    # If we can't verify, we'll keep it if it's sensitive, else drop
                    if any(kw in url.lower() for kw in SENSITIVE_KEYWORDS):
                        verified_results.append(res)
            
            # If we had hundreds of hits but 0 verified, the whole scan is noise
            if len(to_verify) > 10 and len(verified_results) == 0:
                raw_findings = [] # Kill the noise entirely
            else:
                raw_findings = verified_results
        
        # If too many findings with very few unique sizes -> definitely noise
        is_repetitive = len(raw_findings) > 50 and len(unique_sizes) < 10
        
        final_findings = []
        
        # If too noisy, we only report a summary finding
        if is_repetitive or len(raw_findings) > 150:
            top_paths = [r.get("url", "") for r in raw_findings[:15]]
            summary_desc = (
                f"The server appears to return valid responses (HTTP 200) for a large number of potential paths. "
                f"This often indicates a catch-all configuration or a Single Page Application (SPA) routing issues. "
                f"A total of {len(raw_findings)} paths were detected, including: {', '.join(top_paths)}..."
            )
            final_findings.append({
                "scan_id":      scan_id,
                "vuln_type":    "Mass Path Enumeration Disclosure",
                "severity":     "medium",
                "category":     "exposure",
                "url":          target_url,
                "evidence":     f"Detected {len(raw_findings)} active paths with {len(unique_sizes)} unique response sizes.",
                "description":  summary_desc,
                "attack_worked": True,
                "was_attempted": True,
                "tool_source":   "ffuf",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "money_loss_min": 1000,
                "money_loss_max": 50000,
                "attack_name": "Massive Directory Discovery",
            })
            # Also include the first 10 sensitive ones as separate if they exist
            sensitive_only = [r for r in raw_findings if any(kw in r.get("url", "").lower() for kw in SENSITIVE_KEYWORDS)]
            raw_findings = sensitive_only[:15]

        for result in raw_findings[:100]: # Cap at 100 to prevent DB bloat
            url    = result.get("url", "")
            status = result.get("status", 0)
            size   = result.get("length", 0)

            url_lower = url.lower()
            is_sensitive = any(
                kw in url_lower
                for kw in SENSITIVE_KEYWORDS
            )

            if is_sensitive:
                severity = "high"
                vuln_type = "Sensitive File Exposed"
                desc = (
                    f"Sensitive path '{url}' is accessible (HTTP {status}). "
                    f"This may expose configuration, credentials, or admin interfaces."
                )
                money = (10000, 1000000)
            else:
                severity = "medium"
                vuln_type = "Restricted Path Accessible"
                desc = f"Path '{url}' returns HTTP {status}. Possible hidden endpoint."
                money = (1000, 100000)

            final_findings.append({
                "scan_id":      scan_id,
                "vuln_type":    vuln_type,
                "severity":     severity,
                "category":     "exposure",
                "url":          url,
                "evidence":     f"HTTP {status}, size={size}b",
                "description":  desc,
                "attack_worked": True,
                "was_attempted": True,
                "tool_source":   "ffuf",
                "owasp_category": "A05:2021 - Security Misconfiguration",
                "money_loss_min": money[0],
                "money_loss_max": money[1],
                "attack_name": "Directory/File Enumeration",
            })

        return final_findings
