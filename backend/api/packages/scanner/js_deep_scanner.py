import requests
import re
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Essential regex patterns for secrets in JS files
SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"([^A-Z0-9/+=][A-Za-z0-9/+=]{40}[^A-Z0-9/+=])", # Heuristic
    "Google API Key": r"AIza[0-9A-Za-z-_]{35}",
    "Firebase URL": r"https://[a-z0-9.-]+\.firebaseio\.com",
    "Slack Webhook": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+",
    "Stripe API Key": r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24}",
    "Heroku API Key": r"[hH][eE][rR][oO][kK][uU].*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    "MailChimp API Key": r"[0-9a-fA-F]{32}-us[0-9]{1,2}",
    "Facebook Access Token": r"EAACEdEose0cBA[0-9A-Za-z]+",
    "Private IP Address": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
    "Internal Domain/URL": r"https?://(?:internal|admin|dev|stage|prod|backup|vault|api-dev)\.[a-zA-Z0-9.-]+",
    "Generic Secret/Key": r"(?i)(?:key|password|secret|token|auth|pwd)\s*[:=]\s*['\"]([a-zA-Z0-9]{16,})['\"]",
}

# Patterns for sensitive comments
COMMENT_PATTERNS = [
    r"//\s*(?:TODO|FIXME|XXX|DEBUG|TEMP|PASSWORD|CREDENTIALS).*",
    r"/\*\s*(?:TODO|FIXME|XXX|DEBUG|TEMP|PASSWORD|CREDENTIALS)[\s\S]*?\*/",
]

class JSDeepScanner:
    """
    Fetches and deep-scans JavaScript files for secrets, internal URLs, and sensitive comments.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.base_url = f"{urlparse(target_url).scheme}://{urlparse(target_url).netloc}"
        self.scanned_files = set()

    def scan(self, discovered_urls: List[str], scan_id: str) -> List[Dict[str, Any]]:
        findings = []
        js_urls = self._collect_js_urls(discovered_urls)

        for js_url in js_urls:
            if js_url in self.scanned_files:
                continue
            
            logger.info(f"Deep scanning JS file: {js_url}")
            file_findings = self._scan_single_file(js_url, scan_id)
            findings.extend(file_findings)
            self.scanned_files.add(js_url)

        return findings

    def _collect_js_urls(self, urls: List[str]) -> set:
        js_urls = set()
        
        # 1. Direct JS files from crawl
        for url in urls:
            if url.lower().endswith(".js") or ".js?" in url.lower():
                js_urls.add(url)
        
        # 2. Extract from HTML pages
        for url in urls:
            if not any(url.lower().endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff"]):
                try:
                    resp = requests.get(url, timeout=10, verify=False, headers={"User-Agent": "ShieldSentinel/1.0"})
                    if "text/html" in resp.headers.get("Content-Type", "").lower():
                        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', resp.text, re.IGNORECASE)
                        for s in scripts:
                            full_url = urljoin(url, s)
                            if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                                js_urls.add(full_url)
                except Exception:
                    continue
                    
        return js_urls

    def _scan_single_file(self, url: str, scan_id: str) -> List[Dict[str, Any]]:
        findings = []
        try:
            resp = requests.get(url, timeout=15, verify=False, headers={"User-Agent": "ShieldSentinel/1.0"})
            content = resp.text
            
            # --- Secret Scanning ---
            for name, pattern in SECRET_PATTERNS.items():
                matches = re.finditer(pattern, content)
                for match in matches:
                    snippet = content[max(0, match.start()-30) : min(len(content), match.end()+30)]
                    findings.append({
                        "scan_id": scan_id,
                        "vuln_type": "Sensitive Data Exposure in JS",
                        "severity": "High" if "Key" in name or "Secret" in name else "Medium",
                        "url": url,
                        "evidence": f"Pattern matched: {name}. Snippet: ...{snippet}...",
                        "description": f"A potential {name} was found hardcoded in a public JavaScript file. This could lead to unauthorized access to cloud services or internal infrastructure.",
                        "attack_worked": True,
                        "tool_source": "js_deep_scanner",
                    })

            # --- Sensitive Comment Scanning ---
            for pattern in COMMENT_PATTERNS:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    findings.append({
                        "scan_id": scan_id,
                        "vuln_type": "Sensitive Comment in JS",
                        "severity": "Low",
                        "url": url,
                        "evidence": f"Match: {match.group(0)[:100]}",
                        "description": "Sensitive comments (TODO, FIXME, DEBUG) or credentials found in JavaScript source. These can leak implementation details or forgotten debug credentials.",
                        "attack_worked": True,
                        "tool_source": "js_deep_scanner",
                    })

        except Exception as e:
            logger.debug(f"Failed to scan JS file {url}: {e}")
            
        return findings
