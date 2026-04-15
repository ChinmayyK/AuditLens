import requests
import logging
from typing import List, Dict

logger = logging.getLogger(__name__)

class CorsService:
    """
    Service to detect CORS (Cross-Origin Resource Sharing) misconfigurations.
    Tests if the server improperly reflects arbitrary origins or allows
    untrusted origins with credentials.
    """

    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.test_origins = [
            "https://evil.com",
            "http://attacker.local",
            "null",
            "https://google.com"
        ]

    def scan(self, url: str) -> List[Dict]:
        """
        Scans a URL for CORS misconfigurations.
        Returns a list of finding dictionaries.
        """
        findings = []
        
        for origin in self.test_origins:
            try:
                # Send request with a custom Origin header
                headers = {"Origin": origin}
                # We use OPTIONS first to see preflight behavior, 
                # then GET to check actual resource reflection
                
                # Test 1: OPTIONS (Preflight)
                options_resp = requests.options(url, headers=headers, timeout=self.timeout)
                findings.extend(self._analyze_response(url, origin, options_resp, "OPTIONS"))
                
                # Test 2: GET (Actual Request)
                get_resp = requests.get(url, headers=headers, timeout=self.timeout)
                findings.extend(self._analyze_response(url, origin, get_resp, "GET"))
                
            except Exception as e:
                logger.warning(f"CORS scan failed for {url} with origin {origin}: {e}")
                
        # Deduplicate findings based on type and origin
        unique_findings = []
        seen = set()
        for f in findings:
            key = (f["vuln_type"], f["evidence"])
            if key not in seen:
                unique_findings.append(f)
                seen.add(key)
                
        return unique_findings

    def _analyze_response(self, url: str, test_origin: str, response: requests.Response, method: str) -> List[Dict]:
        findings = []
        acao = response.headers.get("Access-Control-Allow-Origin")
        acac = response.headers.get("Access-Control-Allow-Credentials")
        
        # 1. Reflected Origin Misconfiguration (Critical if credentials allowed)
        if acao == test_origin:
            severity = "High" if acac == "true" else "Medium"
            findings.append({
                "vuln_type": "CORS Misconfiguration: Reflected Origin",
                "severity": severity,
                "description": (
                    f"The server reflects arbitrary origins in the Access-Control-Allow-Origin header. "
                    f"Testing with '{test_origin}' resulted in its reflection."
                ),
                "url": url,
                "evidence": f"Method: {method} | Origin: {test_origin} | ACAO: {acao} | ACAC: {acac}",
                "recommendation": "Whitelist specific trusted domains only. Avoid reflecting the Origin header value."
            })
            
        # 2. Wildcard with Credentials (Invalid but dangerous if browsers were to allow it)
        elif acao == "*" and acac == "true":
            findings.append({
                "vuln_type": "CORS Misconfiguration: Wildcard with Credentials",
                "severity": "High",
                "description": (
                    "The server uses a wildcard (*) for Access-Control-Allow-Origin while setting "
                    "Access-Control-Allow-Credentials to true. This is an insecure configuration."
                ),
                "url": url,
                "evidence": f"Method: {method} | ACAO: * | ACAC: true",
                "recommendation": "Wildcard origins cannot be used with credentials. Specify a single trusted origin."
            })
            
        # 3. Development/Null Origin Reflection
        elif test_origin == "null" and acao == "null":
            findings.append({
                "vuln_type": "CORS Misconfiguration: Null Origin Allowed",
                "severity": "Medium",
                "description": (
                    "The server allows the 'null' origin. This can be exploited via sandboxed iframes "
                    "or local files to bypass CORS protections."
                ),
                "url": url,
                "evidence": f"Method: {method} | Origin: null | ACAO: null",
                "recommendation": "Do not whitelist the 'null' origin."
            })

        return findings
