import requests
import json
import logging
from urllib.parse import urljoin, urlparse
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

COMMON_SPEC_PATHS = [
    "/swagger.json",
    "/swagger.yaml",
    "/api-docs",
    "/api/docs",
    "/openapi.json",
    "/openapi.yaml",
    "/v1/swagger.json",
    "/v2/swagger.json",
    "/v3/swagger.json",
    "/api/v1/docs",
    "/docs/openapi.json",
]

class APIContractFuzzer:
    """
    Finds and parses OpenAPI/Swagger specs to automatically fuzz API endpoints.
    """

    def __init__(self, target_url: str):
        parsed = urlparse(target_url)
        self.base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "ShieldSentinel/1.0 APIFuzzer"})

    def scan(self, scan_id: str) -> List[Dict[str, Any]]:
        findings = []
        spec = self._find_and_parse_spec()
        
        if not spec:
            logger.info("No API specification found for fuzzing.")
            return findings

        paths = spec.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.lower() not in ["get", "post", "put", "delete", "patch"]:
                    continue
                
                fuzz_url = urljoin(self.base_url, path)
                logger.info(f"Fuzzing API endpoint: {method.upper()} {fuzz_url}")
                
                # Extract parameters
                parameters = details.get("parameters", [])
                
                # Fuzzing Logic
                findings.extend(self._fuzz_endpoint(fuzz_url, method.upper(), parameters, scan_id))

        return findings

    def _find_and_parse_spec(self) -> Dict[str, Any] | None:
        for path in COMMON_SPEC_PATHS:
            url = urljoin(self.base_url, path)
            try:
                resp = self.session.get(url, timeout=5, verify=False)
                if resp.status_code == 200:
                    try:
                        # Try parsing as JSON first
                        return resp.json()
                    except:
                        # Fallback for YAML (very basic check)
                        if "openapi:" in resp.text or "swagger:" in resp.text:
                            # In a real tool we'd use PyYAML, but for now we look for JSON structure
                            # or notify that a YAML spec was found.
                            pass
            except Exception:
                continue
        return None

    def _fuzz_endpoint(self, url: str, method: str, parameters: List[Dict[str, Any]], scan_id: str) -> List[Dict[str, Any]]:
        findings = []
        
        # Test Case 1: Type Mismatch (e.g. sending string where int expected)
        payload = {}
        for p in parameters:
            name = p.get("name")
            p_type = p.get("schema", {}).get("type", "string")
            if p_type == "integer" or p_type == "number":
                payload[name] = "not_a_number_fuzz_test"
            else:
                payload[name] = 12345
        
        findings.extend(self._send_fuzz_request(url, method, payload, "Type Mismatch", scan_id))

        # Test Case 2: Boundary Values
        payload = {}
        for p in parameters:
            name = p.get("name")
            p_type = p.get("schema", {}).get("type", "string")
            if p_type == "integer" or p_type == "number":
                payload[name] = -1 # Negative
            else:
                payload[name] = "" # Empty
        
        findings.extend(self._send_fuzz_request(url, method, payload, "Boundary Value", scan_id))

        # Test Case 3: Buffer Overflow / Long String
        payload = {}
        for p in parameters:
            payload[p.get("name")] = "A" * 5000
        
        findings.extend(self._send_fuzz_request(url, method, payload, "Buffer Overflow/Long String", scan_id))

        return findings

    def _send_fuzz_request(self, url: str, method: str, payload: dict, test_name: str, scan_id: str) -> List[Dict[str, Any]]:
        try:
            if method == "GET":
                resp = self.session.get(url, params=payload, timeout=10, verify=False)
            else:
                resp = self.session.request(method, url, json=payload, timeout=10, verify=False)

            # If it's a 500 error or similar, it's a finding
            if resp.status_code == 500:
                return [{
                    "scan_id": scan_id,
                    "vuln_type": "API Fuzzing Failure (500 Internal Error)",
                    "severity": "Medium",
                    "url": url,
                    "evidence": f"Test: {test_name}. Payload: {json.dumps(payload)[:100]}. Method: {method}",
                    "description": f"The API endpoint returned a 500 Internal Server Error when provided with {test_name} input. This often indicates unhandled exceptions or potential stability issues in the API contract implementation.",
                    "attack_worked": True,
                    "tool_source": "api_contract_fuzzer",
                }]
            
            # Check for stack traces
            if any(x in resp.text.lower() for x in ["stack trace", "exception", "debug info", "line "]):
                 return [{
                    "scan_id": scan_id,
                    "vuln_type": "API Fuzzing: Information Disclosure",
                    "severity": "High",
                    "url": url,
                    "evidence": "Fuzzing triggered a response containing potential stack trace or debug information.",
                    "description": "Providing malformed input to the API caused it to leak internal exception details or stack traces. This reveals implementation details that can be used for further exploitation.",
                    "attack_worked": True,
                    "tool_source": "api_contract_fuzzer",
                }]

        except Exception:
            pass
        return []
