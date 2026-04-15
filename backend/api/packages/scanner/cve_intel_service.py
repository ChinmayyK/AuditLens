import requests
import logging
import time
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)

# Basic Mapping for common technologies to a:vendor:product format
# This is a 'best-effort' mapping for the demo.
CPE_MAP = {
    "Nginx":         "nginx:nginx",
    "Apache":        "apache:http_server",
    "PHP":           "php:php",
    "WordPress":     "wordpress:wordpress",
    "MySQL":         "mysql:mysql",
    "OpenSSL":       "openssl:openssl",
    "Drupal":        "drupal:drupal",
    "Joomla":        "joomla:joomla",
    "Django":        "django:django",
    "Laravel":       "laravel:laravel",
    "Ruby on Rails": "rubyonrails:ruby_on_rails",
    "Bootstrap CSS": "getbootstrap:bootstrap",
    "jQuery":        "jquery:jquery",
}

class CveIntelService:
    """
    Queries the National Vulnerability Database (NVD) API 2.0 
    for CVEs associated with detected technologies and versions.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.headers = {"apiKey": api_key} if api_key else {}
        # Delay to avoid rate limiting (NVD allows 5/30s without key)
        self.delay = 0.5 if api_key else 6.1

    def get_cves_for_tech(self, name: str, version: str) -> List[Dict]:
        """
        Searches for CVEs given a technology name and version.
        """
        if not version:
            return []

        # 1. Resolve CPE string
        cpe_vendor_product = CPE_MAP.get(name)
        if not cpe_vendor_product:
            # Try lowercase name as a guess for vendor:product
            cpe_vendor_product = f"{name.lower()}:{name.lower()}"

        cpe_string = f"cpe:2.3:a:{cpe_vendor_product}:{version}:*:*:*:*:*:*:*"
        
        logger.info(f"Querying NVD for CPE: {cpe_string}")
        
        params = {
            "cpeName": cpe_string,
            "resultsPerPage": 10 # We only need the top vulnerabilities
        }

        try:
            # Respect rate limits
            time.sleep(self.delay)
            
            response = requests.get(
                self.base_url, 
                params=params, 
                headers=self.headers,
                timeout=15
            )
            
            if response.status_code == 200:
                return self._parse_nvd_response(response.json(), name, version)
            elif response.status_code == 403:
                logger.warning("NVD API Rate limit exceeded.")
                return []
            else:
                logger.error(f"NVD API error: {response.status_code}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to query NVD for {name}: {e}")
            return []

    def _parse_nvd_response(self, data: Dict, name: str, version: str) -> List[Dict]:
        findings = []
        vulnerabilities = data.get("vulnerabilities", [])
        
        if not vulnerabilities:
            return []

        cve_list = []
        max_score = 0.0
        
        for v in vulnerabilities:
            cve = v.get("cve", {})
            cve_id = cve.get("id")
            
            # Extract CVSS score (prioritize V3.1 then V3.0 then V2)
            metrics = cve.get("metrics", {})
            score = 0.0
            
            v31 = metrics.get("cvssMetricV31", [])
            v30 = metrics.get("cvssMetricV30", [])
            v2 = metrics.get("cvssMetricV2", [])
            
            if v31:
                score = v31[0].get("cvssData", {}).get("baseScore", 0.0)
            elif v30:
                score = v30[0].get("cvssData", {}).get("baseScore", 0.0)
            elif v2:
                score = v2[0].get("cvssData", {}).get("baseScore", 0.0)

            cve_list.append({
                "id": cve_id,
                "score": score,
                "description": cve.get("descriptions", [{}])[0].get("value", "")
            })
            
            if score > max_score:
                max_score = score

        # Summarize into one finding
        severity = "info"
        if max_score >= 9.0: severity = "critical"
        elif max_score >= 7.0: severity = "high"
        elif max_score >= 4.0: severity = "medium"
        elif max_score > 0: severity = "low"

        cve_ids_str = ", ".join([c["id"] for c in cve_list[:3]])
        if len(cve_list) > 3:
            cve_ids_str += f" and {len(cve_list) - 3} others"

        findings.append({
            "vuln_type": f"Outdated Technology: {name} {version}",
            "severity": severity,
            "category": "recon",
            "cvss_score": max_score,
            "description": (
                f"Detected {name} version {version} possesses {len(cve_list)} known vulnerabilities "
                f"recorded in the NVD. Highest score detected: {max_score}.\n\n"
                f"Relevant CVEs: {cve_ids_str}"
            ),
            "evidence": f"Tech: {name} | Version: {version} | NVD Match: {len(cve_list)} vulnerabilities",
            "tool_source": "nvd_live_lookup",
            "attack_worked": True if max_score > 0 else False,
            "was_attempted": True,
            "recommendation": f"Update {name} to the latest secure version to mitigate these known public exploits."
        })

        return findings
