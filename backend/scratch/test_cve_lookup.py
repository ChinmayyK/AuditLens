import sys
import os

# Mocking the environment
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../api")))

from packages.scanner.cve_intel_service import CveIntelService

def test_cve_lookup():
    # Use a version known to have CVEs
    name = "Nginx"
    version = "1.14.0"
    
    print(f"Querying NVD for {name} {version}...")
    # No API key for this test, will have a 6s delay
    scanner = CveIntelService()
    findings = scanner.get_cves_for_tech(name, version)
    
    print(f"Found {len(findings)} summary findings.")
    for f in findings:
        print(f" - [{f['severity']}] {f['vuln_type']}")
        print(f"   CVSS: {f['cvss_score']}")
        print(f"   Description: {f['description'][:200]}...")

if __name__ == "__main__":
    test_cve_lookup()
