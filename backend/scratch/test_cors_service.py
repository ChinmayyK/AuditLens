import sys
import os

# Mocking the environment
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../api")))

from packages.scanner.cors_service import CorsService

def test_cors():
    scanner = CorsService()
    
    # Test against a common public API for demonstration (safely)
    target = "https://www.google.com"
    print(f"Scanning {target} for CORS issues...")
    findings = scanner.scan(target)
    
    print(f"Found {len(findings)} issues.")
    for f in findings:
        print(f" - [{f['severity']}] {f['vuln_type']}")
        print(f"   Evidence: {f['evidence']}")

if __name__ == "__main__":
    test_cors()
