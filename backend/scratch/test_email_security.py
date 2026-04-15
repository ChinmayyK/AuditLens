import sys
import os

# Add relevant paths
sys.path.insert(0, "/Users/stewie/Downloads/Enter/Projects/SecureWithAI/backend/api")
sys.path.insert(0, "/Users/stewie/Downloads/Enter/Projects/SecureWithAI/backend/api/packages")

from scanner.email_security_service import EmailSecurityService
import uuid
import json

def test_email_security():
    service = EmailSecurityService()
    test_domains = [
        "google.com",
        "example.com",
        "microsoft.com"
    ]
    
    scan_id = str(uuid.uuid4())
    
    for domain in test_domains:
        print(f"\n--- Testing domain: {domain} ---")
        findings = service.scan(f"http://{domain}", scan_id)
        print(json.dumps(findings, indent=2, default=str))

if __name__ == "__main__":
    test_email_security()
