import dns.resolver
from urllib.parse import urlparse
import logging
import uuid

logger = logging.getLogger(__name__)

class EmailSecurityService:
    def __init__(self):
        self.resolver = dns.resolver.Resolver(configure=True)
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def get_domain(self, target_url: str) -> str:
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path
        if ":" in domain:
            domain = domain.split(":")[0]
        return domain

    def scan(self, target_url: str, scan_id: str) -> list:
        domain = self.get_domain(target_url)
        findings = []
        
        # 1. Check SPF
        spf_findings = self._check_spf(domain, scan_id)
        findings.extend(spf_findings)
        
        # 2. Check DMARC
        dmarc_findings = self._check_dmarc(domain, scan_id)
        findings.extend(dmarc_findings)
        
        return findings

    def _check_spf(self, domain: str, scan_id: str) -> list:
        findings = []
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            spf_records = [str(rdata) for rdata in answers if "v=spf1" in str(rdata)]
            
            if not spf_records:
                findings.append({
                    "scan_id": uuid.UUID(scan_id),
                    "vuln_type": "Email Security: Missing SPF Record",
                    "title": "Missing SPF Record",
                    "severity": "high",
                    "description": f"No SPF record found for {domain}. This allows anyone to send spoofed emails from this domain.",
                    "remediation": "Create a TXT record for the domain with SPF policy (e.g., 'v=spf1 include:_spf.google.com ~all').",
                    "attack_worked": True,
                    "was_attempted": True,
                    "url": domain,
                })
            else:
                for record in spf_records:
                    if "~all" in record or "?all" in record:
                        findings.append({
                            "scan_id": uuid.UUID(scan_id),
                            "vuln_type": "Email Security: Weak SPF Policy",
                            "title": "Weak SPF Policy (Softfail)",
                            "severity": "low",
                            "description": f"The SPF record for {domain} uses a 'softfail' (~all) or 'neutral' (?all) policy. This is better than nothing but less secure than '-all' (fail).",
                            "remediation": "Update the SPF record to use '-all' once you have verified all authorized senders.",
                            "attack_worked": False,
                            "was_attempted": True,
                            "url": domain,
                            "evidence": record
                        })
                    elif "-all" in record:
                        pass # Secure
                    else:
                        # Other SPF found, but maybe incomplete or weird
                        pass

        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
             findings.append({
                "scan_id": uuid.UUID(scan_id),
                "vuln_type": "Email Security: Missing SPF Record",
                "title": "Missing SPF Record",
                "severity": "high",
                "description": f"Could not find any DNS records for {domain} (SPF check failed).",
                "remediation": "Ensure the domain has valid DNS records and set up SPF.",
                "attack_worked": True,
                "was_attempted": True,
                "url": domain,
            })
        except Exception as e:
            logger.error(f"SPF check error for {domain}: {e}")
            
        return findings

    def _check_dmarc(self, domain: str, scan_id: str) -> list:
        findings = []
        dmarc_domain = f"_dmarc.{domain}"
        try:
            answers = self.resolver.resolve(dmarc_domain, 'TXT')
            dmarc_records = [str(rdata) for rdata in answers if "v=DMARC1" in str(rdata)]
            
            if not dmarc_records:
                findings.append({
                    "scan_id": uuid.UUID(scan_id),
                    "vuln_type": "Email Security: Missing DMARC Record",
                    "title": "Missing DMARC Record",
                    "severity": "high",
                    "description": f"No DMARC record found for {domain}. DMARC is essential for instructing mail servers how to handle emails that fail SPF/DKIM.",
                    "remediation": "Create a TXT record for _dmarc.{domain} with a DMARC policy (e.g., 'v=DMARC1; p=quarantine;').",
                    "attack_worked": True,
                    "was_attempted": True,
                    "url": domain,
                })
            else:
                for record in dmarc_records:
                    if "p=none" in record:
                        findings.append({
                            "scan_id": uuid.UUID(scan_id),
                            "vuln_type": "Email Security: Weak DMARC Policy",
                            "title": "Weak DMARC Policy (p=none)",
                            "severity": "medium",
                            "description": f"The DMARC record for {domain} uses 'p=none', which is only for monitoring and does not provide protection against spoofing.",
                            "remediation": "Update the DMARC policy to 'p=quarantine' or 'p=reject'.",
                            "attack_worked": False,
                            "was_attempted": True,
                            "url": domain,
                            "evidence": record
                        })
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            findings.append({
                "scan_id": uuid.UUID(scan_id),
                "vuln_type": "Email Security: Missing DMARC Record",
                "title": "Missing DMARC Record",
                "severity": "high",
                "description": f"No DMARC record found for {domain}.",
                "remediation": "Set up a DMARC record at _dmarc.{domain}.",
                "attack_worked": True,
                "was_attempted": True,
                "url": domain,
            })
        except Exception as e:
            logger.error(f"DMARC check error for {domain}: {e}")
            
        return findings
