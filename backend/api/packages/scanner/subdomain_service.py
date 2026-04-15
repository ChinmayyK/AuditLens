import json
import logging
import os
import re
import subprocess
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings()

logger = logging.getLogger(__name__)

AMASS_PATH = "/usr/local/bin/amass"
GOBUSTER_PATH = "gobuster"

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api",
    "dev", "staging", "test", "app", "portal",
    "dashboard", "login", "secure", "vpn",
    "remote", "blog", "shop", "store", "cdn",
    "static", "assets", "media", "upload",
    "download", "files", "docs", "support",
    "help", "status", "monitor", "metrics",
    "grafana", "jenkins", "gitlab", "jira",
    "confluence", "kibana", "elastic", "redis",
    "mysql", "postgres", "mongo", "db",
    "database", "backup", "s3", "storage",
    "vault", "consul", "k8s", "kubernetes",
    "docker", "registry", "ci", "cd", "git",
]


TAKEOVER_SIGNATURES = {
    "Github Pages": "There isn't a GitHub Pages site here.",
    "Heroku": "No such app",
    "AWS S3": "The specified bucket does not exist",
    "Fastly": "Fastly error: unknown domain",
    "Pantheon": "The mod_shield_error page",
    "Azure": "project not found",
    "Netlify": "Not Found - Request ID:",
    "Tumblr": "Whatever you were looking for doesn't currently exist at this address.",
    "Wordpress": "Do you want to register",
    "Ghost": "The thing you were looking for is no longer here",
    "Surge": "project not found",
    "Shopify": "Sorry, this shop is currently unavailable.",
    "Help_Scout": "No settings were found for this company:",
    "Kinsta": "No Site For Domain"
}

class SubdomainService:

    def enumerate(
        self,
        target_url: str,
        scan_id: str,
        on_progress,
        intensity: str = "standard",
    ) -> dict:
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path.split("/")[0]
        domain = domain.split(":")[0]

        on_progress(
            f"🌐 Enumerating subdomains for {domain}...",
            8,
            tool="subdomain_enum",
        )

        subdomains = set()

        amass_results = self._run_amass(domain, scan_id)
        subdomains.update(amass_results)

        ct_results = self._cert_transparency(domain)
        subdomains.update(ct_results)

        limit = {
            "quick": 20,
            "standard": 40,
            "deep": len(COMMON_SUBDOMAINS),
            "aggressive": len(COMMON_SUBDOMAINS),
        }.get(intensity, 40)

        dns_results = self._dns_bruteforce(domain, COMMON_SUBDOMAINS[:limit])
        subdomains.update(dns_results)

        live = []
        for sub in list(subdomains)[:50]:
            probed = self._probe_subdomain(sub)
            if probed:
                live.append(probed)

        on_progress(
            f"✅ Found {len(live)} live subdomains",
            13,
            tool="subdomain_enum",
        )

        findings = []
        for l in live:
            if l.get("takeover"):
                findings.append({
                    "scan_id": scan_id,
                    "vuln_type": "Subdomain Takeover",
                    "severity": "critical",
                    "url": l["url"],
                    "evidence": f"Response signature matched: '{l['takeover_service']}' unclaimed service.",
                    "description": f"The subdomain {l['subdomain']} points to an unclaimed {l['takeover_service']} service. An attacker can register this external service and take full control of the subdomain to serve malicious content or steal cookies.",
                    "attack_worked": True,
                    "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                    "tool_source": "subdomain_takeover",
                    "was_attempted": True,
                    "attack_name": f"Subdomain Takeover ({l['takeover_service']})",
                    "quick_fix": "Remove the dangling DNS/CNAME record that points to the unclaimed service, or claim the service yourself.",
                    "money_loss_min": 10000,
                    "money_loss_max": 250000
                })

        return {
            "domain": domain,
            "subdomains": live,
            "total_found": len(live),
            "findings": findings
        }

    def _run_amass(self, domain: str, scan_id: str) -> set:
        results = set()
        if not os.path.exists(AMASS_PATH):
            return results
        try:
            subprocess.run(
                [
                    AMASS_PATH,
                    "enum",
                    "-passive",
                    "-d",
                    domain,
                    "-timeout",
                    "30",
                    "-json",
                    f"/tmp/{scan_id}_amass.json",
                ],
                capture_output=True,
                text=True,
                timeout=45,
            )
            try:
                with open(f"/tmp/{scan_id}_amass.json", encoding="utf-8") as f:
                    for line in f:
                        try:
                            item = json.loads(line.strip())
                            name = item.get("name", "")
                            if name:
                                results.add(name)
                        except Exception:
                            pass
            except FileNotFoundError:
                pass
        except Exception as e:
            logger.debug(f"Amass failed: {e}")
        return results

    def _cert_transparency(self, domain: str) -> set:
        results = set()
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%.{domain}&output=json",
                timeout=10,
                verify=True,
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data[:200]:
                    name = entry.get("name_value", "")
                    for n in name.split("\n"):
                        n = n.strip().lstrip("*.")
                        if n.endswith(domain) and n != domain:
                            results.add(n)
        except Exception as e:
            logger.debug(f"CT lookup failed: {e}")
        return results

    def _dns_bruteforce(self, domain: str, wordlist: list) -> set:
        import socket

        results = set()
        for word in wordlist:
            fqdn = f"{word}.{domain}"
            try:
                socket.gethostbyname(fqdn)
                results.add(fqdn)
            except socket.gaierror:
                pass
        return results

    def _probe_subdomain(self, subdomain: str) -> dict | None:
        for scheme in ["https", "http"]:
            url = f"{scheme}://{subdomain}"
            try:
                resp = requests.get(
                    url,
                    timeout=5,
                    verify=False,
                    allow_redirects=True,
                    headers={
                        "User-Agent": "Mozilla/5.0 ShieldSentinel/1.0",
                    },
                )
                server = resp.headers.get("server", "")
                powered = resp.headers.get("x-powered-by", "")
                title = ""
                m = re.search(
                    r"<title[^>]*>([^<]+)</title>",
                    resp.text[:2000],
                    re.IGNORECASE,
                )
                if m:
                    title = m.group(1).strip()[:60]

                risk = "low"
                risk_reasons = []

                sensitive_keywords = [
                    "admin",
                    "jenkins",
                    "gitlab",
                    "jira",
                    "confluence",
                    "kibana",
                    "grafana",
                    "phpmyadmin",
                    "database",
                    "backup",
                    "staging",
                    "dev",
                    "test",
                ]
                for kw in sensitive_keywords:
                    if kw in subdomain.lower():
                        risk = "medium"
                        risk_reasons.append(f"Sensitive subdomain: {kw}")
                        break

                takeover_service = None
                for t_name, t_sig in TAKEOVER_SIGNATURES.items():
                    if t_sig in resp.text:
                        risk = "critical"
                        takeover_service = t_name
                        risk_reasons.append(f"Subdomain Takeover detected ({t_name})")
                        break

                return {
                    "subdomain": subdomain,
                    "url": url,
                    "status_code": resp.status_code,
                    "server": server,
                    "powered_by": powered,
                    "title": title,
                    "risk": risk,
                    "risk_reasons": risk_reasons,
                    "scheme": scheme,
                    "takeover": takeover_service is not None,
                    "takeover_service": takeover_service
                }
            except Exception:
                continue
        return None
