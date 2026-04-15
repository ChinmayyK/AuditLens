import logging
import re

import requests
import urllib3

urllib3.disable_warnings()

logger = logging.getLogger(__name__)

FRAMEWORK_CVES: dict = {
    "wordpress": [
        {
            "id": "CVE-2023-2745",
            "title": "WordPress Core Directory Traversal",
            "version": "< 6.2.1",
            "cvss": 7.2,
            "type": "Directory Traversal",
        },
    ],
    "drupal": [
        {
            "id": "CVE-2018-7600",
            "title": "Drupalgeddon2 RCE",
            "version": "< 7.58 / 8.x < 8.3.9",
            "cvss": 9.8,
            "type": "Remote Code Execution",
        },
    ],
    "joomla": [
        {
            "id": "CVE-2023-23752",
            "title": "Joomla Improper Access Check",
            "version": "< 4.2.8",
            "cvss": 5.3,
            "type": "Information Disclosure",
        },
    ],
    "laravel": [
        {
            "id": "CVE-2021-3129",
            "title": "Laravel Debug RCE",
            "version": "Ignition < 2.5.2 with debug on",
            "cvss": 9.8,
            "type": "Remote Code Execution",
        },
    ],
    "jquery": [
        {
            "id": "CVE-2020-11022",
            "title": "jQuery XSS",
            "version": "< 3.5.0",
            "cvss": 6.1,
            "type": "Cross-Site Scripting",
        },
    ],
    "bootstrap": [],
    "react": [],
    "angular": [],
    "vue": [],
    "express": [
        {
            "id": "CVE-2022-24999",
            "title": "qs prototype pollution",
            "version": "qs < 6.10.3",
            "cvss": 7.5,
            "type": "Prototype Pollution",
        },
    ],
    "nginx": [
        {
            "id": "CVE-2021-23017",
            "title": "Nginx DNS resolver overflow",
            "version": "< 1.21.0",
            "cvss": 7.7,
            "type": "Buffer Overflow",
        },
    ],
    "apache": [
        {
            "id": "CVE-2021-41773",
            "title": "Apache Path Traversal",
            "version": "2.4.49",
            "cvss": 7.5,
            "type": "Path Traversal",
        },
        {
            "id": "CVE-2021-42013",
            "title": "Apache Path Traversal/RCE",
            "version": "2.4.49-2.4.50",
            "cvss": 9.8,
            "type": "Remote Code Execution",
        },
    ],
    "php": [
        {
            "id": "CVE-2024-4577",
            "title": "PHP CGI arg injection",
            "version": "< 8.1.29, 8.2.20, 8.3.8",
            "cvss": 9.8,
            "type": "Remote Code Execution",
        },
    ],
    "tomcat": [
        {
            "id": "CVE-2020-1938",
            "title": "Apache Ghostcat",
            "version": "< 9.0.31",
            "cvss": 9.8,
            "type": "File Read/RCE",
        },
    ],
}


class TechDeepDiveService:
    def analyze(self, target_url: str, tech_fingerprint: dict) -> dict:
        technologies = tech_fingerprint.get("technologies", [])
        server = tech_fingerprint.get("server", "") or ""
        powered = tech_fingerprint.get("powered_by", "") or ""

        all_techs = set()
        for t in technologies:
            all_techs.add(t.lower())
        for part in (server + " " + powered).lower().split():
            all_techs.add(part)

        matched_cves = []
        affected_tech = []

        for tech, cves in FRAMEWORK_CVES.items():
            if any(tech in t for t in all_techs):
                for cve in cves:
                    matched_cves.append(
                        {
                            **cve,
                            "technology": tech,
                            "check_cmd": f"Check if {tech} version is {cve['version']}",
                        }
                    )
                if cves:
                    affected_tech.append(tech)

        versions = self._extract_versions(server, powered, technologies)
        headers_analysis = self._check_security_headers(target_url)
        third_party = self._detect_third_party(tech_fingerprint)

        return {
            "technologies": list(all_techs),
            "versions": versions,
            "known_cves": matched_cves,
            "affected_frameworks": affected_tech,
            "headers_analysis": headers_analysis,
            "third_party_services": third_party,
            "attack_surface_notes": self._generate_notes(all_techs, headers_analysis),
        }

    def _extract_versions(
        self,
        server: str,
        powered_by: str,
        technologies: list,
    ) -> dict:
        versions = {}
        sources = [server, powered_by] + technologies

        patterns = {
            "PHP": r"PHP/([\d.]+)",
            "Apache": r"Apache/([\d.]+)",
            "Nginx": r"nginx/([\d.]+)",
            "OpenSSL": r"OpenSSL/([\w.]+)",
            "Python": r"Python/([\d.]+)",
            "Ruby": r"Ruby/([\d.]+)",
        }

        combined = " ".join(str(s) for s in sources)
        for name, pattern in patterns.items():
            m = re.search(pattern, combined, re.IGNORECASE)
            if m:
                versions[name] = m.group(1)

        return versions

    def _check_security_headers(self, target_url: str) -> dict:
        try:
            resp = requests.get(
                target_url,
                timeout=8,
                verify=False,
                allow_redirects=True,
            )
            headers = {k.lower(): v for k, v in resp.headers.items()}

            checks = {
                "hsts": {
                    "present": "strict-transport-security" in headers,
                    "value": headers.get("strict-transport-security"),
                    "recommendation": "max-age=31536000; includeSubDomains",
                },
                "csp": {
                    "present": "content-security-policy" in headers,
                    "value": headers.get("content-security-policy"),
                    "recommendation": "default-src 'self'; script-src 'self'",
                },
                "x_frame": {
                    "present": "x-frame-options" in headers,
                    "value": headers.get("x-frame-options"),
                    "recommendation": "SAMEORIGIN",
                },
                "x_content_type": {
                    "present": "x-content-type-options" in headers,
                    "value": headers.get("x-content-type-options"),
                    "recommendation": "nosniff",
                },
                "referrer_policy": {
                    "present": "referrer-policy" in headers,
                    "value": headers.get("referrer-policy"),
                    "recommendation": "strict-origin-when-cross-origin",
                },
                "permissions_policy": {
                    "present": "permissions-policy" in headers,
                    "value": headers.get("permissions-policy"),
                    "recommendation": "camera=(), microphone=(), geolocation=()",
                },
            }

            score = sum(1 for v in checks.values() if v["present"])
            grade = (
                "A"
                if score >= 5
                else "B"
                if score == 4
                else "C"
                if score == 3
                else "D"
                if score == 2
                else "F"
            )

            return {
                "checks": checks,
                "score": score,
                "max_score": 6,
                "grade": grade,
                "server_header": headers.get("server", ""),
            }
        except Exception:
            return {
                "checks": {},
                "score": 0,
                "max_score": 6,
                "grade": "F",
            }

    def _detect_third_party(self, fingerprint: dict) -> list:
        services = []
        techs = " ".join(t.lower() for t in fingerprint.get("technologies", []))

        third_party = {
            "cloudflare": "CDN/WAF: Cloudflare",
            "akamai": "CDN: Akamai",
            "aws": "Cloud: Amazon AWS",
            "google": "Cloud: Google Cloud",
            "azure": "Cloud: Microsoft Azure",
            "fastly": "CDN: Fastly",
            "stripe": "Payment: Stripe",
            "paypal": "Payment: PayPal",
            "analytics": "Tracking: Google Analytics",
            "facebook": "Tracking: Facebook Pixel",
            "hotjar": "Tracking: Hotjar",
            "recaptcha": "Security: reCAPTCHA",
            "intercom": "Chat: Intercom",
            "zendesk": "Support: Zendesk",
            "hubspot": "CRM: HubSpot",
        }

        for key, label in third_party.items():
            if key in techs:
                services.append(
                    {
                        "name": label,
                        "key": key,
                        "note": "Third-party service with access to your traffic/data",
                    }
                )

        return services

    def _generate_notes(self, techs: set, headers: dict) -> list:
        notes = []

        if "php" in techs:
            notes.append(
                "PHP detected — check for file inclusion vulnerabilities and ensure error reporting is disabled in production"
            )
        if "wordpress" in techs:
            notes.append(
                "WordPress detected — keep core, plugins, and themes updated. Check /wp-admin and xmlrpc.php exposure"
            )
        if not headers.get("checks", {}).get("csp", {}).get("present"):
            notes.append(
                "No Content Security Policy — XSS attacks are significantly more impactful without CSP"
            )
        if "jquery" in techs:
            notes.append(
                "jQuery detected — ensure version is 3.5.0+ to avoid known XSS vulnerabilities"
            )

        return notes
