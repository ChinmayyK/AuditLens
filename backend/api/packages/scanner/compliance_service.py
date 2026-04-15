import json
import os
from pathlib import Path

COMPLIANCE_PATH = Path(__file__).resolve().parents[2] / \
    "data" / "compliance_map.json"

OWASP_CATEGORIES = {
    "A01": {
        "name": "Broken Access Control",
        "what_it_means":
            "Users can access data or functions "
            "they should not be able to reach.",
        "real_world_example":
            "A regular user changes their ID in "
            "the URL from 123 to 124 and sees "
            "someone else's medical records.",
        "business_impact":
            "Data breach, regulatory fines, "
            "complete system takeover.",
        "quick_fix":
            "Always verify the logged-in user owns "
            "the resource before showing it.",
    },
    "A02": {
        "name": "Cryptographic Failures",
        "what_it_means":
            "Sensitive data stored or transmitted "
            "without proper encryption.",
        "real_world_example":
            "Passwords stored as plain text — if "
            "the database is hacked, all passwords "
            "are instantly readable.",
        "business_impact":
            "Mass credential theft, regulatory "
            "fines, permanent reputation damage.",
        "quick_fix":
            "Use bcrypt for passwords, HTTPS "
            "everywhere, AES-256 for stored data.",
    },
    "A03": {
        "name": "Injection",
        "what_it_means":
            "Attacker input is executed as code — "
            "SQL commands, shell commands, scripts.",
        "real_world_example":
            "Typing ' OR 1=1-- in a login field "
            "bypasses authentication entirely.",
        "business_impact":
            "Complete database dump, server "
            "takeover, data destruction.",
        "quick_fix":
            "Never concatenate user input into "
            "queries — use parameterized statements.",
    },
    "A04": {
        "name": "Insecure Design",
        "what_it_means":
            "Security was not considered during "
            "design — flaws baked into architecture.",
        "real_world_example":
            "Password reset emails the new password "
            "in plaintext instead of a secure link.",
        "business_impact":
            "Architectural flaws cannot be patched "
            "— they require full redesign.",
        "quick_fix":
            "Threat model during design phase. "
            "Apply security patterns before coding.",
    },
    "A05": {
        "name": "Security Misconfiguration",
        "what_it_means":
            "Default settings, exposed admin pages, "
            "verbose errors, unnecessary features.",
        "real_world_example":
            "Admin panel at /admin is publicly "
            "accessible with default credentials.",
        "business_impact":
            "Easy entry point — most common "
            "vulnerability in real breaches.",
        "quick_fix":
            "Harden all defaults, disable debug "
            "in production, restrict admin by IP.",
    },
    "A06": {
        "name": "Vulnerable Components",
        "what_it_means":
            "Using libraries with known publicly "
            "disclosed exploits.",
        "real_world_example":
            "Using jQuery 1.x which has a known "
            "XSS vulnerability already being "
            "actively exploited.",
        "business_impact":
            "Pre-made exploits exist — any attacker "
            "can exploit without skill.",
        "quick_fix":
            "Run npm audit, pip-audit, Trivy "
            "regularly and update dependencies.",
    },
    "A07": {
        "name": "Identification Failures",
        "what_it_means":
            "Weak authentication — no MFA, broken "
            "session management, default passwords.",
        "real_world_example":
            "Session token never expires, or default "
            "admin:admin credentials still work.",
        "business_impact":
            "Account takeover, impersonation, "
            "access to all user data.",
        "quick_fix":
            "Enforce strong passwords, MFA, expire "
            "sessions, use secure random tokens.",
    },
    "A08": {
        "name": "Software Integrity Failures",
        "what_it_means":
            "Untrusted code in updates or plugins "
            "without verification.",
        "real_world_example":
            "Auto-updating from an unverified CDN "
            "that was compromised (supply chain).",
        "business_impact":
            "Attacker code runs with full app "
            "privileges on every server.",
        "quick_fix":
            "Verify checksums of dependencies, "
            "use trusted registries, lock versions.",
    },
    "A09": {
        "name": "Logging Failures",
        "what_it_means":
            "Security events not logged — breaches "
            "go undetected for months.",
        "real_world_example":
            "1000 failed login attempts with no "
            "alert — attacker brute-forced undetected.",
        "business_impact":
            "Cannot detect breaches, no forensic "
            "evidence, regulatory non-compliance.",
        "quick_fix":
            "Log all auth events and admin actions. "
            "Set up alerts for anomalies.",
    },
    "A10": {
        "name": "Server-Side Request Forgery",
        "what_it_means":
            "Server makes HTTP requests controlled "
            "by attacker — reaches internal systems.",
        "real_world_example":
            "URL parameter accepts "
            "http://internal-server/admin — attacker "
            "reaches your private network.",
        "business_impact":
            "Internal network access, cloud "
            "metadata theft, firewall bypass.",
        "quick_fix":
            "Validate all URLs against allowlist. "
            "Block internal IP ranges.",
    },
}


def calculate_compliance(
    scan_id: str, findings: list
) -> dict:
    try:
        with open(COMPLIANCE_PATH) as f:
            compliance_map = json.load(f)
    except Exception:
        compliance_map = {}

    # Only count severe findings
    severe_types = {
        f.get("vuln_type", "")
        for f in findings
        if f.get("attack_worked") and
        f.get("severity") in ["critical", "high"]
    }

    # OWASP Top 10 scoring
    failing_owasp = set()
    failing_findings_per_owasp: dict = {}

    for vt in severe_types:
        mapping = compliance_map.get(vt, {})
        owasp = mapping.get("owasp", "")
        if owasp:
            code = owasp.split(":")[0]  # "A03"
            failing_owasp.add(code)
            if code not in failing_findings_per_owasp:
                failing_findings_per_owasp[code] = []
            failing_findings_per_owasp[code].append(vt)

    passing_owasp = [
        k for k in OWASP_CATEGORIES
        if k not in failing_owasp
    ]
    owasp_score = round(
        len(passing_owasp) / 10 * 100
    )

    owasp_breakdown = []
    for code, info in OWASP_CATEGORIES.items():
        failing = failing_findings_per_owasp.get(
            code, []
        )
        owasp_breakdown.append({
            "code":             code,
            "name":             info["name"],
            "status":
                "FAIL" if code in failing_owasp
                else "PASS",
            "what_it_means":    info["what_it_means"],
            "real_world_example":
                info["real_world_example"],
            "business_impact":  info["business_impact"],
            "quick_fix":        info["quick_fix"],
            "failing_findings": failing,
        })

    # PCI-DSS
    pci_violations: set = set()
    for vt in severe_types:
        m = compliance_map.get(vt, {})
        pci_violations.update(m.get("pci_dss", []))
    pci_score = max(0, 100 - len(pci_violations) * 6)

    pci_gaps = [
        {
            "requirement": req,
            "failing_because": [
                vt for vt in severe_types
                if req in compliance_map.get(
                    vt, {}
                ).get("pci_dss", [])
            ],
        }
        for req in pci_violations
    ]

    # HIPAA
    hipaa_violations: set = set()
    for vt in severe_types:
        m = compliance_map.get(vt, {})
        hipaa_violations.update(m.get("hipaa", []))
    hipaa_score = max(
        0, 100 - len(hipaa_violations) * 8
    )

    hipaa_gaps = [
        {
            "requirement": req,
            "failing_because": [
                vt for vt in severe_types
                if req in compliance_map.get(
                    vt, {}
                ).get("hipaa", [])
            ],
        }
        for req in hipaa_violations
    ]

    # GDPR
    gdpr_violations: set = set()
    for vt in severe_types:
        m = compliance_map.get(vt, {})
        gdpr_violations.update(m.get("gdpr", []))
    gdpr_score = max(
        0, 100 - len(gdpr_violations) * 7
    )

    gdpr_gaps = [
        {
            "requirement": req,
            "failing_because": [
                vt for vt in severe_types
                if req in compliance_map.get(
                    vt, {}
                ).get("gdpr", [])
            ],
        }
        for req in gdpr_violations
    ]

    return {
        "scores": {
            "owasp":   owasp_score,
            "pci_dss": pci_score,
            "hipaa":   hipaa_score,
            "gdpr":    gdpr_score,
        },
        "owasp_breakdown": owasp_breakdown,
        "pci_dss_gaps":    pci_gaps,
        "hipaa_gaps":      hipaa_gaps,
        "gdpr_gaps":       gdpr_gaps,
    }
