#!/usr/bin/env python3
"""
Run: docker compose -f infra/compose/docker-compose.yml --profile seed run seed
Creates a complete demo scan for showcasing.
"""
import sys
import uuid
from datetime import datetime, timedelta

sys.path.insert(0, "/app")

from models.base import SessionLocal, engine, Base
from models.user import User
from models.scan import (
    Scan, Finding, AttackSurface, ComplianceResult,
)

Base.metadata.create_all(bind=engine)

DEMO_USER_EMAIL = "demo@shieldsentinel.io"
DEMO_SCAN_ID = "00000000-0000-0000-0000-000000000001"

DEMO_FINDINGS = [
    {
        "vuln_type":   "SQL Injection",
        "severity":    "critical",
        "url":
            "http://testphp.vulnweb.com"
            "/listproducts.php",
        "parameter":    "cat",
        "evidence":
            "Parameter 'cat' injectable. "
            "Type: Boolean-based blind. "
            "Database: MySQL",
        "description":
            "SQL injection confirmed in parameter "
            "'cat'. Attacker can read/modify/delete "
            "the entire database.",
        "attack_worked": True,
        "was_attempted": True,
        "owasp_category":
            "A03:2021 - Injection",
        "tool_source":   "sqlmap",
        "cvss_score":    9.8,
        "cwe_id":        "CWE-89",
        "money_loss_min": 100000,
        "money_loss_max": 10000000,
        "attack_name":
            "SQL Injection (Boolean Blind)",
        "layman_explanation":
            "SQL injection is like someone "
            "filling out a form and writing "
            "database commands instead of their "
            "name. The server obeys them — "
            "handing over all data or granting "
            "full access.",
        "ai_fix": {
            "layman_explanation":
                "SQL injection is like someone "
                "filling out a form and writing "
                "database commands instead of "
                "their name.",
            "what_is_happening":
                "User input is concatenated "
                "directly into a SQL query string.",
            "attack_examples": [
                {
                    "name": "Auth Bypass",
                    "payload": "admin'--",
                    "explanation":
                        "Comments out password check",
                    "impact": "Login without password",
                },
                {
                    "name": "Data Dump",
                    "payload":
                        "' UNION SELECT "
                        "user,pass FROM users--",
                    "explanation":
                        "Retrieves all credentials",
                    "impact": "Full database exposure",
                },
            ],
            "defense_examples": [
                {
                    "method":
                        "Parameterized Queries",
                    "code_before":
                        "query = 'SELECT * FROM "
                        "products WHERE cat=' + cat",
                    "code_after":
                        "query = 'SELECT * FROM "
                        "products WHERE cat=?'\n"
                        "cursor.execute(query, [cat])",
                    "language": "python",
                    "explanation":
                        "Input passed as data, never "
                        "interpreted as SQL",
                },
            ],
            "services_to_use": [
                "SQLAlchemy ORM",
                "Parameterized queries",
            ],
            "key_terms": [
                "Parameterized Query",
                "Prepared Statement",
                "ORM",
            ],
            "ai_suggestion":
                "Use parameterized queries — never "
                "concatenate user input into SQL",
            "cvss_score":     9.8,
            "effort_minutes": 20,
            "confidence":     95,
            "ide_prompt":
                "Fix SQL injection in "
                "listproducts.php. The 'cat' "
                "parameter is directly concatenated "
                "into a SQL query. Replace with "
                "prepared statements.",
            "breach_examples": [
                {
                    "company": "Equifax (2017)",
                    "loss": "$575M settlement",
                    "detail":
                        "SQL injection contributed "
                        "to 147M record breach",
                },
            ],
            "money_loss_min": 100000,
            "money_loss_max": 10000000,
        },
        "waf_rule": {
            "modsecurity":
                'SecRule ARGS "@detectSQLi" '
                '"id:10001,phase:2,deny,'
                'status:403,log,'
                "msg:'ShieldSentinel-SQLi'\"",
            "cloudflare":
                '(http.request.uri.query '
                'contains "\'")',
            "nginx_config":
                "if ($query_string ~* "
                r'"(union|select|insert)" ) {'
                "\n    return 403;\n}",
            "description":
                "Blocks SQL injection attempts",
        },
    },
    {
        "vuln_type":
            "Cross Site Scripting (Reflected)",
        "severity":    "high",
        "url":
            "http://testphp.vulnweb.com"
            "/search.php",
        "parameter":    "test",
        "evidence":
            "Payload reflected unencoded: "
            "<script>alert(1)</script>",
        "description":
            "Reflected XSS in 'test' parameter. "
            "Script runs in victim's browser.",
        "attack_worked": True,
        "was_attempted": True,
        "owasp_category":
            "A03:2021 - Injection",
        "tool_source":   "xsstrike",
        "cvss_score":    7.4,
        "cwe_id":        "CWE-79",
        "money_loss_min": 10000,
        "money_loss_max": 2000000,
        "attack_name":    "Reflected XSS",
        "layman_explanation":
            "XSS is like someone slipping a "
            "forged note into your mailbox that "
            "calls all your contacts pretending "
            "to be you.",
        "ai_fix": {
            "ai_suggestion":
                "Use output encoding — "
                "htmlspecialchars() before printing "
                "user input",
            "confidence": 92,
            "effort_minutes": 10,
        },
    },
    {
        "vuln_type":   "Hardcoded Secret",
        "severity":    "critical",
        "file_path":   "config/database.php",
        "line_number": 12,
        "evidence":
            "Rule: generic-api-key | "
            "Match: sk-ab****...[REDACTED]",
        "description":
            "Hardcoded API key found in source. "
            "Anyone with code access can use it.",
        "attack_worked":  True,
        "was_attempted":  True,
        "owasp_category":
            "A02:2021 - Cryptographic Failures",
        "tool_source":   "gitleaks",
        "cvss_score":    9.1,
        "cwe_id":        "CWE-798",
        "money_loss_min": 50000,
        "money_loss_max": 5000000,
        "attack_name":   "Exposed Credential",
        "quick_fix":
            "os.getenv('API_KEY') — move to env vars",
    },
    {
        "vuln_type":
            "Missing Content-Security-Policy",
        "severity":    "medium",
        "url":
            "http://testphp.vulnweb.com",
        "evidence":
            "Header 'content-security-policy' "
            "absent",
        "description":
            "No CSP set. XSS attacks are "
            "significantly more impactful.",
        "attack_worked":  True,
        "was_attempted":  True,
        "owasp_category":
            "A05:2021 - Security Misconfiguration",
        "tool_source":   "native_header_check",
        "money_loss_min": 5000,
        "money_loss_max": 1000000,
        "attack_name":
            "XSS Amplification",
        "quick_fix":
            "Content-Security-Policy: "
            "default-src 'self'",
    },
    {
        "vuln_type":   "Missing HSTS Header",
        "severity":    "medium",
        "url":
            "http://testphp.vulnweb.com",
        "evidence":
            "strict-transport-security header "
            "not present",
        "description":
            "HSTS not set. SSL stripping attack "
            "possible.",
        "attack_worked":  True,
        "was_attempted":  True,
        "owasp_category":
            "A02:2021 - Cryptographic Failures",
        "tool_source":   "ssl_audit",
        "money_loss_min": 50000,
        "money_loss_max": 2000000,
        "attack_name":   "SSL Stripping",
        "quick_fix":
            "Strict-Transport-Security: "
            "max-age=31536000",
    },
    {
        "vuln_type":   "Missing Rate Limiting",
        "severity":    "medium",
        "url":
            "http://testphp.vulnweb.com",
        "evidence":
            "30/30 requests succeeded in 4.2s "
            "(7 req/s). No HTTP 429 received.",
        "description":
            "No rate limiting. Brute-force "
            "attacks possible.",
        "attack_worked":  True,
        "was_attempted":  True,
        "owasp_category":
            "A07:2021 - Identification Failures",
        "tool_source":   "stress_test",
        "money_loss_min": 10000,
        "money_loss_max": 1000000,
        "attack_name":
            "Brute Force / Rate Limit Bypass",
        "quick_fix":
            "Implement rate limiting: "
            "max 10 req/min per IP",
    },
    {
        "vuln_type":
            "Remote OS Command Injection",
        "severity":    "info",
        "url":
            "http://testphp.vulnweb.com",
        "evidence":
            "Command injection payloads blocked",
        "description":
            "No command injection found — "
            "system appears protected.",
        "attack_worked": False,
        "was_attempted": True,
        "tool_source":   "commix",
        "owasp_category":
            "A03:2021 - Injection",
    },
    {
        "vuln_type":
            "Server Side Request Forgery",
        "severity":    "info",
        "url":
            "http://testphp.vulnweb.com",
        "evidence":
            "SSRF payloads blocked",
        "description":
            "No SSRF vulnerabilities found.",
        "attack_worked": False,
        "was_attempted": True,
        "tool_source":   "native_ssrf",
        "owasp_category":
            "A10:2021 - SSRF",
    },
    {
        "vuln_type":   "Path Traversal",
        "severity":    "info",
        "url":
            "http://testphp.vulnweb.com",
        "evidence":
            "Traversal payloads blocked",
        "description":
            "No path traversal vulnerabilities.",
        "attack_worked": False,
        "was_attempted": True,
        "tool_source":   "native_path_traversal",
        "owasp_category":
            "A01:2021 - Broken Access Control",
    },
]

DEMO_NODES = [
    {
        "id": "/", "label": "/",
        "full_url":
            "http://testphp.vulnweb.com",
        "risk": "safe", "vuln_count": 0,
        "vulns": [],
    },
    {
        "id": "/listproducts.php",
        "label": "/listproducts.php",
        "full_url":
            "http://testphp.vulnweb.com"
            "/listproducts.php",
        "risk": "critical", "vuln_count": 1,
        "vulns": ["SQL Injection"],
    },
    {
        "id": "/search.php",
        "label": "/search.php",
        "full_url":
            "http://testphp.vulnweb.com"
            "/search.php",
        "risk": "high", "vuln_count": 1,
        "vulns": ["XSS"],
    },
    {
        "id": "/login.php",
        "label": "/login.php",
        "full_url":
            "http://testphp.vulnweb.com"
            "/login.php",
        "risk": "safe", "vuln_count": 0,
        "vulns": [],
    },
    {
        "id": "/categories.php",
        "label": "/categories.php",
        "full_url":
            "http://testphp.vulnweb.com"
            "/categories.php",
        "risk": "medium", "vuln_count": 1,
        "vulns": ["CSRF"],
    },
]

DEMO_EDGES = [
    {"source": "/",
     "target": "/listproducts.php"},
    {"source": "/", "target": "/search.php"},
    {"source": "/", "target": "/login.php"},
    {"source": "/",
     "target": "/categories.php"},
]


def seed():
    db = SessionLocal()
    try:
        user = db.query(User).filter(
            User.email == DEMO_USER_EMAIL
        ).first()
        if not user:
            from core.security import hash_password
            user = User(
                email=DEMO_USER_EMAIL,
                full_name="Demo User",
                google_id="demo_google_id",
                hashed_password=hash_password(
                    "Demo1234!"
                ),
                is_active=True,
                is_verified=True,
                plan="pro",
            )
            db.add(user)
            db.commit()
            db.refresh(user)
            print(f"Created demo user: "
                  f"{DEMO_USER_EMAIL}")
        else:
            print(f"Using existing user: "
                  f"{DEMO_USER_EMAIL}")

        existing = db.query(Scan).filter(
            Scan.id == uuid.UUID(DEMO_SCAN_ID)
        ).first()
        if existing:
            db.query(Finding).filter(
                Finding.scan_id ==
                uuid.UUID(DEMO_SCAN_ID)
            ).delete()
            db.query(AttackSurface).filter(
                AttackSurface.scan_id ==
                uuid.UUID(DEMO_SCAN_ID)
            ).delete()
            db.query(ComplianceResult).filter(
                ComplianceResult.scan_id ==
                uuid.UUID(DEMO_SCAN_ID)
            ).delete()
            db.delete(existing)
            db.commit()

        scan = Scan(
            id=uuid.UUID(DEMO_SCAN_ID),
            user_id=user.id,
            scan_type="url",
            target="http://testphp.vulnweb.com",
            intensity="standard",
            ownership_confirmed=True,
            estimated_asset_value=50000,
            status="complete",
            risk_score=42,
            risk_grade="D",
            progress_pct=100,
            current_phase="Complete",
            created_at=datetime.utcnow() -
                        timedelta(hours=2),
            started_at=datetime.utcnow() -
                        timedelta(hours=2),
            completed_at=datetime.utcnow() -
                          timedelta(hours=1,
                                    minutes=45),
            duration_seconds=917,
            open_ports=[
                {"port": "80",   "service": "http",
                 "version": "nginx 1.19"},
                {"port": "443",  "service": "https",
                 "version": ""},
                {"port": "3306", "service": "mysql",
                 "version": "MySQL 8.0"},
            ],
            os_guess="Linux Ubuntu 20.04",
            tech_stack={
                "technologies": [
                    "PHP", "Nginx", "MySQL",
                    "Bootstrap CSS",
                ],
                "server": "nginx/1.19.0",
                "powered_by": "PHP/7.4",
            },
            cdn_detected=False,
            waf_detected=False,
        )
        db.add(scan)
        db.commit()

        for f in DEMO_FINDINGS:
            finding = Finding(
                scan_id=uuid.UUID(DEMO_SCAN_ID),
                **{k: v for k, v in f.items()},
            )
            db.add(finding)
        db.commit()

        surface = AttackSurface(
            scan_id=uuid.UUID(DEMO_SCAN_ID),
            nodes=DEMO_NODES,
            edges=DEMO_EDGES,
            discovered_urls=[
                "http://testphp.vulnweb.com/",
                "http://testphp.vulnweb.com"
                "/listproducts.php?cat=1",
                "http://testphp.vulnweb.com"
                "/search.php",
                "http://testphp.vulnweb.com"
                "/login.php",
            ],
            total_requests_sent=347,
        )
        db.add(surface)
        db.commit()

        print("\nDemo data seeded successfully!")
        print(f"   Scan ID: {DEMO_SCAN_ID}")
        print(f"   Risk Score: 42/100 (D)")
        print(
            f"   Findings: "
            f"{len(DEMO_FINDINGS)} total"
        )
        print(
            f"\n   Login credentials:"
        )
        print(f"   Email: {DEMO_USER_EMAIL}")
        print(f"   Password: Demo1234!")
        print(
            f"\n   View at: "
            f"http://localhost:9998/scan/"
            f"{DEMO_SCAN_ID}"
        )

    except Exception as e:
        db.rollback()
        print(f"Seed failed: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed()
