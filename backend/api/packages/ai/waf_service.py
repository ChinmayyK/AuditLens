import logging
logger = logging.getLogger(__name__)

MODSEC_TEMPLATES = {
    "SQL Injection":
        'SecRule ARGS "@detectSQLi" '
        '"id:10001,phase:2,deny,status:403,'
        'log,msg:\'ShieldSentinel-SQLi-Blocked\','
        'tag:\'OWASP_CRS/WEB_ATTACK/SQL_INJECTION\'"',
    "Cross Site Scripting (Reflected)":
        'SecRule ARGS "@detectXSS" '
        '"id:10002,phase:2,deny,status:403,'
        'log,msg:\'ShieldSentinel-XSS-Blocked\','
        'tag:\'OWASP_CRS/WEB_ATTACK/XSS\'"',
    "Path Traversal":
        r'SecRule ARGS "@rx '
        r'(?i)(\.\./|\.\.\\|%2e%2e%2f|%252e%252e)" '
        '"id:10003,phase:2,deny,status:403,'
        'log,msg:\'ShieldSentinel-Traversal-Blocked\'"',
    "Server Side Request Forgery":
        'SecRule ARGS "@rx '
        r'(?i)(localhost|127\.0\.0\.1|169\.254\.'
        r'|10\.|192\.168\.)" '
        '"id:10004,phase:2,deny,status:403,'
        'log,msg:\'ShieldSentinel-SSRF-Blocked\'"',
    "Remote OS Command Injection":
        r'SecRule ARGS "@rx (?i)(;|\||`|\$\('
        r'|&&|\|\|)\s*(ls|cat|id|whoami|wget|curl|'
        r'bash|sh|python|perl|ruby)" '
        '"id:10005,phase:2,deny,status:403,'
        'log,msg:\'ShieldSentinel-CMDi-Blocked\'"',
    "Cross-Site Request Forgery":
        'SecRule REQUEST_METHOD "POST" '
        '"chain,id:10006,phase:2,deny,status:403,'
        'log,msg:\'ShieldSentinel-CSRF-Blocked\'"\n'
        'SecRule !REQUEST_HEADERS:Referer "@pm '
        'yourdomain.com"',
    "Missing Rate Limiting":
        'SecAction '
        '"id:10007,phase:1,nolog,pass,'
        'setvar:ip.request_count=+1,'
        'expirevar:ip.request_count=60"\n'
        'SecRule IP:REQUEST_COUNT "@gt 60" '
        '"id:10008,phase:1,deny,status:429,'
        'log,msg:\'ShieldSentinel-RateLimit\'"',
    "Cookie Without Secure Flag":
        'SecRule RESPONSE_HEADERS:Set-Cookie '
        '"!@contains Secure" '
        '"id:10009,phase:3,pass,log,'
        'msg:\'ShieldSentinel-Cookie-NoSecure\'"',
    "Directory Browsing":
        'SecRule REQUEST_URI "@rx '
        r'(?i)\.(git|env|bak|backup|sql|db|log)$" '
        '"id:10010,phase:2,deny,status:403,'
        'log,msg:\'ShieldSentinel-Sensitive-File\'"',
}

CLOUDFLARE_TEMPLATES = {
    "SQL Injection":
        '(http.request.uri.query contains "\'") or '
        '(http.request.uri.query contains "UNION") or '
        '(http.request.uri.query contains "--")',
    "Cross Site Scripting (Reflected)":
        '(http.request.uri.query contains "<script") or '
        '(http.request.uri.query contains "onerror=") or '
        '(http.request.uri.query contains "onload=")',
    "Path Traversal":
        '(http.request.uri.query contains "../") or '
        '(http.request.uri.query contains "..\\\\") or '
        '(http.request.uri.query contains "%2e%2e")',
    "Server Side Request Forgery":
        '(http.request.uri.query contains "localhost") or '
        '(http.request.uri.query contains "127.0.0.1") or '
        '(http.request.uri.query contains "169.254.")',
    "Missing Rate Limiting":
        '(rate(http.request.uri.path) gt 60)',
}

NGINX_TEMPLATES = {
    "SQL Injection":
        "# Add to nginx.conf server block:\n"
        "if ($query_string ~* "
        r'"(union|select|insert|delete|drop|'
        r'update|exec|execute|script|<|>|\'|")" ) {\n'
        "    return 403;\n"
        "}",
    "Path Traversal":
        "# Block path traversal:\n"
        r'if ($request_uri ~* "\.\./") {' "\n"
        "    return 403;\n"
        "}",
    "Directory Browsing":
        "# Disable directory listing:\n"
        "autoindex off;\n\n"
        "# Block sensitive files:\n"
        r'location ~* \.(git|env|bak|sql|log|conf)$ {'
        "\n"
        "    deny all;\n"
        "}",
}


class WAFService:

    def __init__(self):
        from packages.ai.llm_router import LLMRouter
        self.llm = LLMRouter()

    def generate_rules(self, finding: dict) -> dict:
        vuln_type = finding.get("vuln_type", "")
        url       = finding.get("url", "")
        parameter = finding.get("parameter", "")
        evidence  = (
            finding.get("evidence") or ""
        )[:200]

        modsec    = MODSEC_TEMPLATES.get(vuln_type)
        cloudflare = CLOUDFLARE_TEMPLATES.get(
            vuln_type
        )
        nginx     = NGINX_TEMPLATES.get(vuln_type)

        if modsec and cloudflare and nginx:
            return {
                "modsecurity":  modsec,
                "cloudflare":   cloudflare,
                "nginx_config": nginx,
                "aws_waf":      self._build_aws_rule(
                    vuln_type
                ),
                "description":
                    f"WAF rules block {vuln_type} "
                    f"attacks targeting "
                    f"{url or 'all endpoints'}.",
            }

        # Fall back to LLM for unknown vuln types
        return self._llm_generate(
            vuln_type, url, parameter, evidence,
            modsec or "",
        )

    def _build_aws_rule(self, vuln_type: str) -> dict:
        search_strings = {
            "SQL Injection":
                ["'", "UNION", "SELECT", "--"],
            "Cross Site Scripting (Reflected)":
                ["<script", "onerror=", "onload="],
            "Path Traversal":
                ["../", "..\\", "%2e%2e"],
        }
        strings = search_strings.get(
            vuln_type, [vuln_type[:20]]
        )

        return {
            "Name":
                f"ShieldSentinel-Block-"
                f"{vuln_type.replace(' ', '')}",
            "Priority": 100,
            "Action":   {"Block": {}},
            "Statement": {
                "OrStatement": {
                    "Statements": [
                        {
                            "ByteMatchStatement": {
                                "SearchString": s,
                                "FieldToMatch": {
                                    "AllQueryArguments":
                                        {}
                                },
                                "TextTransformations": [
                                    {
                                        "Priority": 0,
                                        "Type":
                                            "URL_DECODE",
                                    }
                                ],
                                "PositionalConstraint":
                                    "CONTAINS",
                            }
                        }
                        for s in strings
                    ]
                }
            },
            "VisibilityConfig": {
                "SampledRequestsEnabled": True,
                "CloudWatchMetricsEnabled": True,
                "MetricName":
                    f"ShieldSentinel-"
                    f"{vuln_type.replace(' ', '')}",
            },
        }

    def _llm_generate(
        self,
        vuln_type: str,
        url: str,
        parameter: str,
        evidence: str,
        base_modsec: str,
    ) -> dict:
        system = (
            "You are a WAF security expert. "
            "Generate production-ready WAF rules. "
            "Respond ONLY with valid JSON."
        )

        prompt = f"""Generate WAF rules for:
Type: {vuln_type}
URL: {url}
Parameter: {parameter}
Evidence: {evidence}
Base ModSecurity rule: {base_modsec or 'none'}

Respond with ONLY this JSON:
{{
  "modsecurity": "complete SecRule line(s)",
  "cloudflare": "Cloudflare firewall rule expression",
  "nginx_config": "nginx config block",
  "aws_waf": {{"Name": "rule-name", "note": "configure manually"}},
  "description": "what this rule blocks and why"
}}"""

        try:
            from packages.ai.llm_router import LLMRouter
            result = LLMRouter().chat_json(
                [{"role": "user", "content": prompt}],
                system,
                max_tokens=600,
            )
            if base_modsec and (
                not result.get("modsecurity") or
                "id:" not in result.get(
                    "modsecurity", ""
                )
            ):
                result["modsecurity"] = base_modsec
            return result
        except Exception:
            return {
                "modsecurity":
                    base_modsec or
                    f"# Configure manually for "
                    f"{vuln_type}",
                "cloudflare":
                    f"# Configure in Cloudflare "
                    f"for {vuln_type}",
                "nginx_config":
                    f"# Configure in nginx "
                    f"for {vuln_type}",
                "aws_waf": {
                    "note":
                        "Configure manually in "
                        "AWS WAF console"
                },
                "description":
                    f"Manual WAF configuration "
                    f"required for {vuln_type}",
            }

    def build_full_conf(
        self, scan, findings_with_rules: list
    ) -> str:
        from datetime import datetime
        lines = [
            "# ShieldSentinel WAF Rules",
            f"# Target: {scan.target}",
            f"# Generated: "
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            f"# Risk Score: "
            f"{scan.risk_score or 'N/A'}/100",
            "#",
            "# IMPORTANT: Test in detection mode "
            "first — set SecRuleEngine DetectionOnly",
            "# Then switch to: SecRuleEngine On",
            "#",
            "",
            "SecRuleEngine On",
            "",
        ]

        for f in findings_with_rules:
            if not f.waf_rule:
                continue
            modsec = f.waf_rule.get("modsecurity")
            if not modsec or modsec.startswith("#"):
                continue
            lines.append(
                f"# Rule for: {f.vuln_type} "
                f"at {f.url or 'code'}"
            )
            lines.append(modsec)
            lines.append("")

        return "\n".join(lines)
