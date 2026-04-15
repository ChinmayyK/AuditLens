import requests
import urllib3
urllib3.disable_warnings()


class CookieChecker:

    def check(self, target_url: str,
              scan_id: str) -> list:
        findings = []

        try:
            resp = requests.get(
                target_url,
                timeout=10,
                verify=False,
                allow_redirects=True,
            )
        except Exception:
            return []

        raw_cookies = []
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            raw_cookies.append(set_cookie)

        # Get all Set-Cookie headers
        if hasattr(resp.raw, "headers"):
            try:
                raw_cookies = resp.raw.headers.getlist(
                    "Set-Cookie"
                )
            except Exception:
                pass

        if not raw_cookies:
            # No cookies — mark as not applicable
            findings.append({
                "scan_id":      scan_id,
                "vuln_type":
                    "Cookie Security Flags",
                "severity":     "info",
                "url":          target_url,
                "evidence":
                    "No Set-Cookie headers in response",
                "description":
                    "No cookies set on this response.",
                "attack_worked": False,
                "was_attempted": True,
                "tool_source":   "cookie_checker",
                "owasp_category":
                    "A02:2021 - Cryptographic Failures",
            })
            return findings

        for cookie_str in raw_cookies:
            cookie_lower = cookie_str.lower()
            name = cookie_str.split("=")[0].strip()

            if "secure" not in cookie_lower:
                findings.append({
                    "scan_id":      scan_id,
                    "vuln_type":
                        "Cookie Without Secure Flag",
                    "severity":     "medium",
                    "category":     "auth",
                    "url":          target_url,
                    "parameter":    name,
                    "evidence":
                        f"Cookie '{name}' missing "
                        f"Secure flag. "
                        f"Raw: {cookie_str[:120]}",
                    "description":
                        f"Cookie '{name}' transmitted "
                        f"over unencrypted HTTP. "
                        f"An attacker on the network "
                        f"captures this cookie and "
                        f"replays it to hijack the "
                        f"user session without needing "
                        f"a password.",
                    "attack_worked": True,
                    "was_attempted": True,
                    "tool_source":   "cookie_checker",
                    "owasp_category":
                        "A02:2021 - Cryptographic "
                        "Failures",
                    "money_loss_min": 5000,
                    "money_loss_max": 500000,
                    "attack_name":
                        "Session Hijacking via "
                        "Cookie Theft",
                    "quick_fix":
                        f"Set-Cookie: {name}=value; "
                        f"Secure; HttpOnly; "
                        f"SameSite=Strict",
                })

            if "httponly" not in cookie_lower:
                findings.append({
                    "scan_id":      scan_id,
                    "vuln_type":
                        "Cookie Without HttpOnly Flag",
                    "severity":     "medium",
                    "category":     "auth",
                    "url":          target_url,
                    "parameter":    name,
                    "evidence":
                        f"Cookie '{name}' missing "
                        f"HttpOnly flag.",
                    "description":
                        f"Cookie '{name}' accessible "
                        f"via JavaScript. Any XSS "
                        f"vulnerability allows "
                        f"document.cookie to steal "
                        f"this token and fully "
                        f"impersonate the user.",
                    "attack_worked": True,
                    "was_attempted": True,
                    "tool_source":   "cookie_checker",
                    "owasp_category":
                        "A02:2021 - Cryptographic "
                        "Failures",
                    "money_loss_min": 5000,
                    "money_loss_max": 500000,
                    "attack_name":
                        "XSS Session Cookie Theft",
                    "quick_fix":
                        f"Add HttpOnly: "
                        f"Set-Cookie: {name}=value; "
                        f"HttpOnly; Secure",
                })

        return findings
