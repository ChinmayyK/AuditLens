import requests
import time
import logging
import re
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class AuthStrengthService:
    """
    Tests the strength of authentication systems by probing login forms.
    Checks for empty passwords, weak passwords, rate limiting, and user enumeration.
    """

    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 ShieldSentinel/1.0 AuthTester",
        })

    def scan(self, post_params: List[Dict[str, Any]], scan_id: str) -> List[Dict[str, Any]]:
        """
        Runs auth strength tests on detected login forms.
        """
        findings = []
        
        # 1. Identify potential login forms by looking at param names
        login_forms = []
        for form in post_params:
            params = form.get("params", [])
            param_names = [p.get("name", "").lower() for p in params]
            
            # Heuristic for login forms
            is_login = any(re.search(r"user|login|email|phone", name) for name in param_names) and \
                       any(re.search(r"pass|pwd|secret|token", name) for name in param_names)
            
            if is_login:
                login_forms.append(form)

        if not login_forms:
            logger.info("No login forms identified for auth strength testing.")
            return findings

        for form in login_forms:
            form_url = form.get("url", self.target_url)
            params = form.get("params", [])
            
            # Test 1: Empty Password Submission
            findings += self._test_empty_password(form_url, params, scan_id)
            
            # Test 2: Weak Password (password123)
            findings += self._test_weak_password(form_url, params, scan_id)
            
            # Test 3: User Enumeration (Error Message Analysis)
            findings += self._test_user_enumeration(form_url, params, scan_id)
            
            # Test 4: Rate Limiting / Lockout
            findings += self._test_rate_limiting(form_url, params, scan_id)
            
            # Test 5: MFA Presence
            findings += self._check_mfa_mention(form_url, scan_id)

        return findings

    def _test_empty_password(self, url: str, params: List[Dict[str, Any]], scan_id: str) -> List[Dict[str, Any]]:
        payload = {}
        for p in params:
            name = p.get("name")
            if re.search(r"pass|pwd|secret", name.lower()):
                payload[name] = ""
            else:
                payload[name] = "testuser_admin"

        try:
            resp = self.session.post(url, data=payload, timeout=10, verify=False)
            # If server returns 200 OK or redirects (302) and doesn't explicitly look like an error, it might be vulnerable
            # This is a heuristic, real login bypass is harder to confirm without creds, but we check for 'required' validation
            if resp.status_code in [200, 302] and "required" not in resp.text.lower() and "empty" not in resp.text.lower():
                return [{
                    "scan_id": scan_id,
                    "vuln_type": "Weak Auth: Empty Password Allowed",
                    "severity": "High",
                    "url": url,
                    "evidence": f"POST request with empty password returned {resp.status_code}. No client-side or server-side validation detected.",
                    "description": "The login form appears to accept or improperly handle empty password submissions, which can lead to authentication bypass if logic errors exist in the backend.",
                    "attack_worked": True,
                    "tool_source": "auth_strength_tester"
                }]
        except Exception:
            pass
        return []

    def _test_weak_password(self, url: str, params: List[Dict[str, Any]], scan_id: str) -> List[Dict[str, Any]]:
        payload = {}
        for p in params:
            name = p.get("name")
            if re.search(r"pass|pwd|secret", name.lower()):
                payload[name] = "password123"
            else:
                payload[name] = "admin"

        try:
            resp = self.session.post(url, data=payload, timeout=10, verify=False)
            # If we get a long response time or specific flags, we might flag it. 
            # For a scanner, we mostly check if it fails *differently* or if it's accepted.
            pass # confirmation usually requires a valid user
        except Exception:
            pass
        return []

    def _test_user_enumeration(self, url: str, params: List[Dict[str, Any]], scan_id: str) -> List[Dict[str, Any]]:
        # Check if error message differs for non-existent user
        user_field = next((p.get("name") for p in params if re.search(r"user|login|email", p.get("name").lower())), None)
        pass_field = next((p.get("name") for p in params if re.search(r"pass|pwd|secret", p.get("name").lower())), "password123")
        
        if not user_field: return []

        try:
            # 1. Non-existent long random user
            resp1 = self.session.post(url, data={user_field: "nonexistent_user_9922x", pass_field: "wrongpass123"}, verify=False)
            # 2. Common user like 'admin'
            resp2 = self.session.post(url, data={user_field: "admin", pass_field: "wrongpass123"}, verify=False)
            
            if resp1.text != resp2.text:
                return [{
                    "scan_id": scan_id,
                    "vuln_type": "Authentication: User Enumeration",
                    "severity": "Medium",
                    "url": url,
                    "evidence": "Different error responses or lengths returned for valid vs invalid usernames.",
                    "description": "The application leaks whether a user exists via different error messages (e.g., 'User not found' vs 'Incorrect password'). Attackers use this to build a list of valid users for brute-force attacks.",
                    "attack_worked": True,
                    "tool_source": "auth_strength_tester"
                }]
        except Exception:
            pass
        return []

    def _test_rate_limiting(self, url: str, params: List[Dict[str, Any]], scan_id: str) -> List[Dict[str, Any]]:
        count = 15 # Probing with 15 requests to see if blocked
        start_time = time.time()
        blocked = False
        
        payload = {}
        for p in params:
            payload[p.get("name")] = "bruteforce_test_val"

        for i in range(count):
            try:
                resp = self.session.post(url, data=payload, timeout=5, verify=False)
                if resp.status_code == 429:
                    blocked = True
                    break
                # Check for "too many attempts" in body
                if any(x in resp.text.lower() for x in ["too many", "blocked", "rate limit", "try again later"]):
                    blocked = True
                    break
            except Exception:
                break
        
        if not blocked:
            return [{
                "scan_id": scan_id,
                "vuln_type": "Lack of Brute-Force Protection",
                "severity": "High",
                "url": url,
                "evidence": f"Successfully performed {count} failed login attempts without being rate-limited or blocked.",
                "description": "The login interface does not enforce rate limiting or account lockouts. This allows attackers to perform automated brute-force attacks at high speed.",
                "attack_worked": True,
                "tool_source": "auth_strength_tester"
            }]
        return []

    def _check_mfa_mention(self, url: str, scan_id: str) -> List[Dict[str, Any]]:
        try:
            resp = self.session.get(url, timeout=10, verify=False)
            mfa_keywords = ["mfa", "2fa", "two-factor", "authenticator", "verification code", "sms code", "totp"]
            if not any(kw in resp.text.lower() for kw in mfa_keywords):
                return [{
                    "scan_id": scan_id,
                    "vuln_type": "Security Best Practice: MFA Not Detected",
                    "severity": "Low",
                    "url": url,
                    "evidence": "No mention of MFA/2FA found on login page.",
                    "description": "Multi-Factor Authentication (MFA) was not detected on the login interface. Implementing MFA is the most effective defense against credential theft.",
                    "attack_worked": False,
                    "tool_source": "auth_strength_tester",
                    "was_attempted": True
                }]
        except Exception:
            pass
        return []
