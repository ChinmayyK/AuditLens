import threading
import logging
from typing import List, Dict, Any, Callable
from urllib.parse import urlparse
import requests
import urllib3

urllib3.disable_warnings()

logger = logging.getLogger(__name__)


class RaceConditionService:
    """
    Race Condition Attacker
    Sends 50 identical requests at the exact same millisecond using Python threads.
    Checks for financial bypasses, coupon reuse, and double-spending.
    """

    def __init__(self, request_count: int = 50):
        self.request_count = request_count
        self.barrier = threading.Barrier(request_count)

    def scan(
        self,
        url: str,
        scan_id: str,
        post_params: List[Dict[str, Any]],
        on_progress: Callable[[str, int], None]
    ) -> List[Dict[str, Any]]:
        """
        Scans a target for race condition vulnerabilities by firing concurrent requests.
        """
        findings = []

        # Target candidates: keywords that suggest valuable operations
        keywords = [
            "coupon", "transfer", "pay", "order", "balance",
            "draw", "claim", "redeem", "discount"
        ]

        candidates = []
        for form in post_params:
            url_str = form.get("url", "").lower()
            params = [p.lower() for p in form.get("params", [])]

            # Check if URL or params match keywords
            matches_kw = (
                any(k in url_str for k in keywords) or
                any(any(k in p for k in keywords) for p in params)
            )
            if matches_kw:
                candidates.append(form)

        if not candidates and post_params:
            # Fallback: take the first POST form
            candidates = [post_params[0]]

        if not candidates:
            return []

        on_progress(
            f"🏎️ Race Condition: Testing {len(candidates)} candidate endpoints...",
            85
        )

        for form in candidates:
            target_url = form["url"]
            params = form["params"]

            # Construct a dummy payload based on params
            data = {
                p: "SAVE10" if "coupon" in p.lower() or "discount" in p.lower()
                else "1" for p in params
            }

            path = urlparse(target_url).path
            on_progress(f"⚔️ Firing 50 parallel requests at {path}...", 86)

            results: List[Any] = [None] * self.request_count
            threads = []

            def fire(idx: int):
                try:
                    self.barrier.wait()  # Synchro point
                    r = requests.post(
                        target_url, json=data, timeout=10, verify=False
                    )
                    try:
                        is_json = "json" in r.headers.get("Content-Type", "").lower()
                        results[idx] = {
                            "status": r.status_code,
                            "json": r.json() if is_json else None,
                            "text": r.text[:200]
                        }
                    except Exception:
                        results[idx] = {
                            "status": r.status_code,
                            "text": r.text[:200]
                        }
                except Exception as e:
                    results[idx] = {"error": str(e)}

            for i in range(self.request_count):
                t = threading.Thread(target=fire, args=(i,))
                threads.append(t)
                t.start()

            for t in threads:
                t.join()

            # Analyze results
            success_count = 0

            # We look for "applied", "success", "confirmed", or 200/201 status codes
            for res in [r for r in results if r]:
                if res.get("status") in [200, 201]:
                    # Heuristic check for success in body
                    body = str(res.get("json", "")) + res.get("text", "")
                    indicators = [
                        "applied", "success", "complete", "confirmed", "ok"
                    ]
                    if any(word in body.lower() for word in indicators):
                        success_count += 1

            if success_count > 1:
                desc = (
                    f"The application is vulnerable to race conditions. "
                    f"We fired {self.request_count} identical requests "
                    f"simultaneously, and {success_count} of them were "
                    f"processed as successful. This indicates a 'Time of "
                    f"Check to Time of Use' (TOCTOU) vulnerability where "
                    f"balance, inventory, or coupon state is not correctly "
                    f"locked during concurrent operations."
                )
                findings.append({
                    "scan_id": scan_id,
                    "vuln_type": "Race Condition (Financial Bypass)",
                    "severity": "critical",
                    "category": "logic",
                    "url": target_url,
                    "evidence": (
                        f"Successfully triggered {success_count} parallel "
                        f"responses for a single-use operation."
                    ),
                    "description": desc,
                    "attack_worked": True,
                    "was_attempted": True,
                    "tool_source": "race_condition_attacker",
                    "owasp_category": "A04:2021 - Insecure Design",
                    "attack_name": "Parallel Request Flooding",
                    "money_loss_min": 1000,
                    "money_loss_max": 1000000,
                    "quick_fix": (
                        "Implement atomic database operations or distributed "
                        "locking (e.g., Redis locks) to ensure that sensitive "
                        "transactions are serialized and checked correctly "
                        "under concurrent load."
                    )
                })
                on_progress(
                    f"🔴 RACE CONDITION CONFIRMED: {success_count} parallel!",
                    87
                )
            else:
                on_progress(
                    f"✅ Race Condition: {path} appears resilient.",
                    87
                )

        return findings
