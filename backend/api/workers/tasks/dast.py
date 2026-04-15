import time
import uuid
import sys
from datetime import datetime

sys.path.insert(0, "/app")
sys.path.insert(0, "/packages")

from workers.celery_app import celery_app
from models.base import SessionLocal
from models.scan import Scan, ScanEvent, AttackSurface
from core.db_helpers import (
    update_scan_status, update_scan,
    save_findings, calculate_risk_score,
    get_risk_grade,
)
from core.websocket import ws_emit
import logging

logger = logging.getLogger(__name__)


def _emit(scan_id, msg, pct, db,
          tool=None, et="progress",
          target_url=None, result=None):
    ws_emit(scan_id, msg, pct,
            tool=tool, event_type=et,
            target_url=target_url, result=result)
    try:
        ev = ScanEvent(
            scan_id=uuid.UUID(scan_id),
            event_type=et,
            message=msg,
            progress_pct=pct,
            tool=tool,
            target_url=target_url,
            result=result,
        )
        db.add(ev)
        db.commit()
    except Exception:
        db.rollback()


@celery_app.task(
    bind=True,
    name="workers.tasks.dast.run_url_scan",
    queue="dast",
    max_retries=1,
    default_retry_delay=10,
)
def run_url_scan(
    self, scan_id, target_url, intensity,
):
    db = SessionLocal()
    all_findings = []

    def emit(msg, pct, tool=None,
             et="progress", result=None, **kw):
        if "event_type" in kw and kw["event_type"]:
            et = kw["event_type"]
        if "tool" in kw and kw["tool"]:
            tool = kw["tool"]
        if "result" in kw and kw["result"]:
            result = kw["result"]
        _emit(scan_id, msg, pct, db,
              tool=tool, et=et,
              target_url=target_url,
              result=result)

    try:
        logger.info(
            f"DAST {scan_id} → {target_url} "
            f"[{intensity}]"
        )
        scan = db.query(Scan).filter(
            Scan.id == uuid.UUID(scan_id)
        ).first()
        scan.started_at = datetime.utcnow()
        update_scan_status(
            scan_id, "running", db, "Initializing"
        )
        emit("🚀 Scan started", 2)

        # 1 ── Tech fingerprint ─────────────────────
        emit("🌐 Fingerprinting technology...",
             3, tool="tech_fingerprint", et="phase")
        from packages.scanner.tech_fingerprint \
            import TechFingerprintService
        tech = TechFingerprintService().detect(
            target_url
        )
        
        # Save tech stack to DB
        scan.tech_stack = tech
        scan.cdn_detected = tech.get("cdn_detected")
        scan.waf_detected = tech.get("waf_detected")
        scan.waf_name = tech.get("waf_name")
        db.commit()

        tech_list = tech.get("technologies", [])
        stack_str = ", ".join(
            [t["name"] for t in tech_list[:4]]
        ) or "Unknown"
        emit(
            f"✅ Stack detected: {stack_str}",
            6, tool="tech_fingerprint",
        )

        # 1.1 ── CVE Live Lookup ────────────────────
        techs_with_versions = [
            t for t in tech_list if t.get("version")
        ]
        if techs_with_versions:
            emit(f"🔎 Querying NVD for CVEs...",
                 6, tool="nvd_intel", et="phase")
            try:
                from packages.scanner.cve_intel_service import CveIntelService
                import os
                nvd_api_key = os.getenv("NVD_API_KEY")
                cve_svc = CveIntelService(api_key=nvd_api_key)
                
                for t in techs_with_versions:
                    name = t["name"]
                    version = t["version"]
                    emit(f"🔍 Checking CVEs for {name} {version}...", 6, tool="nvd_intel")
                    
                    cve_findings = cve_svc.get_cves_for_tech(name, version)
                    for find in cve_findings:
                        find["scan_id"] = uuid.UUID(scan_id)
                        all_findings.append(find)
                        
                emit(f"✅ CVE Intel: {len(techs_with_versions)} technologies audited", 7, tool="nvd_intel")
            except Exception as e:
                logger.error(f"CVE lookup failed: {e}")
                emit(f"⚠️ CVE lookup skipped: API access error", 7, tool="nvd_intel")
        
        # 1.2 ── Email Security Intelligence ────────
        emit("📧 Checking DNS & Email Security...",
             6, tool="email_security", et="phase")
        try:
            from packages.scanner.email_security_service import EmailSecurityService
            email_f = EmailSecurityService().scan(target_url, scan_id)
            all_findings += email_f
            vuln_email = [f for f in email_f if f.get("attack_worked")]
            emit(
                f"✅ Email Security: {len(vuln_email)} issues found",
                7, tool="email_security",
            )
        except Exception as e:
            logger.warning(f"Email security scan failed: {e}")
            emit(
                f"⚠️ Email security scan skipped: {str(e)[:40]}",
                7, tool="email_security",
            )

        # 1.3 ── CORS Misconfiguration Tester ────────
        emit("🛡️ Testing CORS policy...",
             7, tool="cors_security", et="phase")
        try:
            from packages.scanner.cors_service import CorsService
            cors_f = CorsService().scan(target_url)
            # Map simplified finding to internal format if needed
            for cf in cors_f:
                cf["scan_id"] = uuid.UUID(scan_id)
                cf["attack_worked"] = True if cf["severity"] in ["High", "Medium"] else False
                all_findings.append(cf)
            
            emit(
                f"✅ CORS Testing: {len(cors_f)} issue(s) detected",
                8, tool="cors_security",
            )
        except Exception as e:
            logger.warning(f"CORS security scan failed: {e}")
            emit(
                f"⚠️ CORS scan skipped: {str(e)[:40]}",
                8, tool="cors_security",
            )

        # 1.5 ── Subdomain enumeration ──────────────
        if intensity in ["deep", "aggressive"]:
            emit(
                "🌐 Enumerating subdomains...",
                5,
                tool="subdomain_enum",
            )
            try:
                import json as _json
                import os

                import redis as sync_redis

                from packages.scanner.subdomain_service import SubdomainService

                sub_result = SubdomainService().enumerate(
                    target_url,
                    scan_id,
                    lambda m, p, **kw: emit(
                        m,
                        p,
                        tool="subdomain_enum",
                    ),
                    intensity=intensity,
                )
                r = sync_redis.from_url(
                    os.getenv(
                        "REDIS_URL",
                        "redis://redis:6379/0",
                    )
                )
                r.setex(
                    f"subdomains:{scan_id}",
                    3600,
                    _json.dumps(sub_result),
                )
                
                sub_findings = sub_result.get("findings", [])
                if sub_findings:
                    all_findings += sub_findings
                    emit(
                        f"🚨 Subdomain Takeover! {len(sub_findings)} claimable domains found!",
                        7,
                        tool="subdomain_enum",
                        result="vulnerable",
                    )
                else:
                    emit(
                        f"✅ Subdomains: {sub_result['total_found']} live",
                        7,
                        tool="subdomain_enum",
                    )

            except Exception as e:
                emit(
                    f"⚠️ Subdomain enum skipped: {str(e)[:40]}",
                    7,
                    tool="subdomain_enum",
                )

        # 2 ── Nmap ─────────────────────────────────
        emit("🗺️ Port scanning...",
             7, tool="nmap", et="phase")
        from packages.scanner.nmap_service \
            import NmapService
        nmap_res = NmapService().scan(
            target_url, scan_id
        )

        # 2.5 ── API Contract Fuzzing ───────────────
        if intensity in ["standard", "deep", "aggressive"]:
            emit("🧪 Detecting and Fuzzing API Contracts...",
                 10, tool="api_fuzzer", et="phase")
            try:
                from packages.scanner.api_fuzzer import APIContractFuzzer
                fuzzer = APIContractFuzzer(target_url)
                fuzzer_f = fuzzer.scan(scan_id)
                all_findings += fuzzer_f
                emit(f"✅ API Fuzzing: {len(fuzzer_f)} contract violations found", 12, tool="api_fuzzer")
            except Exception as e:
                logger.warning(f"API fuzzing failed: {e}")
                emit(f"⚠️ API fuzzing skipped: {str(e)[:40]}", 12, tool="api_fuzzer")
        scan.open_ports = nmap_res.get(
            "open_ports", []
        )
        scan.os_guess = nmap_res.get(
            "os_guess", "Unknown"
        )
        db.commit()
        nmap_f = nmap_res.get("findings", [])
        all_findings += nmap_f
        emit(
            f"✅ Nmap: "
            f"{len(nmap_res.get('open_ports', []))}"
            f" ports open, "
            f"{len(nmap_f)} issues",
            14, tool="nmap",
        )

        # 3 ── SSL + headers ────────────────────────
        emit("🔒 SSL/TLS and header audit...",
             15, tool="ssl_audit", et="phase")
        from packages.scanner.ssl_service \
            import SSLService
        ssl_f = SSLService().scan(
            target_url, scan_id
        )
        all_findings += ssl_f
        vuln_ssl = [f for f in ssl_f
                    if f.get("attack_worked")]
        emit(
            f"✅ SSL/Headers: {len(vuln_ssl)} issues",
            22, tool="ssl_audit",
        )

        # 4 ── Cookies ──────────────────────────────
        emit("🍪 Cookie security check...",
             23, tool="cookie_checker")
        from packages.scanner.cookie_checker \
            import CookieChecker
        cookie_f = CookieChecker().check(
            target_url, scan_id
        )
        all_findings += cookie_f
        emit(
            f"✅ Cookies: "
            f"{len([f for f in cookie_f if f.get('attack_worked')])}"
            f" issues",
            26, tool="cookie_checker",
        )

        # 5 ── FFUF ─────────────────────────────────
        emit("📂 Directory discovery (FFUF)...",
             27, tool="ffuf", et="phase")
        from packages.scanner.ffuf_service \
            import FFUFService
        ffuf_f = FFUFService().scan(
            target_url, scan_id,
            lambda m, p, **kw: emit(m, p, **kw),
        )
        all_findings += ffuf_f
        emit(
            f"✅ FFUF: "
            f"{len([f for f in ffuf_f if f.get('attack_worked')])}"
            f" sensitive paths",
            28, tool="ffuf",
        )

        # 5.5 ── Gobuster (second-pass dir busting) ─
        from packages.scanner.gobuster_service \
            import GobusterService
        gob_f = GobusterService().scan(
            target_url, scan_id,
            lambda m, p, **kw: emit(m, p, **kw),
            intensity=intensity,
        )
        all_findings += gob_f
        emit(
            f"✅ Gobuster: "
            f"{len([f for f in gob_f if f.get('attack_worked')])}"
            f" interesting paths",
            30, tool="gobuster",
        )

        # 6 ── ZAP spider ───────────────────────────
        emit("🕷️ Starting web crawler...",
             31, tool="zap_spider", et="phase")
        discovered_urls = []
        all_urls = [target_url]
        try:
            from packages.scanner.zap_service \
                import ZAPService
            zap = ZAPService()
            zap_timeout = {
                "quick":      120,
                "standard":   180,
                "deep":         300,
                "aggressive":   420,
            }.get(intensity, 180)
            zap.wait_for_zap(timeout=zap_timeout)
            zap.new_session()
            discovered_urls = zap.spider(
                target_url, scan_id,
                lambda m, p, **kw: emit(m, p, **kw),
                intensity=intensity,
            )
            emit(
                f"✅ Crawled {len(discovered_urls)} URLs",
                35, tool="zap_spider",
            )
            all_urls = list(set([target_url] + discovered_urls))

            # 7 ── ZAP active scan ─────────────────
            emit("⚔️ ZAP active attack simulation...",
                 36, tool="zap_ascan", et="phase")
            zap.active_scan(
                target_url, scan_id,
                lambda m, p, **kw: emit(
                    m, p, et="attack", **kw
                ),
                intensity=intensity,
            )
            zap_alerts = zap.get_alerts(target_url)
            zap_f = zap.parse_alerts(
                zap_alerts, scan_id
            )
            all_findings += zap_f
            emit(
                f"✅ ZAP: "
                f"{len([f for f in zap_f if f.get('attack_worked')])}"
                f" vulnerabilities found",
                61, tool="zap",
            )
            _save_attack_surface(
                scan_id, target_url,
                all_urls, all_findings, db,
            )

            # 7.5 ── JavaScript Deep Scanner ─────────────
            if intensity != "quick":
                emit("📜 Scanning JavaScript files for secrets...",
                     36, tool="js_scanner", et="phase")
                try:
                    from packages.scanner.js_deep_scanner import JSDeepScanner
                    js_scanner = JSDeepScanner(target_url)
                    js_f = js_scanner.scan(all_urls, scan_id)
                    all_findings += js_f
                    emit(f"✅ JS Scan: {len(js_f)} sensitive items found", 37, tool="js_scanner")
                except Exception as e:
                    logger.warning(f"JS deep scan failed: {e}")
                    emit(f"⚠️ JS scan skipped: {str(e)[:40]}", 37, tool="js_scanner")
        except Exception as zap_err:
            logger.warning(f"ZAP error: {zap_err}")
            emit(
                f"⚠️ ZAP unavailable: "
                f"{str(zap_err)[:60]}",
                61, tool="zap",
            )
            _save_attack_surface(
                scan_id, target_url,
                all_urls, all_findings, db,
            )

        # 8 ── Parameter extraction ─────────────────
        emit("🔬 Extracting input parameters...",
             62, tool="param_extractor")
        from packages.scanner.param_extractor \
            import ParamExtractor
        params = ParamExtractor().extract(
            target_url, discovered_urls
        )
        get_params  = params["get_params"]
        post_params = params["post_params"]
        emit(
            f"✅ Found {len(get_params)} GET params,"
            f" {len(post_params)} forms",
            64, tool="param_extractor",
        )

        # 8.5 ── Auth Strength & policy ─────────────
        emit("🔐 Auditing authentication strength...",
             64, tool="auth_strength", et="phase")
        try:
            from packages.scanner.auth_strength_service import AuthStrengthService
            auth_svc = AuthStrengthService(target_url)
            auth_f = auth_svc.scan(post_params, scan_id)
            all_findings += auth_f
            emit(f"✅ Auth Audit: {len(auth_f)} issues detected", 65, tool="auth_strength")
        except Exception as e:
            logger.warning(f"Auth strength scan failed: {e}")
            emit(f"⚠️ Auth audit skipped: {str(e)[:40]}", 65, tool="auth_strength")

        # 9 ── Nuclei ───────────────────────────────
        from packages.scanner.nuclei_service \
            import NucleiService
        nuclei_f = NucleiService().scan(
            target_url, scan_id,
            lambda m, p, **kw: emit(m, p, **kw),
            intensity=intensity,
        )
        all_findings += nuclei_f
        emit(
            f"✅ Nuclei: "
            f"{len([f for f in nuclei_f if f.get('attack_worked')])}"
            f" CVEs/templates matched",
            65, tool="nuclei",
        )

        # 10 ── SQLMap (deep/aggressive only) ───────
        if intensity in ["deep", "aggressive"] and \
           (get_params or post_params):
            emit("💉 Targeted SQL injection testing...",
                 66, tool="sqlmap", et="phase")
            from packages.scanner.sqlmap_service \
                import SQLMapService
            sql_f = SQLMapService().scan_parameters(
                scan_id, get_params, post_params,
                lambda m, p, **kw: emit(
                    m, p, et="attack", **kw
                ),
                intensity=intensity,
            )
            all_findings += sql_f
            vuln_sql = [f for f in sql_f
                        if f.get("attack_worked")]
            if vuln_sql:
                emit(
                    f"🔴 SQLMap CONFIRMED: "
                    f"{len(vuln_sql)} injections!",
                    78, tool="sqlmap",
                    result="vulnerable",
                )
            else:
                emit(
                    "✅ SQLMap: No injections found",
                    78, tool="sqlmap",
                )

        # 11 ── XSStrike ────────────────────────────
        if intensity in ["deep", "aggressive"] and \
           get_params:
            emit("🎯 Advanced XSS testing...",
                 79, tool="xsstrike", et="attack")
            from packages.scanner.xsstrike_service \
                import XSStrikeService
            xss_f = XSStrikeService().scan(
                scan_id, get_params,
                lambda m, p, **kw: emit(
                    m, p, et="attack", **kw
                ),
            )
            all_findings += xss_f
            vuln_xss = [f for f in xss_f
                        if f.get("attack_worked")]
            if vuln_xss:
                emit(
                    f"🔴 XSS CONFIRMED: "
                    f"{len(vuln_xss)} endpoints!",
                    81, tool="xsstrike",
                    result="vulnerable",
                )
            else:
                emit(
                    "✅ XSS: Parameters appear safe",
                    81, tool="xsstrike",
                )

        # 11.5 ── Commix (OS command injection) ──────
        if intensity in ["deep", "aggressive"] and \
           get_params:
            emit(
                "💀 OS command injection (Commix)...",
                82, tool="commix", et="phase",
            )
            from packages.scanner.commix_service \
                import CommixService
            cx_f = CommixService().scan_parameters(
                scan_id, get_params,
                lambda m, p, **kw: emit(
                    m, p, et="attack", **kw
                ),
                intensity=intensity,
            )
            all_findings += cx_f
            vuln_cx = [
                f for f in cx_f
                if f.get("attack_worked")
            ]
            if vuln_cx:
                emit(
                    f"🔴 Commix: {len(vuln_cx)} "
                    f"command injection signal(s)",
                    84, tool="commix",
                    result="vulnerable",
                )
            else:
                emit(
                    "✅ Commix: no command injection "
                    "confirmed",
                    84, tool="commix",
                )

        # 11.8 ── HTTP Request Smuggling ───────────
        if intensity in ["deep", "aggressive"]:
            emit("🚇 Testing HTTP Request Smuggling...",
                 85, tool="smuggling", et="phase")
            from packages.scanner.smuggling_service \
                import test_http_smuggling
            
            smuggling_f = test_http_smuggling(
                target_url, scan_id, 
                lambda m, p, **kw: emit(m, p, **kw)
            )
            all_findings += smuggling_f
            vuln_smuggling = sum(1 for f in smuggling_f if f.get("attack_worked"))
            if vuln_smuggling > 0:
                emit(
                    f"🚨 HTTP Smuggling CONFIRMED: {vuln_smuggling} variant(s) found!",
                    86, tool="smuggling", result="vulnerable"
                )
            else:
                emit("✅ HTTP Smuggling: All tests passed", 86, tool="smuggling")

        # 11.9 ── Race Condition Attacker ───────────
        if intensity in ["standard", "deep", "aggressive"] and post_params:
            emit("🏎️ Testing for Race Conditions (TOCTOU)...", 
                 86, tool="race_condition_attacker", et="phase")
            try:
                from packages.scanner.race_condition_service import RaceConditionService
                race_svc = RaceConditionService()
                race_f = race_svc.scan(
                    target_url, scan_id, post_params,
                    lambda m, p: emit(m, p, tool="race_condition_attacker")
                )
                all_findings += race_f
                if race_f:
                    emit(
                        f"🔴 Race Condition: {len(race_f)} critical bypass(es)!",
                        87, tool="race_condition_attacker", result="vulnerable"
                    )
                else:
                    emit(
                        "✅ Race Condition: No immediate TOCTOU flaws found",
                        87, tool="race_condition_attacker"
                    )
            except Exception as e:
                logger.warning(f"Race condition scan failed: {e}")
                emit(
                    f"⚠️ Race condition scan skipped: {str(e)[:40]}",
                    87, tool="race_condition_attacker"
                )

        # 12 ── Nikto ───────────────────────────────
        from packages.scanner.nikto_service \
            import NiktoService
        nikto_f = NiktoService().scan(
            target_url, scan_id,
            lambda m, p, **kw: emit(m, p, **kw),
        )
        all_findings += nikto_f
        emit(
            f"✅ Nikto: "
            f"{len([f for f in nikto_f if f.get('attack_worked')])}"
            f" server issues",
            87, tool="nikto",
        )

        # Stress test (standard and above)
        if intensity in ["standard", "deep", "aggressive"]:
            emit(
                "⚡ Testing rate limits and auth controls...",
                76, tool="stress", et="phase",
            )
            from packages.scanner.stress_service \
                import StressTestService
            stress_f = StressTestService().test_rate_limiting(
                target_url, scan_id,
                lambda m, p, **kw: emit(
                    m, p, **kw
                ),
            )
            all_findings += stress_f

        # 13 ── Score + save ────────────────────────
        emit("📊 Calculating risk score...",
             88, tool="analysis")

        score, breakdown = calculate_risk_score(all_findings)
        grade = get_risk_grade(score)

        total_vuln = len([
            f for f in all_findings
            if f.get("attack_worked")
        ])
        total_def = len([
            f for f in all_findings
            if not f.get("attack_worked") and
            f.get("was_attempted")
        ])

        emit(
            f"💾 Saving "
            f"{len(all_findings)} results...",
            90, tool="analysis",
        )
        save_findings(scan_id, all_findings, db)

        # 14 ── AI fixes ────────────────────────────
        emit("🤖 Queuing AI fix generation...",
             93, tool="ai")
        from workers.tasks.ai_tasks \
            import generate_ai_fixes
        generate_ai_fixes.apply_async(
            args=[scan_id],
            queue="ai",
            countdown=3,
        )

        # Finalize
        start_t = scan.started_at or datetime.utcnow()
        dur = int(
            (datetime.utcnow() - start_t).total_seconds()
        )
        update_scan(
            scan_id, db,
            status="complete",
            risk_score=score,
            risk_grade=grade,
            risk_breakdown=breakdown,
            progress_pct=100,
            current_phase="Complete",
            completed_at=datetime.utcnow(),
            duration_seconds=dur,
        )
        emit(
            "────────────────────────────────────────",
            100, et="phase"
        )
        emit(
            f"✅ SUCCESS: Scan complete! "
            f"Result: {grade} ({score}/100)",
            100, et="complete",
        )
        emit(
            f"📊 Final Stats: {total_vuln} vulns | {total_def} defended",
            100, et="info"
        )
        emit(
            "🏁 Core systems standing down.",
            100, et="info"
        )

    except Exception as e:
        logger.error(
            f"DAST {scan_id} failed: {e}",
            exc_info=True,
        )
        try:
            update_scan(
                scan_id, db,
                status="failed",
                error_message=str(e)[:500],
                current_phase="Failed",
            )
        except Exception:
            pass
        emit(
            "────────────────────────────────────────",
            0, et="error"
        )
        emit(
            f"❌ FAILURE: Scan aborted: {str(e)[:100]}",
            0, event_type="error",
        )
        emit(
            "⚠️ Check your target connectivity or credentials.",
            0, event_type="error",
        )
    finally:
        db.close()


def _save_attack_surface(
    scan_id, target_url,
    all_urls, findings, db,
):
    try:
        from urllib.parse import urlparse

        nodes = {}
        for url in all_urls[:100]:
            path = urlparse(url).path or "/"
            if path not in nodes:
                nodes[path] = {
                    "id":        path,
                    "label":
                        path[:30] + "..."
                        if len(path) > 30 else path,
                    "full_url":  url,
                    "risk":      "safe",
                    "vuln_count": 0,
                    "vulns":     [],
                }

        SEV_RANK = {
            "critical": 4, "high": 3,
            "medium": 2, "low": 1, "safe": 0,
        }
        for f in findings:
            if not f.get("url") or \
               not f.get("attack_worked"):
                continue
            p = urlparse(f["url"]).path or "/"
            if p in nodes:
                nodes[p]["vuln_count"] += 1
                nodes[p]["vulns"].append(
                    f.get("vuln_type", "")
                )
                sev = f.get("severity", "info")
                cur = nodes[p]["risk"]
                if SEV_RANK.get(sev, 0) > \
                   SEV_RANK.get(cur, 0):
                    nodes[p]["risk"] = sev

        edges = []
        seen_edges = set()
        for path in list(nodes.keys()):
            parts = path.rstrip("/").split("/")
            if len(parts) > 1:
                parent = "/".join(parts[:-1]) or "/"
                if parent in nodes:
                    key = f"{parent}→{path}"
                    if key not in seen_edges:
                        edges.append({
                            "source": parent,
                            "target": path,
                        })
                        seen_edges.add(key)

        # Root node
        if "/" not in nodes:
            nodes["/"] = {
                "id":        "/",
                "label":     "/",
                "full_url":  target_url,
                "risk":      "safe",
                "vuln_count": 0,
                "vulns":     [],
            }

        existing = db.query(AttackSurface).filter(
            AttackSurface.scan_id ==
            uuid.UUID(scan_id)
        ).first()
        if existing:
            existing.nodes = list(nodes.values())
            existing.edges = edges
            existing.discovered_urls = all_urls[:200]
        else:
            surf = AttackSurface(
                scan_id=uuid.UUID(scan_id),
                nodes=list(nodes.values()),
                edges=edges,
                discovered_urls=all_urls[:200],
            )
            db.add(surf)
        db.commit()
    except Exception as e:
        logger.warning(
            f"Attack surface save failed: {e}"
        )
