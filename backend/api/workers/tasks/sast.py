import os
import time
import uuid
import subprocess
from datetime import datetime
from pathlib import Path

from workers.celery_app import celery_app
from models.base import SessionLocal
from models.scan import Scan, ScanEvent
from models.ide import IDESession
from core.db_helpers import (
    update_scan, update_scan_status,
    save_findings, calculate_risk_score,
    get_risk_grade,
)
from core.websocket import ws_emit
import logging

logger = logging.getLogger(__name__)


def _emit(scan_id, msg, pct, db,
          tool=None, et="progress"):
    ws_emit(scan_id, msg, pct,
            tool=tool, event_type=et)
    try:
        ev = ScanEvent(
            scan_id=uuid.UUID(scan_id),
            event_type=et,
            message=msg,
            progress_pct=pct,
            tool=tool,
        )
        db.add(ev)
        db.commit()
    except Exception:
        db.rollback()


@celery_app.task(
    bind=True,
    name="workers.tasks.sast.run_sast_scan",
    queue="sast",
    max_retries=1,
)
def run_sast_scan(
    self, scan_id: str, code_path: str
):
    db = SessionLocal()
    all_findings = []

    def emit(msg, pct, tool=None, et="progress"):
        _emit(scan_id, msg, pct, db,
              tool=tool, et=et)

    try:
        logger.info(
            f"SAST {scan_id} → {code_path}"
        )
        scan = db.query(Scan).filter(
            Scan.id == uuid.UUID(scan_id)
        ).first()
        scan.started_at = datetime.utcnow()
        update_scan_status(
            scan_id, "running", db,
            "Preparing analysis",
        )
        emit("📦 Preparing code analysis...", 3)

        # Language detection
        emit("📝 Detecting languages...", 8,
             tool="lang_detect")
        from packages.scanner.lang_detect \
            import detect_languages
        languages = detect_languages(code_path)
        lang_str = ", ".join(languages) or "unknown"
        emit(
            f"✅ Languages: {lang_str}", 10,
            tool="lang_detect",
        )

        # Semgrep
        from packages.scanner.semgrep_service \
            import SemgrepService
        semgrep_f = SemgrepService().scan(
            code_path, scan_id,
            lambda m, p, **kw: emit(
                m, p, tool="semgrep"
            ),
        )
        all_findings += semgrep_f

        # Gitleaks
        from packages.scanner.gitleaks_service \
            import GitleaksService
        gitleaks_f = GitleaksService().scan(
            code_path, scan_id,
            lambda m, p, **kw: emit(
                m, p, tool="gitleaks"
            ),
        )
        all_findings += gitleaks_f

        # TruffleHog
        from packages.scanner.trufflehog_service \
            import TruffleHogService
        truffle_f = TruffleHogService().scan(
            code_path, scan_id,
            lambda m, p, **kw: emit(
                m, p, tool="trufflehog"
            ),
        )
        all_findings += truffle_f

        # Bandit (Python only)
        if "python" in languages:
            from packages.scanner.bandit_service \
                import BanditService
            bandit_f = BanditService().scan(
                code_path, scan_id,
                lambda m, p, **kw: emit(
                    m, p, tool="bandit"
                ),
            )
            all_findings += bandit_f

        # Trivy
        from packages.scanner.trivy_service \
            import TrivyService
        trivy_f = TrivyService().scan(
            code_path, scan_id,
            lambda m, p, **kw: emit(
                m, p, tool="trivy"
            ),
        )
        all_findings += trivy_f

        # Score + save
        emit("📊 Calculating risk score...", 82)
        score, breakdown = calculate_risk_score(all_findings)
        grade = get_risk_grade(score)

        total_v = len([
            f for f in all_findings
            if f.get("attack_worked")
        ])
        emit(
            f"💾 Saving {len(all_findings)} results...",
            88,
        )
        save_findings(scan_id, all_findings, db)

        # AI fixes
        emit("🤖 Queuing AI fixes...", 93, tool="ai")
        from workers.tasks.ai_tasks \
            import generate_ai_fixes
        generate_ai_fixes.apply_async(
            args=[scan_id], queue="ai", countdown=3
        )

        # Finalize
        start_t = (
            scan.started_at or datetime.utcnow()
        )
        dur = int(
            (datetime.utcnow() -
             start_t).total_seconds()
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
            f"✅ Analysis complete! "
            f"Score: {score}/100 ({grade}) | "
            f"{total_v} vulnerabilities",
            100, et="complete",
        )

    except Exception as e:
        logger.error(
            f"SAST {scan_id} failed: {e}",
            exc_info=True,
        )
        try:
            update_scan(
                scan_id, db,
                status="failed",
                error_message=str(e)[:500],
            )
        except Exception:
            pass
        ws_emit(
            scan_id,
            f"❌ Analysis failed: {str(e)[:100]}",
            0, event_type="error",
        )
    finally:
        db.close()


@celery_app.task(
    bind=True,
    name="workers.tasks.sast.run_github_scan",
    queue="sast",
    max_retries=1,
)
def run_github_scan(
    self,
    scan_id: str,
    ide_session_id: str,
    repo_url: str,
):
    db = SessionLocal()
    all_findings = []

    def emit(msg, pct, tool=None, et="progress"):
        _emit(scan_id, msg, pct, db,
              tool=tool, et=et)

    try:
        scan = db.query(Scan).filter(
            Scan.id == uuid.UUID(scan_id)
        ).first()
        session = db.query(IDESession).filter(
            IDESession.id ==
            uuid.UUID(ide_session_id)
        ).first()

        scan.started_at = datetime.utcnow()
        update_scan_status(
            scan_id, "running", db,
            "Cloning repository",
        )

        # Clone repo
        emit("📥 Cloning repository...", 5,
             tool="git")
        from packages.scanner.github_service \
            import GitHubService
        gh = GitHubService()
        clone_result = gh.clone_repo(
            repo_url, ide_session_id
        )
        code_path = clone_result["clone_path"]

        if session:
            session.clone_path = code_path
            session.file_tree  = \
                clone_result["file_tree"]
            session.file_contents = \
                clone_result["file_contents"]
            session.status = "scanning"
            db.commit()

        emit(
            f"✅ Cloned — "
            f"{len(clone_result['file_contents'])}"
            f" files indexed",
            15, tool="git",
        )

        # Run full SAST on cloned code
        emit("🔍 Running SAST analysis...",
             16, tool="semgrep")

        from packages.scanner.semgrep_service \
            import SemgrepService
        from packages.scanner.gitleaks_service \
            import GitleaksService
        from packages.scanner.trufflehog_service \
            import TruffleHogService
        from packages.scanner.trivy_service \
            import TrivyService
        from packages.scanner.bandit_service \
            import BanditService
        from packages.scanner.lang_detect \
            import detect_languages

        languages = detect_languages(code_path)

        semgrep_f = SemgrepService().scan(
            code_path, scan_id,
            lambda m, p, **kw: emit(
                m, p, tool="semgrep"
            ),
        )
        all_findings += semgrep_f

        gitleaks_f = GitleaksService().scan(
            code_path, scan_id,
            lambda m, p, **kw: emit(
                m, p, tool="gitleaks"
            ),
        )
        all_findings += gitleaks_f

        truffle_f = TruffleHogService().scan(
            code_path, scan_id,
            lambda m, p, **kw: emit(
                m, p, tool="trufflehog"
            ),
        )
        all_findings += truffle_f

        if "python" in languages:
            bandit_f = BanditService().scan(
                code_path, scan_id,
                lambda m, p, **kw: emit(
                    m, p, tool="bandit"
                ),
            )
            all_findings += bandit_f

        trivy_f = TrivyService().scan(
            code_path, scan_id,
            lambda m, p, **kw: emit(
                m, p, tool="trivy"
            ),
        )
        all_findings += trivy_f

        emit("📍 Mapping findings to code lines...",
             75, tool="mapper")

        # Build IDE annotations
        if session:
            _build_ide_annotations(
                session, all_findings,
                clone_result["file_contents"],
                db,
            )

        # Per-file scores
        file_scores = _calculate_file_scores(
            all_findings,
            list(clone_result[
                "file_contents"
            ].keys()),
        )

        score, breakdown = calculate_risk_score(all_findings)
        grade = get_risk_grade(score)

        save_findings(scan_id, all_findings, db)

        if session:
            session.status         = "ready"
            session.security_score = score
            session.file_scores    = file_scores
            session.total_findings = len([
                f for f in all_findings
                if f.get("attack_worked")
            ])
            session.languages_detected = languages
            db.commit()

        from workers.tasks.ai_tasks \
            import generate_ai_fixes
        generate_ai_fixes.apply_async(
            args=[scan_id], queue="ai", countdown=3
        )

        start_t = (
            scan.started_at or datetime.utcnow()
        )
        dur = int(
            (datetime.utcnow() -
             start_t).total_seconds()
        )
        update_scan(
            scan_id, db,
            status="complete",
            risk_score=score,
            risk_grade=grade,
            risk_breakdown=breakdown,
            progress_pct=100,
            completed_at=datetime.utcnow(),
            duration_seconds=dur,
        )
        emit(
            f"✅ GitHub scan complete! "
            f"Score: {score}/100",
            100, et="complete",
        )

    except Exception as e:
        logger.error(
            f"GitHub scan {scan_id} failed: {e}",
            exc_info=True,
        )
        try:
            update_scan(
                scan_id, db,
                status="failed",
                error_message=str(e)[:500],
            )
            if session:
                session.status = "error"
                session.error_message = str(e)[:200]
                db.commit()
        except Exception:
            pass
        ws_emit(
            scan_id,
            f"❌ Failed: {str(e)[:100]}",
            0, event_type="error",
        )
    finally:
        db.close()


def _build_ide_annotations(
    session, findings, file_contents, db
):
    from models.ide import IDEAnnotation

    for f in findings:
        fp = f.get("file_path")
        ln = f.get("line_number")
        if not fp or not ln:
            continue

        # Fuzzy path match
        actual_path = fp
        if fp not in file_contents:
            matches = [
                k for k in file_contents.keys()
                if fp in k or k.endswith(fp)
            ]
            if matches:
                actual_path = matches[0]
            else:
                continue

        ann_type = (
            "error"
            if f.get("severity") in [
                "critical", "high"
            ]
            else "warning"
        )

        ann = IDEAnnotation(
            session_id=session.id,
            file_path=actual_path,
            line_number=ln,
            annotation_type=ann_type,
            vuln_type=f.get("vuln_type", ""),
            severity=f.get("severity", ""),
            message=(
                f"{f.get('vuln_type', '')}: "
                f"{(f.get('description', ''))[:80]}"
            ),
            quick_fix=f.get("quick_fix", ""),
        )
        db.add(ann)

    try:
        db.commit()
    except Exception:
        db.rollback()


def _calculate_file_scores(
    findings: list, all_files: list
) -> dict:
    scores = {}
    for fp in all_files:
        file_findings = [
            f for f in findings
            if f.get("file_path") == fp and
            f.get("attack_worked")
        ]
        if not file_findings:
            scores[fp] = 100
            continue
        deductions = sum(
            {
                "critical": 30,
                "high":     15,
                "medium":    7,
                "low":       3,
            }.get(f.get("severity", "low"), 1)
            for f in file_findings
        )
        scores[fp] = max(0, 100 - deductions)
    return scores


# ── Finding → FindingInput adapter (v3) ────────────

def _convert_to_finding_inputs(
    findings: list,
) -> list:
    """
    Convert raw scanner finding dicts into
    Dev 2's FindingInput Pydantic models.

    This is the adapter bridge between
    Dev 1's scanner output and Dev 2's
    ReviewEngine input contract.

    v3: Now also maps status, diff_context,
    tools[], and change_risk fields.
    """
    from review_engine.schemas.review import (
        FindingInput,
    )

    inputs = []
    for f in findings:
        # Map severity — ensure it matches Dev 2's
        # allowed values: critical|high|medium|low|info
        severity = f.get(
            "severity", "info"
        ).lower()
        if severity not in {
            "critical", "high", "medium",
            "low", "info",
        }:
            severity = "info"

        # v3: Map status
        status = f.get("status", "new")
        if status not in {"new", "existing", "fixed"}:
            status = "new"

        # v3: Map change_risk
        change_risk = f.get(
            "change_risk", "medium"
        )
        if change_risk not in {
            "critical", "high", "medium",
            "low", "none",
        }:
            change_risk = "medium"

        # v3: Map tools array
        tools = f.get("tools", [])
        if not isinstance(tools, list):
            tools = []

        try:
            inp = FindingInput(
                file_path=f.get("file_path"),
                line_number=f.get("line_number"),
                vuln_type=f.get(
                    "vuln_type", "Unknown"
                ),
                severity=severity,
                tool=f.get(
                    "tool_source", "unknown"
                ),
                message=f.get("description", ""),
                cvss_score=f.get("cvss_score"),
                cve_id=f.get("cve_id"),
                cwe_id=f.get("cwe_id"),
                category=f.get("category"),
                code_snippet=f.get("code_snippet"),
                fix=f.get("quick_fix"),
                # v3 fields
                status=status,
                diff_context=f.get("diff_context"),
                tools=tools,
                change_risk=change_risk,
            )
            inputs.append(inp)
        except Exception as e:
            logger.warning(
                f"Skipping finding conversion: {e}"
            )
            continue

    return inputs


# ── PR-specific scan task ──────────────────────────

@celery_app.task(
    bind=True,
    name="workers.tasks.sast.run_pr_scan",
    queue="sast",
    max_retries=1,
)
def run_pr_scan(
    self,
    review_id: str,
    code_path: str,
    changed_lines_map: dict,
    per_file_diffs: dict,
    pr_metadata: dict,
):
    """
    PR-specific scan pipeline.

    Phase 1 — Scan: Run all SAST scanners on full codebase.
    Phase 2 — Transform: Convert findings → FindingInput[].
    Phase 3 — ReviewEngine: Call Dev 2's execute_pr().
    Phase 4 — Publish: POST results to GitHub PR.

    Args:
        review_id: Unique review identifier.
        code_path: Path to cloned repo.
        changed_lines_map: {file: [line_numbers]}.
        per_file_diffs: {file: "unified diff text"}.
        pr_metadata: {owner, repo, pr_number, head_sha, ...}.
    """
    db = SessionLocal()
    all_findings = []

    def emit(msg, pct, tool=None, et="progress"):
        _emit(review_id, msg, pct, db,
              tool=tool, et=et)

    try:
        logger.info(
            f"PR scan {review_id} → "
            f"{pr_metadata.get('owner')}/"
            f"{pr_metadata.get('repo')}"
            f"#{pr_metadata.get('pr_number')} "
            f"at {code_path}"
        )

        emit("📥 PR review scan starting...", 5)

        # ── Phase 1: Run SAST scanners ─────────────
        emit("📝 Detecting languages...", 8,
             tool="lang_detect")
        from packages.scanner.lang_detect \
            import detect_languages
        languages = detect_languages(code_path)
        lang_str = ", ".join(languages) or "unknown"
        emit(
            f"✅ Languages: {lang_str}", 10,
            tool="lang_detect",
        )

        # Semgrep
        from packages.scanner.semgrep_service \
            import SemgrepService
        semgrep_f = SemgrepService().scan(
            code_path, review_id,
            lambda m, p, **kw: emit(
                m, p, tool="semgrep"
            ),
        )
        all_findings += semgrep_f

        # Gitleaks
        from packages.scanner.gitleaks_service \
            import GitleaksService
        gitleaks_f = GitleaksService().scan(
            code_path, review_id,
            lambda m, p, **kw: emit(
                m, p, tool="gitleaks"
            ),
        )
        all_findings += gitleaks_f

        # TruffleHog
        from packages.scanner.trufflehog_service \
            import TruffleHogService
        truffle_f = TruffleHogService().scan(
            code_path, review_id,
            lambda m, p, **kw: emit(
                m, p, tool="trufflehog"
            ),
        )
        all_findings += truffle_f

        # Bandit (Python only)
        if "python" in languages:
            from packages.scanner.bandit_service \
                import BanditService
            bandit_f = BanditService().scan(
                code_path, review_id,
                lambda m, p, **kw: emit(
                    m, p, tool="bandit"
                ),
            )
            all_findings += bandit_f

        # Trivy
        from packages.scanner.trivy_service \
            import TrivyService
        trivy_f = TrivyService().scan(
            code_path, review_id,
            lambda m, p, **kw: emit(
                m, p, tool="trivy"
            ),
        )
        all_findings += trivy_f

        emit(
            f"🔍 Scan complete: "
            f"{len(all_findings)} raw findings",
            60,
        )

        # ── Phase 1.5: Data Intelligence Layer ─────
        emit(
            "🧬 Enriching findings (Phase 1.5)...",
            62,
        )
        from packages.scanner.diff_enrichment import (
            classify_finding_status,
            extract_diff_context,
            compute_change_risk,
            correlate_scanner_findings,
        )
        from review_engine.engine.diff_analyzer import (
            DiffAnalyzer,
        )

        # 1.5a: Pre-correlate multi-tool findings
        all_findings = correlate_scanner_findings(
            all_findings
        )

        # 1.5b: Compute per-file change risk
        change_risk_map = compute_change_risk(
            changed_lines_map, per_file_diffs,
        )

        # 1.5c: Parse diffs for context extraction
        analyzer = DiffAnalyzer()
        parsed_diffs = analyzer.parse(per_file_diffs)

        # 1.5d: Enrich each finding with status,
        #        diff_context, and change_risk
        for f in all_findings:
            f["status"] = classify_finding_status(
                f, changed_lines_map,
            )
            f["diff_context"] = extract_diff_context(
                f, parsed_diffs,
            )
            fp = f.get("file_path", "")
            f["change_risk"] = change_risk_map.get(
                fp, "medium"
            )

        emit(
            f"✅ Enrichment complete: "
            f"{len(all_findings)} findings, "
            f"{len(change_risk_map)} risk-mapped files",
            65,
        )

        # ── Phase 2: Convert to FindingInput ───────
        emit(
            "🔄 Converting findings for review engine...",
            67,
        )
        finding_inputs = _convert_to_finding_inputs(
            all_findings
        )
        emit(
            f"✅ Converted {len(finding_inputs)} "
            f"findings",
            70,
        )

        # ── Phase 3: Call Dev 2's ReviewEngine ─────
        emit(
            "🧠 Running review engine...", 75,
            tool="review_engine",
        )
        from review_engine.schemas.review import (
            ReviewRequest,
        )
        from review_engine.service import ReviewEngine

        review_request = ReviewRequest(
            findings=finding_inputs,
            changed_lines=changed_lines_map,
            diffs=per_file_diffs,
            change_risk=change_risk_map,
        )

        engine = ReviewEngine()
        result = engine.execute_pr(review_request)

        emit(
            f"✅ Review complete: "
            f"score={result.score.total_score}, "
            f"decision={result.decision.decision.value}, "
            f"{len(result.comments)} comments",
            85,
            tool="review_engine",
        )

        # ── Phase 4: Publish to GitHub ─────────────
        emit(
            "📤 Publishing to GitHub...", 88,
            tool="github",
        )
        from packages.scanner.github_publisher \
            import GitHubPublisher

        publisher = GitHubPublisher()
        owner = pr_metadata.get("owner", "")
        repo = pr_metadata.get("repo", "")
        pr_number = pr_metadata.get("pr_number", 0)
        head_sha = pr_metadata.get("head_sha", "")

        # Post inline review
        if result.pr_review:
            try:
                publisher.post_pr_review(
                    owner, repo, pr_number,
                    head_sha, result.pr_review,
                )
                emit(
                    f"✅ Posted {len(result.pr_review.comments)} "
                    f"inline review comments",
                    92,
                    tool="github",
                )
            except Exception as pub_err:
                logger.error(
                    f"PR review publish failed: "
                    f"{pub_err}",
                    exc_info=True,
                )
                emit(
                    f"⚠️ Failed to post inline review: "
                    f"{str(pub_err)[:100]}",
                    92,
                    tool="github",
                )

        # Post summary comment
        if result.summary_markdown:
            try:
                publisher.post_summary_comment(
                    owner, repo, pr_number,
                    result.summary_markdown,
                )
                emit(
                    "✅ Posted summary comment",
                    95,
                    tool="github",
                )
            except Exception as sum_err:
                logger.error(
                    f"Summary comment failed: "
                    f"{sum_err}",
                    exc_info=True,
                )

        # ── Finalize ───────────────────────────────
        emit(
            f"✅ PR review complete! "
            f"Score: {result.score.total_score}/100 | "
            f"Decision: {result.decision.decision.value} | "
            f"{result.relevant_count} relevant, "
            f"{result.contextual_count} contextual, "
            f"{result.unrelated_count} filtered out",
            100, et="complete",
        )

    except Exception as e:
        logger.error(
            f"PR scan {review_id} failed: {e}",
            exc_info=True,
        )
        ws_emit(
            review_id,
            f"❌ PR review failed: {str(e)[:100]}",
            0, event_type="error",
        )
    finally:
        db.close()

