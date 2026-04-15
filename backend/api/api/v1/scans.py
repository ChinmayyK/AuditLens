import os
import uuid
import zipfile
import shutil
from datetime import datetime
from typing import Optional

from fastapi import (
    APIRouter, Depends, HTTPException,
    UploadFile, File, Form, status, BackgroundTasks,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import desc
import redis as sync_redis
import logging

logger = logging.getLogger(__name__)

from models.base import get_db
from models.scan import Scan, Finding, ScanEvent, AttackSurface
from models.user import User
from models.ide import IDESession
from schemas.scan import (
    UrlScanRequest, GitHubScanRequest,
    ScanResponse, ScanDetailResponse,
)
from core.dependencies import get_current_user
from core.db_helpers import (
    calculate_risk_score, get_risk_grade,
    get_findings_summary,
)
from workers.celery_app import celery_app

router = APIRouter(prefix="/api/v1/scans", tags=["scans"])

UPLOAD_DIR = os.getenv(
    "UPLOAD_DIR", "/tmp/shieldsentinel/uploads"
)
MAX_ZIP_SIZE = 100 * 1024 * 1024  # 100MB


def _invalidate_dashboard_cache(user_id) -> None:
    """Best-effort cache bust when scan data changes."""
    try:
        redis_client = sync_redis.from_url(
            os.getenv("REDIS_URL", "redis://redis:6379/0"),
            decode_responses=True,
        )
        redis_client.delete(f"dashboard:{user_id}")
        redis_client.close()
    except Exception:
        logger.debug(
            "Skipping dashboard cache invalidation",
            exc_info=True,
        )


@router.get("/compare")
async def compare_scans(
    scan1: str,
    scan2: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    s1 = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan1),
        Scan.user_id == current_user.id,
    ).first()
    s2 = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan2),
        Scan.user_id == current_user.id,
    ).first()

    if not s1 or not s2:
        raise HTTPException(404, "Scan not found")

    def scan_summary(scan: Scan):
        findings = db.query(Finding).filter(
            Finding.scan_id == scan.id,
            Finding.attack_worked == True,
        ).all()
        return {
            "id": str(scan.id),
            "target": scan.target,
            "risk_score": scan.risk_score or 0,
            "risk_grade": scan.risk_grade or "F",
            "created_at": scan.created_at.isoformat(),
            "summary": {
                "critical": sum(1 for f in findings if f.severity == "critical"),
                "high": sum(1 for f in findings if f.severity == "high"),
                "medium": sum(1 for f in findings if f.severity == "medium"),
                "low": sum(1 for f in findings if f.severity == "low"),
                "total": len(findings),
            },
            "vuln_types": list({f.vuln_type for f in findings}),
        }

    data1 = scan_summary(s1)
    data2 = scan_summary(s2)

    if s1.created_at > s2.created_at:
        data1, data2 = data2, data1

    score_change = data2["risk_score"] - data1["risk_score"]
    crit_change = data2["summary"]["critical"] - data1["summary"]["critical"]
    high_change = data2["summary"]["high"] - data1["summary"]["high"]
    med_change = data2["summary"]["medium"] - data1["summary"]["medium"]

    types1 = set(data1["vuln_types"])
    types2 = set(data2["vuln_types"])
    fixed_vulns = list(types1 - types2)
    new_vulns = list(types2 - types1)

    return {
        "scan1": data1,
        "scan2": data2,
        "diff": {
            "score_change": score_change,
            "critical_change": crit_change,
            "high_change": high_change,
            "medium_change": med_change,
            "fixed_vulns": fixed_vulns[:10],
            "new_vulns": new_vulns[:10],
        },
    }


def _scan_to_detail(scan: Scan,
                    db: Session) -> dict:
    summary = get_findings_summary(str(scan.id), db)
    return {
        "id":               str(scan.id),
        "scan_type":        scan.scan_type,
        "target":           scan.target,
        "status":           scan.status,
        "intensity":        scan.intensity,
        "risk_score":       scan.risk_score,
        "risk_grade":       scan.risk_grade,
        "progress_pct":     scan.progress_pct,
        "current_phase":    scan.current_phase,
        "error_message":    scan.error_message,
        "created_at":       scan.created_at.isoformat(),
        "started_at":       scan.started_at.isoformat()
                            if scan.started_at else None,
        "completed_at":     scan.completed_at.isoformat()
                            if scan.completed_at else None,
        "duration_seconds": scan.duration_seconds,
        "open_ports":       scan.open_ports,
        "subdomains":       scan.subdomains,
        "tech_stack":       scan.tech_stack,
        "os_guess":         scan.os_guess,
        "cdn_detected":     scan.cdn_detected,
        "waf_detected":     scan.waf_detected,
        "waf_name":         scan.waf_name,
        "summary":          summary,
        "celery_task_id":   scan.celery_task_id,
    }


# ── POST /api/v1/scans/url ────────────────────────────
@router.post("/url", response_model=ScanResponse)
async def start_url_scan(
    payload: UrlScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    try:
        scan = Scan(
            user_id=current_user.id,
            scan_type="url",
            target=payload.target_url,
            intensity=payload.intensity,
            ownership_confirmed=payload.ownership_confirmed,
            estimated_asset_value=payload.estimated_asset_value,
            status="queued",
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        _invalidate_dashboard_cache(current_user.id)

        # Queue Celery task
        try:
            task = celery_app.send_task(
                "workers.tasks.dast.run_url_scan",
                args=[str(scan.id), payload.target_url,
                      payload.intensity],
                queue="dast",
            )
            scan.celery_task_id = task.id
            db.commit()
        except Exception as celery_err:
            logger.error(f"Celery failure: {celery_err}")
            raise celery_err

        return ScanResponse(
            scan_id=str(scan.id),
            status="queued",
            message="URL scan queued successfully",
            scan_type="url",
        )
    except Exception as e:
        logger.error(f"Scan initialization failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Scan initialization failed: {str(e)}"
        )


# ── POST /api/v1/scans/zip ────────────────────────────
@router.post("/zip", response_model=ScanResponse)
async def start_zip_scan(
    file: UploadFile = File(...),
    ownership_confirmed: str = Form("false"),
    estimated_asset_value: Optional[str] = Form(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Validate
    if ownership_confirmed.lower() != "true":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You must confirm ownership"
        )
    if not file.filename or not \
       file.filename.endswith(".zip"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .zip files are accepted"
        )

    # Read and size-check
    content = await file.read()
    if len(content) > MAX_ZIP_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="File too large. Maximum 100MB"
        )

    # Save and extract
    scan_id = uuid.uuid4()
    scan_dir = os.path.join(UPLOAD_DIR, str(scan_id))
    os.makedirs(scan_dir, exist_ok=True)

    zip_path = os.path.join(scan_dir, "upload.zip")
    with open(zip_path, "wb") as f:
        f.write(content)

    code_path = os.path.join(scan_dir, "code")
    os.makedirs(code_path, exist_ok=True)

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            # Security: check for path traversal in zip
            for name in zf.namelist():
                if ".." in name or name.startswith("/"):
                    raise HTTPException(
                        status_code=400,
                        detail="Invalid zip file contents"
                    )
            zf.extractall(code_path)
        file_count = sum(
            1 for _, _, files in os.walk(code_path)
            for _ in files
        )
    except zipfile.BadZipFile:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or corrupted zip file"
        )

    asset_val = None
    if estimated_asset_value:
        try:
            asset_val = int(estimated_asset_value)
        except ValueError:
            pass

    scan = Scan(
        id=scan_id,
        user_id=current_user.id,
        scan_type="zip",
        target=file.filename,
        intensity="standard",
        ownership_confirmed=True,
        estimated_asset_value=asset_val,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _invalidate_dashboard_cache(current_user.id)

    task = celery_app.send_task(
        "workers.tasks.sast.run_sast_scan",
        args=[str(scan.id), code_path],
        queue="sast",
    )
    scan.celery_task_id = task.id
    db.commit()

    return ScanResponse(
        scan_id=str(scan.id),
        status="queued",
        message=f"ZIP scan queued — {file_count} files found",
        scan_type="zip",
    )


# ── POST /api/v1/scans/github ─────────────────────────
@router.post("/github", response_model=ScanResponse)
async def start_github_scan(
    payload: GitHubScanRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    # Extract repo name
    clean_repo = payload.repo_url.rstrip("/")
    if clean_repo.endswith(".git"):
        clean_repo = clean_repo[:-4]
    parts = clean_repo.replace(
        "https://", ""
    ).replace("http://", "").rstrip("/").split("/")
    repo_name = f"{parts[1]}/{parts[2]}" \
        if len(parts) >= 3 else payload.repo_url

    scan = Scan(
        user_id=current_user.id,
        scan_type="github",
        target=repo_name,
        intensity="standard",
        ownership_confirmed=payload.ownership_confirmed,
        estimated_asset_value=payload.estimated_asset_value,
        status="queued",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    _invalidate_dashboard_cache(current_user.id)

    # Create IDE session linked to this scan
    ide_session = IDESession(
        user_id=current_user.id,
        scan_id=scan.id,
        source_type="github",
        repo_url=payload.repo_url,
        repo_name=repo_name,
        status="cloning",
    )
    db.add(ide_session)
    db.commit()
    db.refresh(ide_session)

    task = celery_app.send_task(
        "workers.tasks.sast.run_github_scan",
        args=[str(scan.id), str(ide_session.id),
              payload.repo_url],
        queue="sast",
    )
    scan.celery_task_id = task.id
    db.commit()

    return {
        "scan_id":        str(scan.id),
        "ide_session_id": str(ide_session.id),
        "status":         "queued",
        "message":        f"GitHub scan queued for {repo_name}",
        "scan_type":      "github",
    }


# ── GET /api/v1/scans ─────────────────────────────────
@router.get("")
async def list_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 20,
    offset: int = 0,
):
    scans = db.query(Scan).filter(
        Scan.user_id == current_user.id
    ).order_by(desc(Scan.created_at)).offset(
        offset
    ).limit(limit).all()

    return {
        "scans": [_scan_to_detail(s, db) for s in scans],
        "total": db.query(Scan).filter(
            Scan.user_id == current_user.id
        ).count(),
    }


# ── GET /api/v1/scans/{scan_id}/attack-surface ───────
@router.get("/{scan_id}/attack-surface")
async def get_attack_surface(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    surface = db.query(AttackSurface).filter(
        AttackSurface.scan_id == uuid.UUID(scan_id)
    ).first()

    if not surface:
        return {"nodes": [], "edges": []}

    return {
        "nodes": surface.nodes or [],
        "edges": surface.edges or [],
        "api_endpoints":
            surface.api_endpoints or [],
        "total_urls":
            len(surface.discovered_urls or []),
    }


@router.get("/{scan_id}/heatmap")
async def get_heatmap(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings = db.query(Finding).filter(
        Finding.scan_id == uuid.UUID(scan_id),
        Finding.attack_worked == True,
    ).all()

    owasp_counts: dict[str, int] = {}
    for i in range(1, 11):
        code = f"A{i:02d}"
        owasp_counts[code] = 0

    for f in findings:
        cat = f.owasp_category or ""
        for code in owasp_counts:
            if code in cat:
                owasp_counts[code] += 1
                break

    owasp_list = [{"code": code, "count": count} for code, count in owasp_counts.items()]

    timeline = []
    if findings and scan.started_at and scan.completed_at:
        total_secs = (scan.completed_at - scan.started_at).total_seconds()
        if total_secs > 0:
            for f in sorted(findings, key=lambda x: x.created_at):
                offset = (f.created_at - scan.started_at).total_seconds()
                pct = min(100, int((offset / total_secs) * 100))
                timeline.append(
                    {
                        "pct": pct,
                        "tool": f.tool_source or "",
                        "vuln_type": f.vuln_type,
                        "severity": f.severity,
                    }
                )

    return {
        "owasp_counts": owasp_list,
        "timeline": timeline,
    }


@router.get("/ide/{session_id}")
async def get_ide_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(IDESession).filter(
        IDESession.id == uuid.UUID(session_id),
        IDESession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(404, "IDE session not found")

    scan = None
    if session.scan_id:
        scan = db.query(Scan).filter(
            Scan.id == session.scan_id,
            Scan.user_id == current_user.id,
        ).first()

    return {
        "id": str(session.id),
        "status": session.status,
        "error_message": session.error_message,
        "source_type": session.source_type,
        "repo_url": session.repo_url,
        "repo_name": session.repo_name,
        "scan_id": str(session.scan_id) if session.scan_id else None,
        "security_score": session.security_score,
        "total_findings": session.total_findings,
        "languages_detected": session.languages_detected or [],
        "file_tree": session.file_tree or [],
        "file_scores": session.file_scores or {},
        "file_count": len(session.file_contents or {}),
        "scan_status": scan.status if scan else None,
        "created_at": session.created_at.isoformat(),
        "updated_at": session.updated_at.isoformat()
        if session.updated_at else None,
    }


# ── GET /api/v1/scans/{scan_id} ───────────────────────
@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    return _scan_to_detail(scan, db)


# ── GET /api/v1/scans/{scan_id}/events ────────────────
@router.get("/{scan_id}/events")
async def get_scan_events(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 200,
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    events = db.query(ScanEvent).filter(
        ScanEvent.scan_id == uuid.UUID(scan_id)
    ).order_by(ScanEvent.created_at).limit(limit).all()

    return {
        "events": [
            {
                "id":           str(e.id),
                "event_type":   e.event_type,
                "message":      e.message,
                "progress_pct": e.progress_pct,
                "tool":         e.tool,
                "target_url":   e.target_url,
                "result":       e.result,
                "created_at":   e.created_at.isoformat(),
            }
            for e in events
        ]
    }


# ── GET /api/v1/scans/{scan_id}/findings ──────────────
@router.get("/{scan_id}/findings")
async def get_findings(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    severity: Optional[str] = None,
    attacked: Optional[bool] = None,
    tool: Optional[str] = None,
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    q = db.query(Finding).filter(
        Finding.scan_id == uuid.UUID(scan_id)
    )

    if severity:
        q = q.filter(Finding.severity == severity)
    if attacked is not None:
        q = q.filter(Finding.attack_worked == attacked)
    if tool:
        q = q.filter(Finding.tool_source == tool)

    # Sort: critical first
    SEV_ORDER = {
        "critical": 0, "high": 1,
        "medium": 2, "low": 3, "info": 4,
    }

    findings = q.all()
    findings.sort(
        key=lambda f: SEV_ORDER.get(f.severity, 5)
    )

    return {
        "scan":    _scan_to_detail(scan, db),
        "findings": [
            {
                "id":             str(f.id),
                "vuln_type":      f.vuln_type,
                "severity":       f.severity,
                "cvss_score":     f.cvss_score,
                "owasp_category": f.owasp_category,
                "url":            f.url,
                "parameter":      f.parameter,
                "http_method":    f.http_method,
                "file_path":      f.file_path,
                "line_number":    f.line_number,
                "code_snippet":   f.code_snippet,
                "tool_source":    f.tool_source,
                "attack_payload": f.attack_payload,
                "attack_worked":  f.attack_worked,
                "was_attempted":  f.was_attempted,
                "attack_name":    f.attack_name,
                "evidence":       f.evidence,
                "description":    f.description,
                "layman_explanation": f.layman_explanation,
                "money_loss_min": f.money_loss_min,
                "money_loss_max": f.money_loss_max,
                "breach_examples":f.breach_examples,
                "ai_fix":         f.ai_fix,
                "waf_rule":       f.waf_rule,
                "quick_fix":      f.quick_fix,
                "correlated_finding_id":
                    str(f.correlated_finding_id)
                    if f.correlated_finding_id else None,
                "correlation_message": f.correlation_message,
                "fix_verified":   f.fix_verified,
                "created_at":     f.created_at.isoformat(),
            }
            for f in findings
        ],
    }


# ── POST /api/v1/scans/{scan_id}/cancel ────────────────
@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    if scan.status not in ["queued", "running"]:
        return {
            "status": scan.status,
            "message": "Scan cannot be cancelled in current state"
        }

    if scan.celery_task_id:
        # Stop the celery worker task
        celery_app.control.revoke(
            scan.celery_task_id, terminate=True
        )

    scan.status = "failed" # Use 'failed' or 'cancelled'
    scan.current_phase = "Cancelled by User"
    scan.error_message = "Scan was manually cancelled"
    db.commit()
    _invalidate_dashboard_cache(current_user.id)

    from core.websocket import ws_emit
    ws_emit(
        str(scan.id),
        "🛑 Scan cancelled by user",
        scan.progress_pct or 0,
        event_type="error",
    )

    return {"status": "cancelled"}


# ── DELETE /api/v1/scans/{scan_id} ────────────────────
@router.delete("/{scan_id}")
async def delete_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    db.delete(scan)
    db.commit()
    _invalidate_dashboard_cache(current_user.id)
    return {"status": "deleted"}
