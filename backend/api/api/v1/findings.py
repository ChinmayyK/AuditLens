import uuid
from datetime import datetime
from typing import Optional

from fastapi import (
    APIRouter, Depends, HTTPException,
    BackgroundTasks,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from models.base import get_db
from models.scan import Finding, Scan
from models.user import User
from core.dependencies import get_current_user

router = APIRouter(
    prefix="/api/v1/findings",
    tags=["findings"],
)


@router.get("/{finding_id}")
async def get_finding(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(
        Finding.id == uuid.UUID(finding_id)
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    # Verify ownership via scan
    scan = db.query(Scan).filter(
        Scan.id == finding.scan_id,
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(403, "Access denied")

    return _finding_to_dict(finding)


@router.get("/{finding_id}/fix")
async def get_finding_fix(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(
        Finding.id == uuid.UUID(finding_id)
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    scan = db.query(Scan).filter(
        Scan.id == finding.scan_id,
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(403, "Access denied")

    if not finding.ai_fix:
        # Trigger async generation
        from workers.tasks.ai_tasks \
            import generate_ai_fixes
        generate_ai_fixes.apply_async(
            args=[str(finding.scan_id)],
            queue="ai",
            countdown=1,
        )
        return {
            "status":      "generating",
            "message":     "AI fix is being generated",
            "retry_after": 5,
            "ai_fix":      None,
            "waf_rule":    finding.waf_rule,
        }

    return {
        "status":   "ready",
        "ai_fix":   finding.ai_fix,
        "waf_rule": finding.waf_rule,
        "finding":  _finding_to_dict(finding),
    }


@router.post("/{finding_id}/mark-fixed")
async def mark_fixed(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    finding = db.query(Finding).filter(
        Finding.id == uuid.UUID(finding_id)
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    scan = db.query(Scan).filter(
        Scan.id == finding.scan_id,
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(403, "Access denied")

    finding.marked_fixed_at = datetime.utcnow()
    finding.fix_verified = False
    db.commit()

    return {"status": "marked_fixed",
            "finding_id": finding_id}


@router.post("/{finding_id}/verify-fix")
async def verify_fix(
    finding_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """
    Re-run the specific attack for this finding
    to confirm the fix worked.
    Phase 14+ expands with real re-test logic.
    """
    finding = db.query(Finding).filter(
        Finding.id == uuid.UUID(finding_id)
    ).first()
    if not finding:
        raise HTTPException(404, "Finding not found")

    scan = db.query(Scan).filter(
        Scan.id == finding.scan_id,
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(403, "Access denied")

    # For header/cookie findings:
    # re-check the specific header right now
    if finding.tool_source in [
        "native_header_check", "cookie_checker",
        "ssl_audit",
    ] and finding.url:
        try:
            import requests
            resp = requests.get(
                finding.url, timeout=8,
                verify=False,
            )
            headers = {
                k.lower(): v
                for k, v in resp.headers.items()
            }

            # Check if the specific header now exists
            if finding.vuln_type.lower().startswith(
                "missing"
            ):
                header_map = {
                    "missing x-frame-options":
                        "x-frame-options",
                    "missing content-security-policy":
                        "content-security-policy",
                    "missing hsts":
                        "strict-transport-security",
                    "missing x-content-type-options":
                        "x-content-type-options",
                }
                for vt, hdr in header_map.items():
                    if vt in finding.vuln_type.lower():
                        if hdr in headers:
                            finding.fix_verified = True
                            finding.fix_verified_at = \
                                datetime.utcnow()
                            db.commit()
                            return {
                                "still_vulnerable":
                                    False,
                                "message":
                                    f"✅ Fix confirmed! "
                                    f"{hdr} is now present.",
                            }
                        else:
                            return {
                                "still_vulnerable":
                                    True,
                                "message":
                                    f"❌ Still vulnerable. "
                                    f"{hdr} not found.",
                            }
        except Exception as e:
            return {
                "still_vulnerable": None,
                "message":
                    f"Could not verify: {str(e)[:100]}",
            }

    # Generic response for other finding types
    return {
        "still_vulnerable": None,
        "message":
            "Manual verification required for "
            "this finding type. Re-run the full "
            "scan to confirm.",
    }


@router.get("/scan/{scan_id}/waf-rules")
async def download_waf_rules(
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
        Finding.waf_rule != None,
    ).all()

    from packages.ai.waf_service import WAFService
    conf_content = WAFService().build_full_conf(
        scan, findings
    )

    import os, tempfile
    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".conf", delete=False
    )
    tmp.write(conf_content)
    tmp.close()

    return FileResponse(
        tmp.name,
        filename=f"shieldsentinel_waf_rules.conf",
        media_type="text/plain",
    )


def _finding_to_dict(f: Finding) -> dict:
    return {
        "id":             str(f.id),
        "scan_id":        str(f.scan_id),
        "vuln_type":      f.vuln_type,
        "severity":       f.severity,
        "cvss_score":     f.cvss_score,
        "owasp_category": f.owasp_category,
        "url":            f.url,
        "parameter":      f.parameter,
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
        "breach_examples":
            f.ai_fix.get("breach_examples", [])
            if f.ai_fix else [],
        "ai_fix":         f.ai_fix,
        "waf_rule":       f.waf_rule,
        "quick_fix":      f.quick_fix,
        "fix_verified":   f.fix_verified,
        "marked_fixed_at":
            f.marked_fixed_at.isoformat()
            if f.marked_fixed_at else None,
        "created_at":     f.created_at.isoformat(),
    }
