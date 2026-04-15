import os
import uuid
import json
import tempfile
from datetime import datetime

from fastapi import (
    APIRouter, Depends, HTTPException,
)
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.orm import Session

from models.base import get_db
from models.scan import Scan, Finding
from models.user import User
from core.dependencies import get_current_user

router = APIRouter(
    prefix="/api/v1/reports",
    tags=["reports"],
)

REPORTS_DIR = os.getenv(
    "REPORTS_DIR",
    "/tmp/shieldsentinel/reports",
)


def _get_scan_and_findings(
    scan_id: str,
    current_user: User,
    db: Session,
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan.status != "complete":
        raise HTTPException(
            400, "Scan not complete yet"
        )
    findings = db.query(Finding).filter(
        Finding.scan_id == uuid.UUID(scan_id)
    ).all()
    return scan, findings


@router.get("/{scan_id}/pdf")
async def download_pdf(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan, findings = _get_scan_and_findings(
        scan_id, current_user, db
    )

    os.makedirs(REPORTS_DIR, exist_ok=True)
    pdf_path = os.path.join(
        REPORTS_DIR, f"{scan_id}.pdf"
    )

    if not os.path.exists(pdf_path):
        findings_dicts = [
            {
                "vuln_type":   f.vuln_type,
                "severity":    f.severity,
                "url":         f.url,
                "file_path":   f.file_path,
                "line_number": f.line_number,
                "owasp_category": f.owasp_category,
                "tool_source": f.tool_source,
                "evidence":    f.evidence,
                "description": f.description,
                "attack_worked": f.attack_worked,
                "was_attempted": f.was_attempted,
                "ai_fix":      f.ai_fix,
                "cvss_score":  f.cvss_score,
                "money_loss_min": f.money_loss_min,
                "money_loss_max": f.money_loss_max,
            }
            for f in findings
        ]

        from packages.reports.pdf_service \
            import generate_pdf_report
        generate_pdf_report(
            scan, findings_dicts, pdf_path
        )

    short_id = scan_id[:8]
    return FileResponse(
        pdf_path,
        filename=f"shieldsentinel-{short_id}.pdf",
        media_type="application/pdf",
        headers={
            "Content-Disposition":
                f'attachment; filename='
                f'"shieldsentinel-{short_id}.pdf"',
        },
    )


@router.get("/{scan_id}/json")
async def export_json(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan, findings = _get_scan_and_findings(
        scan_id, current_user, db
    )

    findings_list = []
    for f in findings:
        findings_list.append({
            "id":          str(f.id),
            "vuln_type":   f.vuln_type,
            "severity":    f.severity,
            "cvss_score":  f.cvss_score,
            "cve_id":      f.cve_id,
            "owasp":       f.owasp_category,
            "url":         f.url,
            "parameter":   f.parameter,
            "file_path":   f.file_path,
            "line_number": f.line_number,
            "tool":        f.tool_source,
            "attack_worked": f.attack_worked,
            "was_attempted": f.was_attempted,
            "evidence":    f.evidence,
            "description": f.description,
            "ai_fix":      f.ai_fix,
            "waf_rule":    f.waf_rule,
            "money_loss_min": f.money_loss_min,
            "money_loss_max": f.money_loss_max,
        })

    report = {
        "generated_at":
            datetime.utcnow().isoformat(),
        "tool":    "ShieldSentinel v1.0",
        "scan": {
            "id":          str(scan.id),
            "target":      scan.target,
            "scan_type":   scan.scan_type,
            "intensity":   scan.intensity,
            "status":      scan.status,
            "risk_score":  scan.risk_score,
            "risk_grade":  scan.risk_grade,
            "created_at":  scan.created_at.isoformat(),
            "completed_at":
                scan.completed_at.isoformat()
                if scan.completed_at else None,
            "duration_seconds": scan.duration_seconds,
            "tech_stack":  scan.tech_stack,
            "open_ports":  scan.open_ports,
        },
        "summary": {
            "total":     len(findings_list),
            "critical":  sum(
                1 for f in findings_list
                if f["severity"] == "critical" and
                f["attack_worked"]
            ),
            "high":      sum(
                1 for f in findings_list
                if f["severity"] == "high" and
                f["attack_worked"]
            ),
            "medium":    sum(
                1 for f in findings_list
                if f["severity"] == "medium" and
                f["attack_worked"]
            ),
            "low":       sum(
                1 for f in findings_list
                if f["severity"] == "low" and
                f["attack_worked"]
            ),
        },
        "findings": findings_list,
    }

    tmp = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json",
        delete=False,
    )
    json.dump(report, tmp, indent=2,
              default=str)
    tmp.close()

    short_id = scan_id[:8]
    return FileResponse(
        tmp.name,
        filename=
            f"shieldsentinel-report-{short_id}.json",
        media_type="application/json",
    )


@router.get("/{scan_id}/compliance")
async def get_compliance(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan, findings = _get_scan_and_findings(
        scan_id, current_user, db
    )

    findings_dicts = [
        {
            "vuln_type":    f.vuln_type,
            "severity":     f.severity,
            "attack_worked": f.attack_worked,
        }
        for f in findings
    ]

    from packages.scanner.compliance_service \
        import calculate_compliance
    result = calculate_compliance(
        scan_id, findings_dicts
    )

    # Cache in DB
    from models.scan import ComplianceResult
    existing = db.query(ComplianceResult).filter(
        ComplianceResult.scan_id ==
        uuid.UUID(scan_id)
    ).first()

    if not existing:
        cr = ComplianceResult(
            scan_id=uuid.UUID(scan_id),
            owasp_score=result["scores"]["owasp"],
            pci_dss_score=result["scores"]["pci_dss"],
            hipaa_score=result["scores"]["hipaa"],
            gdpr_score=result["scores"]["gdpr"],
            owasp_breakdown=result["owasp_breakdown"],
            pci_dss_gaps=result["pci_dss_gaps"],
            hipaa_gaps=result["hipaa_gaps"],
            gdpr_gaps=result["gdpr_gaps"],
        )
        db.add(cr)
        db.commit()

    return result
