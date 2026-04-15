import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from models.scan import Scan, Finding, ScanEvent
from models.user import User


def get_scan(scan_id: str, db: Session,
             user_id: str = None) -> Optional[Scan]:
    q = db.query(Scan).filter(Scan.id == uuid.UUID(scan_id))
    if user_id:
        q = q.filter(Scan.user_id == uuid.UUID(user_id))
    return q.first()


def update_scan(scan_id: str, db: Session, **kwargs):
    db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id)
    ).update(kwargs)
    db.commit()


def update_scan_status(scan_id: str, status: str,
                       db: Session, phase: str = None):
    updates = {"status": status}
    if phase:
        updates["current_phase"] = phase
    if status == "running" and not db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id)
    ).first().started_at:
        updates["started_at"] = datetime.utcnow()
    db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id)
    ).update(updates)
    db.commit()


def save_findings(scan_id: str, findings: list,
                  db: Session):
    for f in findings:
        finding = Finding(
            scan_id=uuid.UUID(scan_id),
            vuln_type=f.get("vuln_type", "Unknown"),
            category=f.get("category"),
            severity=f.get("severity", "info"),
            cvss_score=f.get("cvss_score"),
            cve_id=f.get("cve_id"),
            cwe_id=f.get("cwe_id"),
            owasp_category=f.get("owasp_category"),
            url=f.get("url"),
            parameter=f.get("parameter"),
            http_method=f.get("http_method"),
            file_path=f.get("file_path"),
            line_number=f.get("line_number"),
            code_snippet=f.get("code_snippet"),
            tool_source=f.get("tool_source"),
            attack_payload=f.get("attack_payload"),
            attack_worked=f.get("attack_worked", False),
            was_attempted=f.get("was_attempted", True),
            request_sent=f.get("request_sent"),
            response_received=f.get("response_received"),
            attack_name=f.get("attack_name"),
            evidence=f.get("evidence"),
            description=f.get("description"),
            layman_explanation=f.get("layman_explanation"),
            money_loss_min=f.get("money_loss_min"),
            money_loss_max=f.get("money_loss_max"),
            breach_examples=f.get("breach_examples"),
            quick_fix=f.get("quick_fix"),
        )
        db.add(finding)
    db.commit()


def emit_event(scan_id: str, event_type: str,
               message: str, db: Session,
               progress_pct: int = None,
               tool: str = None,
               target_url: str = None,
               result: str = None,
               metadata: dict = None):
    event = ScanEvent(
        scan_id=uuid.UUID(scan_id),
        event_type=event_type,
        message=message,
        progress_pct=progress_pct,
        tool=tool,
        target_url=target_url,
        result=result,
        metadata_=metadata,
    )
    db.add(event)
    db.commit()
    return event


def calculate_risk_score(findings: list) -> tuple[int, list]:
    """
    Score 0-100. Higher = more secure.
    Returns (score, breakdown)
    """
    if not findings:
        return 100, []

    # Only confirmed exploitable / positive findings lower the score
    active = [
        f for f in findings
        if f.get("attack_worked") is True
    ]

    breakdown = []
    deductions = 0
    
    # We group by vuln_type to avoid double-charging if multiple URLs have same bug
    # (Optional: user's choice, but grouping makes the explainer cleaner)
    seen_vulns = {}
    for f in active:
        v_type = f.get("vuln_type", "Unknown")
        sev = f.get("severity", "low").lower()
        
        points = {
            "critical": 20,
            "high":     14,
            "medium":    7,
            "low":       3,
            "info":      0,
        }.get(sev, 0)
        
    # Group findings by tool to implement tool-based capping
    tool_deductions = {}
    
    for f in active:
        v_type = f.get("vuln_type", "Unknown")
        sev = f.get("severity", "low").lower()
        tool = f.get("tool_source", "generic")
        
        points = {
            "critical": 20,
            "high":     14,
            "medium":    7,
            "low":       3,
            "info":      0,
        }.get(sev, 0)
        
        if v_type not in seen_vulns:
            seen_vulns[v_type] = {
                "points": points, 
                "count": 1, 
                "severity": sev,
                "tool": tool
            }
        else:
            seen_vulns[v_type]["count"] += 1
            is_noise_prone = any(x in v_type.lower() for x in ["path", "file exposed", "enumeration", "timestamp"])
            max_count_before_cap = 3 if is_noise_prone else 15
            
            if seen_vulns[v_type]["count"] <= max_count_before_cap:
                seen_vulns[v_type]["points"] += 1 

    # Now calculate deductions per tool and total
    for v_type, data in seen_vulns.items():
        tool = data["tool"]
        
        # Category cap
        is_high_noise = any(x in v_type.lower() for x in ["path", "exposed", "timestamp"])
        category_max = 10 if is_high_noise else 25
        actual_cat_deduction = min(data["points"], category_max if data["severity"] != "critical" else 35)
        
        # Tool cap (accumulated)
        if tool not in tool_deductions:
            tool_deductions[tool] = 0
            
        # If this tool has already deducted too much, we taper off
        # FFUF and ZAP are the most noisy
        tool_max = 25 if tool in ["ffuf", "zap"] else 50
        
        if tool_deductions[tool] < tool_max:
            # How much can this category still deduct?
            remaining_tool_quota = tool_max - tool_deductions[tool]
            deduction_to_add = min(actual_cat_deduction, remaining_tool_quota)
            
            tool_deductions[tool] += deduction_to_add
            deductions += deduction_to_add
            
            breakdown.append({
                "name": v_type,
                "deduction": deduction_to_add,
                "severity": data["severity"],
                "count": data["count"],
                "tool": tool
            })
        else:
            # Tool quota reached, still show it in breakdown but with 0 deduction
            breakdown.append({
                "name": v_type,
                "deduction": 0,
                "severity": data["severity"],
                "count": data["count"],
                "tool": tool,
                "note": "Capped due to tool noise limits"
            })

    breakdown.sort(key=lambda x: x["deduction"], reverse=True)
    final_score = max(0, min(100, 100 - deductions))
    return int(final_score), breakdown


def get_risk_grade(score: int) -> str:
    if score >= 90: return "A+"
    if score >= 80: return "A"
    if score >= 70: return "B"
    if score >= 60: return "C"
    if score >= 50: return "D"
    return "F"


def get_findings_summary(scan_id: str,
                          db: Session) -> dict:
    findings = db.query(Finding).filter(
        Finding.scan_id == uuid.UUID(scan_id)
    ).all()

    summary = {
        "critical": 0, "high": 0,
        "medium": 0, "low": 0, "info": 0,
        "total": 0, "attacked": 0,
        "defended": 0, "not_tested": 0,
    }

    for f in findings:
        summary["total"] += 1
        if f.attack_worked:
            summary[f.severity] = \
                summary.get(f.severity, 0) + 1
            summary["attacked"] += 1
        elif f.was_attempted:
            summary["defended"] += 1
        else:
            summary["not_tested"] += 1

    return summary
