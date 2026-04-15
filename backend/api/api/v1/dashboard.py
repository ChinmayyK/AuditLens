import json as _json
import os
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, text
import redis as sync_redis

from models.base import get_db
from models.scan import Scan, Finding
from models.user import User
from core.dependencies import get_current_user

router = APIRouter(tags=["dashboard"])

r = sync_redis.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379/0"),
    decode_responses=True,
)


@router.get("/dashboard")
async def get_dashboard(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    cache_key = f"dashboard:{current_user.id}"
    cached = r.get(cache_key)
    if cached:
        return _json.loads(cached)

    user_id = current_user.id

    total_scans = db.query(func.count(Scan.id)).filter(
        Scan.user_id == user_id
    ).scalar() or 0

    total_findings = db.query(
        func.count(Finding.id)
    ).join(Scan).filter(
        Scan.user_id == user_id,
        Finding.attack_worked == True,
    ).scalar() or 0

    avg_score = db.query(
        func.avg(Scan.risk_score)
    ).filter(
        Scan.user_id == user_id,
        Scan.status == "complete",
        Scan.risk_score.isnot(None),
    ).scalar()
    avg_risk_score = (
        round(float(avg_score)) if avg_score else None
    )

    critical_open = db.query(
        func.count(Finding.id)
    ).join(Scan).filter(
        Scan.user_id == user_id,
        Finding.severity == "critical",
        Finding.attack_worked == True,
        Finding.fix_verified == False,
    ).scalar() or 0

    recent_scans_raw = db.query(Scan).filter(
        Scan.user_id == user_id,
    ).order_by(desc(Scan.created_at)).limit(20).all()

    recent_scans = []
    for scan in recent_scans_raw:
        findings = db.query(Finding).filter(
            Finding.scan_id == scan.id,
            Finding.attack_worked == True,
        ).all()

        summary = {
            "critical": sum(1 for f in findings
                            if f.severity == "critical"),
            "high":     sum(1 for f in findings
                            if f.severity == "high"),
            "medium":   sum(1 for f in findings
                            if f.severity == "medium"),
            "low":      sum(1 for f in findings
                            if f.severity == "low"),
            "total":    len(findings),
        }

        recent_scans.append({
            "id":               str(scan.id),
            "scan_type":        scan.scan_type,
            "target":           scan.target,
            "status":           scan.status,
            "risk_score":       scan.risk_score,
            "risk_grade":       scan.risk_grade,
            "created_at":       scan.created_at.isoformat(),
            "duration_seconds": scan.duration_seconds,
            "summary":          summary,
        })

    history_scans = db.query(Scan).filter(
        Scan.user_id == user_id,
        Scan.status == "complete",
        Scan.risk_score.isnot(None),
    ).order_by(desc(Scan.created_at)).limit(10).all()

    score_history = [
        {
            "date":  s.created_at.strftime("%b %d"),
            "score": s.risk_score,
        }
        for s in reversed(history_scans)
    ]

    tool_stats_raw = db.execute(
        text("""
            SELECT f.tool_source,
                   COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE s.user_id = :uid
              AND f.attack_worked = true
              AND f.tool_source IS NOT NULL
            GROUP BY f.tool_source
            ORDER BY cnt DESC
            LIMIT 8
        """),
        {"uid": user_id},
    ).fetchall()

    tool_stats = [
        {"tool": r[0], "count": r[1]}
        for r in tool_stats_raw
    ]

    top_vulns_raw = db.execute(
        text("""
            SELECT f.vuln_type,
                   COUNT(*) AS cnt
            FROM findings f
            JOIN scans s ON s.id = f.scan_id
            WHERE s.user_id = :uid
              AND f.attack_worked = true
            GROUP BY f.vuln_type
            ORDER BY cnt DESC
            LIMIT 5
        """),
        {"uid": user_id},
    ).fetchall()

    top_vulns = [
        {"vuln_type": r[0], "count": r[1]}
        for r in top_vulns_raw
    ]

    result = {
        "total_scans":    total_scans,
        "total_findings": total_findings,
        "avg_risk_score": avg_risk_score,
        "critical_open":  critical_open,
        "recent_scans":   recent_scans,
        "score_history":  score_history,
        "tool_stats":     tool_stats,
        "top_vulns":      top_vulns,
    }
    r.setex(cache_key, 30, _json.dumps(result))
    return result
