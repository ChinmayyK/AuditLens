import hashlib
import secrets
import uuid
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from core.dependencies import get_current_user
from models.base import get_db
from models.scheduled import APIKey, ScanSchedule, ScanTemplate
from models.user import User

router = APIRouter(
    prefix="/api/v1/settings",
    tags=["settings"],
)


class ScheduleCreate(BaseModel):
    name: str
    target: str
    scan_type: str = "url"
    intensity: str = "standard"
    frequency: str = "weekly"
    day_of_week: Optional[int] = None
    hour_utc: int = 2
    notify_email: bool = True
    notify_on_new: bool = True


class TemplateCreate(BaseModel):
    name: str
    description: Optional[str] = None
    scan_type: str = "url"
    intensity: str = "standard"
    config: dict = {}
    is_public: bool = False


class APIKeyCreate(BaseModel):
    name: str
    scopes: list = ["scan:read", "scan:write"]
    expires_days: Optional[int] = None


class ProfileUpdate(BaseModel):
    full_name: Optional[str] = None
    notification_email: Optional[bool] = None
    weekly_digest: Optional[bool] = None


def _next_run(
    frequency: str,
    day_of_week: Optional[int],
    hour_utc: int,
) -> datetime:
    now = datetime.utcnow()
    if frequency == "hourly":
        return now.replace(minute=0, second=0, microsecond=0) + timedelta(hours=1)
    if frequency == "daily":
        candidate = now.replace(hour=hour_utc, minute=0, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate
    if frequency == "weekly":
        target_dow = day_of_week if day_of_week is not None else 0
        days_ahead = (target_dow - now.weekday() + 7) % 7 or 7
        return (now + timedelta(days=days_ahead)).replace(
            hour=hour_utc,
            minute=0,
            second=0,
            microsecond=0,
        )
    if frequency == "monthly":
        next_month = (now.month % 12) + 1
        year = now.year + (1 if next_month == 1 else 0)
        return datetime(year, next_month, 1, hour_utc, 0, 0)
    return now + timedelta(days=7)


@router.get("/schedules")
async def list_schedules(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    schedules = (
        db.query(ScanSchedule)
        .filter(ScanSchedule.user_id == current_user.id)
        .order_by(ScanSchedule.created_at.desc())
        .all()
    )
    return [_sched_to_dict(s) for s in schedules]


@router.post("/schedules")
async def create_schedule(
    body: ScheduleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    count = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.user_id == current_user.id,
            ScanSchedule.is_active == True,
        )
        .count()
    )
    limit = 3 if current_user.plan == "free" else 20
    if count >= limit:
        raise HTTPException(400, f"Schedule limit reached ({limit} for {current_user.plan} plan)")

    sched = ScanSchedule(
        user_id=current_user.id,
        name=body.name,
        target=body.target,
        scan_type=body.scan_type,
        intensity=body.intensity,
        frequency=body.frequency,
        day_of_week=body.day_of_week,
        hour_utc=body.hour_utc,
        notify_email=body.notify_email,
        notify_on_new=body.notify_on_new,
        next_run_at=_next_run(body.frequency, body.day_of_week, body.hour_utc),
    )
    db.add(sched)
    db.commit()
    db.refresh(sched)
    return _sched_to_dict(sched)


@router.put("/schedules/{schedule_id}")
async def update_schedule(
    schedule_id: str,
    body: ScheduleCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sched = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.id == uuid.UUID(schedule_id),
            ScanSchedule.user_id == current_user.id,
        )
        .first()
    )
    if not sched:
        raise HTTPException(404, "Schedule not found")

    sched.name = body.name
    sched.target = body.target
    sched.intensity = body.intensity
    sched.frequency = body.frequency
    sched.day_of_week = body.day_of_week
    sched.hour_utc = body.hour_utc
    sched.notify_email = body.notify_email
    sched.next_run_at = _next_run(body.frequency, body.day_of_week, body.hour_utc)
    db.commit()
    return _sched_to_dict(sched)


@router.patch("/schedules/{schedule_id}/toggle")
async def toggle_schedule(
    schedule_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sched = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.id == uuid.UUID(schedule_id),
            ScanSchedule.user_id == current_user.id,
        )
        .first()
    )
    if not sched:
        raise HTTPException(404, "Not found")
    sched.is_active = not sched.is_active
    db.commit()
    return {"is_active": sched.is_active}


@router.delete("/schedules/{schedule_id}")
async def delete_schedule(
    schedule_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sched = (
        db.query(ScanSchedule)
        .filter(
            ScanSchedule.id == uuid.UUID(schedule_id),
            ScanSchedule.user_id == current_user.id,
        )
        .first()
    )
    if not sched:
        raise HTTPException(404, "Not found")
    db.delete(sched)
    db.commit()
    return {"deleted": True}


def _sched_to_dict(s: ScanSchedule) -> dict:
    return {
        "id": str(s.id),
        "name": s.name,
        "target": s.target,
        "scan_type": s.scan_type,
        "intensity": s.intensity,
        "frequency": s.frequency,
        "day_of_week": s.day_of_week,
        "hour_utc": s.hour_utc,
        "is_active": s.is_active,
        "run_count": s.run_count,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "notify_email": s.notify_email,
        "notify_on_new": s.notify_on_new,
        "created_at": s.created_at.isoformat(),
    }


BUILT_IN_TEMPLATES = [
    {
        "id": "builtin-quick-url",
        "name": "Quick URL Check",
        "description": "Fast surface scan — SSL, headers, cookies, basic ZAP. Under 5 minutes.",
        "scan_type": "url",
        "intensity": "quick",
        "config": {},
        "is_public": True,
        "use_count": 0,
        "is_builtin": True,
    },
    {
        "id": "builtin-standard-url",
        "name": "Standard Web Scan",
        "description": "Full DAST — ZAP, Nuclei, FFUF, Gobuster, Nikto, stress test. Recommended for weekly scans.",
        "scan_type": "url",
        "intensity": "standard",
        "config": {},
        "is_public": True,
        "use_count": 0,
        "is_builtin": True,
    },
    {
        "id": "builtin-deep-url",
        "name": "Deep Penetration Test",
        "description": "Full DAST + SQLMap + XSStrike + Commix (RCE probe) + subdomain recon. 30-90 minutes.",
        "scan_type": "url",
        "intensity": "deep",
        "config": {},
        "is_public": True,
        "use_count": 0,
        "is_builtin": True,
    },
    {
        "id": "builtin-code-review",
        "name": "Code Security Review",
        "description": "Full SAST — Semgrep, Gitleaks, TruffleHog, Bandit, Trivy CVEs.",
        "scan_type": "zip",
        "intensity": "standard",
        "config": {},
        "is_public": True,
        "use_count": 0,
        "is_builtin": True,
    },
    {
        "id": "builtin-github-ide",
        "name": "GitHub IDE Review",
        "description": "Clone repo, run SAST, open Monaco editor with red line annotations.",
        "scan_type": "github",
        "intensity": "standard",
        "config": {},
        "is_public": True,
        "use_count": 0,
        "is_builtin": True,
    },
]


@router.get("/templates")
async def list_templates(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    user_templates = (
        db.query(ScanTemplate)
        .filter(ScanTemplate.user_id == current_user.id)
        .order_by(ScanTemplate.created_at.desc())
        .all()
    )

    return {
        "builtin": BUILT_IN_TEMPLATES,
        "custom": [_tmpl_to_dict(t) for t in user_templates],
    }


@router.post("/templates")
async def create_template(
    body: TemplateCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tmpl = ScanTemplate(
        user_id=current_user.id,
        name=body.name,
        description=body.description,
        scan_type=body.scan_type,
        intensity=body.intensity,
        config=body.config,
        is_public=body.is_public,
    )
    db.add(tmpl)
    db.commit()
    db.refresh(tmpl)
    return _tmpl_to_dict(tmpl)


@router.delete("/templates/{template_id}")
async def delete_template(
    template_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tmpl = (
        db.query(ScanTemplate)
        .filter(
            ScanTemplate.id == uuid.UUID(template_id),
            ScanTemplate.user_id == current_user.id,
        )
        .first()
    )
    if not tmpl:
        raise HTTPException(404, "Not found")
    db.delete(tmpl)
    db.commit()
    return {"deleted": True}


def _tmpl_to_dict(t: ScanTemplate) -> dict:
    return {
        "id": str(t.id),
        "name": t.name,
        "description": t.description,
        "scan_type": t.scan_type,
        "intensity": t.intensity,
        "config": t.config or {},
        "is_public": t.is_public,
        "use_count": t.use_count,
        "is_builtin": False,
        "created_at": t.created_at.isoformat(),
    }


def _generate_api_key() -> tuple:
    raw = f"ss_{secrets.token_urlsafe(32)}"
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    preview = raw[:5] + "..." + raw[-4:]
    return raw, hashed, preview


@router.get("/api-keys")
async def list_api_keys(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    keys = (
        db.query(APIKey)
        .filter(
            APIKey.user_id == current_user.id,
            APIKey.is_active == True,
        )
        .order_by(APIKey.created_at.desc())
        .all()
    )
    return [_key_to_dict(k) for k in keys]


@router.post("/api-keys")
async def create_api_key(
    body: APIKeyCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    count = (
        db.query(APIKey)
        .filter(
            APIKey.user_id == current_user.id,
            APIKey.is_active == True,
        )
        .count()
    )
    limit = 2 if current_user.plan == "free" else 10
    if count >= limit:
        raise HTTPException(400, f"API key limit reached ({limit} for {current_user.plan} plan)")

    raw, hashed, preview = _generate_api_key()

    expires = None
    if body.expires_days:
        expires = datetime.utcnow() + timedelta(days=body.expires_days)

    key = APIKey(
        user_id=current_user.id,
        name=body.name,
        key_hash=hashed,
        key_preview=preview,
        scopes=body.scopes,
        expires_at=expires,
    )
    db.add(key)
    db.commit()
    db.refresh(key)

    result = _key_to_dict(key)
    result["raw_key"] = raw
    return result


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    key = (
        db.query(APIKey)
        .filter(
            APIKey.id == uuid.UUID(key_id),
            APIKey.user_id == current_user.id,
        )
        .first()
    )
    if not key:
        raise HTTPException(404, "Key not found")
    key.is_active = False
    db.commit()
    return {"revoked": True}


def _key_to_dict(k: APIKey) -> dict:
    return {
        "id": str(k.id),
        "name": k.name,
        "key_preview": k.key_preview,
        "scopes": k.scopes or [],
        "is_active": k.is_active,
        "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None,
        "expires_at": k.expires_at.isoformat() if k.expires_at else None,
        "request_count": k.request_count,
        "created_at": k.created_at.isoformat(),
    }


@router.get("/profile")
async def get_profile(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from models.scan import Finding, Scan

    total_scans = db.query(Scan).filter(Scan.user_id == current_user.id).count()
    total_findings = (
        db.query(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .filter(
            Scan.user_id == current_user.id,
            Finding.attack_worked == True,
        )
        .count()
    )

    return {
        "id": str(current_user.id),
        "email": current_user.email,
        "full_name": current_user.full_name,
        "avatar_url": current_user.avatar_url,
        "plan": current_user.plan,
        "created_at": current_user.created_at.isoformat() if current_user.created_at else None,
        "stats": {
            "total_scans": total_scans,
            "total_findings": total_findings,
        },
    }


@router.put("/profile")
async def update_profile(
    body: ProfileUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if body.full_name:
        current_user.full_name = body.full_name
    db.commit()
    return {"updated": True}
