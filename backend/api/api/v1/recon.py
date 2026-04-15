import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from core.dependencies import get_current_user
from models.base import get_db
from models.scan import Scan
from models.user import User

router = APIRouter(
    prefix="/api/v1/scans",
    tags=["recon"],
)


@router.get("/{scan_id}/recon")
async def get_recon_data(
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

    from packages.scanner.port_intel_service import analyze_port_exposure, enrich_port

    raw_ports = scan.open_ports or []
    enriched_ports = [enrich_port(p) for p in raw_ports]
    port_analysis = analyze_port_exposure(raw_ports)

    tech_analysis = {}
    if scan.tech_stack:
        try:
            from packages.scanner.tech_deep_dive import TechDeepDiveService

            tech_analysis = TechDeepDiveService().analyze(
                scan.target,
                scan.tech_stack,
            )
        except Exception:
            tech_analysis = {}

    return {
        "scan_id": scan_id,
        "target": scan.target,
        "os_guess": scan.os_guess,
        "cdn_detected": scan.cdn_detected,
        "waf_detected": scan.waf_detected,
        "waf_name": scan.waf_name,
        "tech_stack": scan.tech_stack,
        "open_ports": enriched_ports,
        "port_analysis": port_analysis,
        "tech_analysis": tech_analysis,
    }


@router.post("/{scan_id}/recon/subdomains")
async def start_subdomain_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
        Scan.scan_type == "url",
    ).first()
    if not scan:
        raise HTTPException(404, "URL scan not found")

    background_tasks.add_task(
        _run_subdomain_enum,
        scan_id,
        scan.target,
        scan.intensity,
    )

    return {
        "status": "started",
        "message": "Subdomain enumeration running in background",
    }


@router.get("/{scan_id}/recon/subdomains")
async def get_subdomains(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
        Scan.scan_type == "url",
    ).first()
    if not scan:
        raise HTTPException(404, "URL scan not found")

    import json as _json
    import os

    import redis as sync_redis

    r = sync_redis.from_url(
        os.getenv("REDIS_URL", "redis://redis:6379/0"),
        decode_responses=True,
    )
    key = f"subdomains:{scan_id}"
    data = r.get(key)

    if not data:
        return {
            "status": "not_started",
            "subdomains": [],
        }

    return {
        "status": "complete",
        **_json.loads(data),
    }


async def _run_subdomain_enum(
    scan_id: str,
    target_url: str,
    intensity: str,
):
    import json as _json
    import os

    import redis as sync_redis

    from packages.scanner.subdomain_service import SubdomainService

    r = sync_redis.from_url(
        os.getenv("REDIS_URL", "redis://redis:6379/0"),
        decode_responses=True,
    )

    def noop(*args, **kwargs):
        return None

    try:
        result = SubdomainService().enumerate(
            target_url,
            scan_id,
            noop,
            intensity,
        )
        key = f"subdomains:{scan_id}"
        r.setex(key, 3600, _json.dumps(result))
    except Exception:
        pass
