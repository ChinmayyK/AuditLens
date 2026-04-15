from datetime import datetime

from workers.celery_app import celery_app
from models.base import SessionLocal
from models.scheduled import ScanSchedule

import logging

logger = logging.getLogger(__name__)


@celery_app.task(
    name="workers.tasks.scheduler.run_due_schedules",
)
def run_due_schedules():
    """
    Called by Celery beat every 15 minutes.
    Fires any schedules whose next_run_at has passed.
    """
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        due = (
            db.query(ScanSchedule)
            .filter(
                ScanSchedule.is_active == True,
                ScanSchedule.next_run_at <= now,
            )
            .all()
        )

        logger.info(f"Scheduler: {len(due)} schedules due")

        for sched in due:
            try:
                _fire_schedule(sched, db)
            except Exception as e:
                logger.error(f"Schedule {sched.id} failed: {e}")
    finally:
        db.close()


def _fire_schedule(sched: ScanSchedule, db):
    from api.v1.settings import _next_run
    from models.scan import Scan
    from models.user import User
    from workers.tasks.dast import run_url_scan

    user = db.query(User).filter(User.id == sched.user_id).first()
    if not user:
        return

    scan = Scan(
        user_id=user.id,
        scan_type=sched.scan_type,
        target=sched.target,
        intensity=sched.intensity,
        ownership_confirmed=True,
        status="queued",
        current_phase="Queued by scheduler",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    scan_id = str(scan.id)
    run_url_scan.apply_async(
        args=[scan_id, sched.target, sched.intensity],
        queue="dast",
    )

    sched.last_run_at = datetime.utcnow()
    sched.last_scan_id = scan.id
    sched.run_count = (sched.run_count or 0) + 1
    sched.next_run_at = _next_run(
        sched.frequency,
        sched.day_of_week,
        sched.hour_utc,
    )
    db.commit()

    logger.info(f"Fired scheduled scan {scan_id} for {sched.target}")
