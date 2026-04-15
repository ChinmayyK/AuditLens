from workers.celery_app import celery_app


@celery_app.task(bind=True, max_retries=3, default_retry_delay=5)
def generate_report(self, scan_id: str = "") -> dict:
    return {"status": "queued", "engine": "reports", "scan_id": scan_id}
