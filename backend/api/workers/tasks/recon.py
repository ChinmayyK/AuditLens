from workers.celery_app import celery_app


@celery_app.task(bind=True, max_retries=3, default_retry_delay=5)
def run_recon(self, target: str = "") -> dict:
    return {"status": "queued", "engine": "recon", "target": target}
