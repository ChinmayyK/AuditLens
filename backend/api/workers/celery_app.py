import os
from celery import Celery
from celery.schedules import crontab
from kombu import Queue

broker_url = os.getenv("CELERY_BROKER_URL", "redis://redis:6379/0")
result_backend = os.getenv("CELERY_RESULT_BACKEND", "redis://redis:6379/1")

celery_app = Celery(
    "shieldsentinel",
    broker=broker_url,
    backend=result_backend,
    include=[
        "workers.tasks.recon",
        "workers.tasks.dast",
        "workers.tasks.sast",
        "workers.tasks.ai_tasks",
        "workers.tasks.reports",
        "workers.tasks.scheduler",
    ]
)

celery_app.conf.update(
    # Queue routing
    task_queues=(
        Queue("recon", routing_key="recon.#"),
        Queue("dast", routing_key="dast.#"),
        Queue("sast", routing_key="sast.#"),
        Queue("ai", routing_key="ai.#"),
        Queue("reports", routing_key="reports.#"),
        Queue("default", routing_key="default.#"),
    ),
    task_default_queue="default",
    task_default_routing_key="default.task",

    # Serialization
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="UTC",
    enable_utc=True,
    broker_connection_retry_on_startup=True,

    # Reliability
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,

    # Result expiry
    result_expires=86400,

    # Retry defaults
    task_max_retries=3,
    task_default_retry_delay=5,

    # Monitoring
    worker_send_task_events=True,
    task_send_sent_event=True,
)

# ── Task routing ───────────────────────────────────────
celery_app.conf.task_routes = {
    "workers.tasks.recon.*": {"queue": "recon"},
    "workers.tasks.dast.*": {"queue": "dast"},
    "workers.tasks.sast.*": {"queue": "sast"},
    "workers.tasks.ai_tasks.*": {"queue": "ai"},
    "workers.tasks.reports.*": {"queue": "reports"},
    "workers.tasks.scheduler.*": {"queue": "default"},
}

celery_app.conf.beat_schedule = {
    "run-due-schedules": {
        "task": "workers.tasks.scheduler.run_due_schedules",
        "schedule": crontab(minute="*/15"),
    },
}
celery_app.conf.timezone = "UTC"

if __name__ == "__main__":
    celery_app.start()
