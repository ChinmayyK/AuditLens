import os
import asyncio
import json
import traceback
from contextlib import asynccontextmanager
from datetime import datetime

import redis.asyncio as aioredis
from fastapi import FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import logging
from api.v1 import auth as auth_router
from api.v1 import dashboard as dashboard_router
from api.v1 import scans as scans_router
from api.v1 import findings as findings_router
from api.v1 import reports as reports_router
from api.v1 import chat as chat_router
from api.v1 import ide as ide_router
from api.v1 import recon as recon_router
from api.v1 import settings as settings_router
from review_engine.api import router as review_engine_router
from api.v1 import review as pr_review_router
from api.v1 import webhooks as webhooks_router
from core.websocket import ws_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s"
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ShieldSentinel API starting up...")
    # Run migrations
    try:
        from alembic.config import Config
        from alembic import command
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations complete")
    except Exception as e:
        logger.error(f"Migration error: {e}")

    # Create upload directories
    for path in [
        os.getenv("UPLOAD_DIR", "/tmp/shieldsentinel/uploads"),
        os.getenv("REPORTS_DIR", "/tmp/shieldsentinel/reports"),
        os.getenv("IDE_SESSIONS_DIR", "/tmp/shieldsentinel/ide"),
    ]:
        os.makedirs(path, exist_ok=True)

    yield
    logger.info("ShieldSentinel API shutting down...")


app = FastAPI(
    title="ShieldSentinel API",
    description="Professional Security Assessment Platform",
    version="1.0.0",
    docs_url="/api/v1/docs",
    redoc_url="/api/v1/redoc",
    openapi_url="/api/v1/openapi.json",
    lifespan=lifespan,
)

# ── Middleware ─────────────────────────────────────────
allowed_origins = os.getenv(
    "ALLOWED_ORIGINS",
    "http://localhost:9998,http://localhost:9997,http://localhost:99"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Request logging middleware ─────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = datetime.utcnow()
    try:
        response = await call_next(request)
        duration = (datetime.utcnow() - start).total_seconds()
        logger.info(
            f"{request.method} {request.url.path} "
            f"→ {response.status_code} ({duration:.3f}s)"
        )
        return response
    except Exception as e:
        logger.error(f"Middleware failure: {e}", exc_info=True)
        raise e


# ── Health check ───────────────────────────────────────
@app.get("/api/v1/health", tags=["system"])
async def health():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat(),
        "environment": os.getenv("ENVIRONMENT", "development"),
    }


@app.get("/api/v1/health/services", tags=["system"])
async def health_services():
    import redis as sync_redis
    from sqlalchemy import text

    results = {
        "database": False,
        "redis": False,
        "zap": False,
        "workers": False,
    }

    try:
        from models.base import SessionLocal
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        results["database"] = True
    except Exception:
        pass

    try:
        r = sync_redis.from_url(
            os.getenv("REDIS_URL", "redis://redis:6379/0")
        )
        r.ping()
        results["redis"] = True
    except Exception:
        pass

    try:
        import httpx
        resp = httpx.get(
            f"{os.getenv('ZAP_URL', 'http://zap:8090')}"
            f"/JSON/core/view/version/"
            f"?apikey={os.getenv('ZAP_API_KEY', '')}",
            timeout=5,
        )
        results["zap"] = resp.status_code == 200
    except Exception:
        pass

    try:
        from workers.celery_app import celery_app
        inspect = celery_app.control.inspect(timeout=2)
        active = inspect.active()
        results["workers"] = bool(active)
    except Exception:
        pass

    return results


app.include_router(
    auth_router.router,
    prefix="/api/v1",
)
app.include_router(dashboard_router.router, prefix="/api/v1")
app.include_router(scans_router.router)
app.include_router(findings_router.router)
app.include_router(reports_router.router)
app.include_router(chat_router.router)
app.include_router(ide_router.router)
app.include_router(recon_router.router)
app.include_router(settings_router.router)
app.include_router(review_engine_router)
app.include_router(pr_review_router.router)
app.include_router(webhooks_router.router)


@app.websocket("/ws/scan/{scan_id}")
async def scan_websocket(
    websocket: WebSocket,
    scan_id: str,
):
    await ws_manager.connect(scan_id, websocket)
    redis_client = aioredis.from_url(
        os.getenv("REDIS_URL", "redis://redis:6379/0")
    )

    try:
        key = f"ws:events:{scan_id}"
        buffered = await redis_client.lrange(key, 0, -1)
        for raw in reversed(buffered):
            try:
                await websocket.send_json(json.loads(raw))
            except Exception:
                break

        last_len = len(buffered)
        while True:
            try:
                events = await redis_client.lrange(
                    key, 0, -1
                )
                if len(events) > last_len:
                    for raw in list(reversed(events))[last_len:]:
                        await websocket.send_json(
                            json.loads(raw)
                        )
                    last_len = len(events)

                await asyncio.sleep(0.5)
            except WebSocketDisconnect:
                break

    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(scan_id, websocket)
        await redis_client.aclose()


@app.websocket("/ws/ide/{session_id}")
async def ide_websocket(
    websocket: WebSocket,
    session_id: str,
):
    await ws_manager.connect(session_id, websocket)
    redis_client = aioredis.from_url(
        os.getenv("REDIS_URL", "redis://redis:6379/0")
    )
    try:
        key = f"ws:events:{session_id}"
        last_len = 0
        while True:
            try:
                events = await redis_client.lrange(
                    key, 0, -1
                )
                if len(events) > last_len:
                    for raw in list(reversed(events))[last_len:]:
                        await websocket.send_json(
                            json.loads(raw)
                        )
                    last_len = len(events)
                await asyncio.sleep(0.5)
            except WebSocketDisconnect:
                break
    except WebSocketDisconnect:
        pass
    finally:
        ws_manager.disconnect(session_id, websocket)
        await redis_client.aclose()


@app.exception_handler(404)
async def not_found(request: Request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "not_found",
            "message": f"Route {request.url.path} not found",
            "docs": "/api/v1/docs",
        }
    )


@app.exception_handler(500)
async def server_error(request: Request, exc: Exception):
    logger.error(f"500 error: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "internal_server_error",
            "message": f"Something went wrong: {str(exc)}",
            "traceback": "".join(
                traceback.format_exception(
                    type(exc), exc, exc.__traceback__
                )
            ) if os.getenv("ENVIRONMENT") == "development" else None
        }
    )
