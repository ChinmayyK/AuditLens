import os
import json
import uuid
import asyncio
from datetime import datetime

import redis
from fastapi import (
    APIRouter, Depends, HTTPException,
    Request,
)
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from models.base import get_db
from models.scan import Scan, Finding
from models.user import User
from core.dependencies import get_current_user

router = APIRouter(
    prefix="/api/v1/scans",
    tags=["chat"],
)

REDIS_URL = os.getenv(
    "REDIS_URL", "redis://redis:6379/0"
)
CHAT_TTL  = 86400  # 24 hours
MAX_HIST  = 20

redis_client = redis.from_url(
    REDIS_URL, decode_responses=True
)


def _get_history(scan_id: str) -> list:
    key = f"chat:{scan_id}"
    raw = redis_client.get(key)
    return json.loads(raw) if raw else []


def _save_history(scan_id: str, history: list):
    key = f"chat:{scan_id}"
    redis_client.setex(
        key, CHAT_TTL,
        json.dumps(history[-MAX_HIST:]),
    )


def _build_context(
    scan: Scan, findings: list
) -> str:
    attacked = [
        f for f in findings
        if f.attack_worked
    ]
    defended = [
        f for f in findings
        if not f.attack_worked and
        f.was_attempted
    ]
    critical = [
        f for f in attacked
        if f.severity == "critical"
    ]
    high = [
        f for f in attacked
        if f.severity == "high"
    ]

    ctx = (
        f"SCAN DETAILS:\n"
        f"Target: {scan.target}\n"
        f"Type: {scan.scan_type}\n"
        f"Risk Score: {scan.risk_score}/100 "
        f"({scan.risk_grade})\n"
        f"Date: "
        f"{scan.created_at.strftime('%Y-%m-%d %H:%M')}\n"
        f"\nFINDING COUNTS:\n"
        f"Critical: {len(critical)}, "
        f"High: {len(high)}, "
        f"Total Vulnerable: {len(attacked)}, "
        f"Protected: {len(defended)}\n"
        f"\nCRITICAL VULNERABILITIES:\n"
    )

    for f in critical[:6]:
        loc = f.url or \
              f"{f.file_path}:{f.line_number}" or \
              "unknown"
        ctx += f"- {f.vuln_type} at {loc}\n"
        if f.ai_fix and isinstance(f.ai_fix, dict):
            tip = f.ai_fix.get("ai_suggestion", "")
            if tip:
                ctx += f"  Fix: {tip}\n"

    ctx += "\nHIGH VULNERABILITIES:\n"
    for f in high[:5]:
        loc = f.url or \
              f"{f.file_path}:{f.line_number}" or \
              "unknown"
        ctx += f"- {f.vuln_type} at {loc}\n"

    if scan.tech_stack:
        techs = scan.tech_stack.get(
            "technologies", []
        )
        if techs:
            ctx += (
                f"\nTECH STACK: "
                f"{', '.join(techs[:6])}\n"
            )

    if scan.open_ports:
        ctx += (
            f"\nOPEN PORTS: "
            f"{len(scan.open_ports)} found\n"
        )

    return ctx[:3000]


def _build_system(scan: Scan, ctx: str) -> str:
    return (
        f"You are ShieldSentinel AI — an expert "
        f"security analyst.\n"
        f"You are answering questions about a "
        f"specific security scan of "
        f"'{scan.target}'.\n\n"
        f"{ctx}\n\n"
        f"RULES:\n"
        f"- Answer specifically based on THIS "
        f"scan's data only.\n"
        f"- Show before/after code for fix requests.\n"
        f"- Use markdown formatting.\n"
        f"- Be concise. Max 4 paragraphs.\n"
        f"- Always reference specific vulnerability "
        f"locations.\n"
        f"- For executive summary: write 3 "
        f"professional paragraphs."
    )


class ChatRequest(BaseModel):
    message: str


@router.post("/{scan_id}/chat")
async def chat(
    scan_id: str,
    req: ChatRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
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

    ctx     = _build_context(scan, findings)
    system  = _build_system(scan, ctx)
    history = _get_history(scan_id)
    history.append({
        "role":    "user",
        "content": req.message,
    })

    from packages.ai.llm_router import LLMRouter
    try:
        reply = LLMRouter().chat(
            messages=history,
            system=system,
            max_tokens=800,
        )
    except Exception as e:
        raise HTTPException(
            500, f"AI unavailable: {str(e)[:100]}"
        )

    history.append({
        "role":    "assistant",
        "content": reply,
    })
    _save_history(scan_id, history)

    return {
        "reply":   reply,
        "scan_id": scan_id,
    }


@router.get("/{scan_id}/chat/stream")
async def chat_stream(
    scan_id: str,
    message: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(
        Scan.id == uuid.UUID(scan_id),
        Scan.user_id == current_user.id,
    ).first()
    if not scan:
        raise HTTPException(404, "Scan not found")

    findings = db.query(Finding).filter(
        Finding.scan_id == uuid.UUID(scan_id)
    ).all()

    ctx     = _build_context(scan, findings)
    system  = _build_system(scan, ctx)
    history = _get_history(scan_id)
    history.append({
        "role": "user", "content": message
    })

    async def event_stream():
        full_response = ""
        try:
            from groq import Groq
            import os
            client = Groq(
                api_key=os.getenv("GROQ_API_KEY","")
            )
            msgs = [
                {"role": "system", "content": system}
            ] + history

            stream = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=msgs,
                max_tokens=800,
                stream=True,
                temperature=0.3,
            )
            for chunk in stream:
                delta = (
                    chunk.choices[0]
                         .delta.content or ""
                )
                if delta:
                    full_response += delta
                    yield (
                        f"data: "
                        f"{json.dumps({'token': delta})}"
                        f"\n\n"
                    )

        except Exception:
            # Fallback: get full response + stream it
            try:
                from packages.ai.llm_router \
                    import LLMRouter
                full_response = LLMRouter().chat(
                    history, system, 800
                )
                for char in full_response:
                    yield (
                        f"data: "
                        f"{json.dumps({'token': char})}"
                        f"\n\n"
                    )
                    await asyncio.sleep(0.008)
            except Exception as e:
                yield (
                    f"data: "
                    f"{json.dumps({'error': str(e)})}"
                    f"\n\n"
                )

        if full_response:
            history.append({
                "role":    "assistant",
                "content": full_response,
            })
            _save_history(scan_id, history)

        yield (
            f"data: "
            f"{json.dumps({'done': True})}"
            f"\n\n"
        )

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "Connection":       "keep-alive",
            "X-Accel-Buffering":"no",
        },
    )


@router.get("/{scan_id}/chat/suggested")
async def get_suggested_prompts(
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

    findings = db.query(Finding).filter(
        Finding.scan_id == uuid.UUID(scan_id),
        Finding.attack_worked == True,
    ).order_by(Finding.severity).limit(3).all()

    prompts = [
        "What is the most critical vulnerability?",
        "What should I fix first?",
        "Generate an executive summary for my manager",
    ]

    if findings:
        top = findings[0]
        prompts.append(
            f"Explain the {top.vuln_type} "
            f"in simple terms"
        )
        prompts.append(
            f"Show me how to fix the {top.vuln_type}"
        )

    return {"prompts": prompts[:5]}


@router.delete("/{scan_id}/chat")
async def clear_chat(
    scan_id: str,
    current_user: User = Depends(get_current_user),
):
    redis_client.delete(f"chat:{scan_id}")
    return {"status": "cleared"}
