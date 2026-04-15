import os
import uuid
import zipfile
import tempfile
from pathlib import Path
from datetime import datetime

from fastapi import (
    APIRouter, Depends, HTTPException,
)
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from models.base import get_db
from models.scan import Scan, Finding
from models.ide import IDESession, IDEAnnotation
from models.user import User
from core.dependencies import get_current_user

router = APIRouter(
    prefix="/api/v1/ide",
    tags=["ide"],
)


def _session_to_dict(
    session: IDESession, db: Session
) -> dict:
    scan = None
    if session.scan_id:
        scan = db.query(Scan).filter(
            Scan.id == session.scan_id
        ).first()

    return {
        "id":              str(session.id),
        "source_type":     session.source_type,
        "repo_url":        session.repo_url,
        "repo_name":       session.repo_name,
        "zip_filename":    session.zip_filename,
        "status":          session.status,
        "error_message":   session.error_message,
        "file_tree":       session.file_tree or [],
        "security_score":  session.security_score,
        "total_findings":  session.total_findings,
        "file_scores":     session.file_scores or {},
        "languages_detected":
            session.languages_detected or [],
        "created_at":
            session.created_at.isoformat(),
        "scan": {
            "id":         str(scan.id),
            "status":     scan.status,
            "risk_score": scan.risk_score,
            "risk_grade": scan.risk_grade,
        } if scan else None,
    }


@router.get("/{session_id}")
async def get_session(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(IDESession).filter(
        IDESession.id == uuid.UUID(session_id),
        IDESession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(
            404, "IDE session not found"
        )
    return _session_to_dict(session, db)


@router.get("/{session_id}/file")
async def get_file(
    session_id: str,
    path: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(IDESession).filter(
        IDESession.id == uuid.UUID(session_id),
        IDESession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(404, "Session not found")

    contents = session.file_contents or {}
    content = contents.get(path)

    if content is None:
        for k, v in contents.items():
            if k.endswith(path) or path.endswith(k):
                content = v
                path = k
                break

    if content is None:
        if session.clone_path:
            disk_path = Path(
                session.clone_path
            ) / path
            if disk_path.exists():
                try:
                    content = disk_path.read_text(
                        encoding="utf-8",
                        errors="replace",
                    )
                except Exception:
                    pass

    if content is None:
        raise HTTPException(
            404, f"File not found: {path}"
        )

    annotations = db.query(IDEAnnotation).filter(
        IDEAnnotation.session_id ==
        uuid.UUID(session_id),
        IDEAnnotation.file_path == path,
        IDEAnnotation.is_resolved == False,
    ).all()

    ext_lang = {
        ".py":    "python",
        ".js":    "javascript",
        ".ts":    "typescript",
        ".jsx":   "javascript",
        ".tsx":   "typescript",
        ".java":  "java",
        ".php":   "php",
        ".go":    "go",
        ".rb":    "ruby",
        ".cs":    "csharp",
        ".cpp":   "cpp",
        ".c":     "c",
        ".rs":    "rust",
        ".html":  "html",
        ".css":   "css",
        ".json":  "json",
        ".yaml":  "yaml",
        ".yml":   "yaml",
        ".md":    "markdown",
        ".sh":    "shell",
        ".bash":  "shell",
        ".sql":   "sql",
        ".toml":  "toml",
        ".tf":    "hcl",
    }
    ext = Path(path).suffix.lower()
    language = ext_lang.get(ext, "plaintext")

    score = (
        (session.file_scores or {}).get(path, 100)
    )

    return {
        "path":      path,
        "content":   content,
        "language":  language,
        "score":     score,
        "annotations": [
            {
                "id":        str(a.id),
                "line":      a.line_number,
                "column":    a.column_number,
                "type":      a.annotation_type,
                "vuln_type": a.vuln_type,
                "severity":  a.severity,
                "message":   a.message,
                "quick_fix": a.quick_fix,
            }
            for a in annotations
        ],
    }


@router.get("/{session_id}/findings")
async def get_session_findings(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(IDESession).filter(
        IDESession.id == uuid.UUID(session_id),
        IDESession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(404, "Session not found")

    if not session.scan_id:
        return {"findings_by_file": {}, "total": 0}

    findings = db.query(Finding).filter(
        Finding.scan_id == session.scan_id,
    ).all()

    by_file: dict = {}
    no_file = []

    for f in findings:
        if f.file_path:
            fp = f.file_path
            if fp not in by_file:
                by_file[fp] = []
            by_file[fp].append({
                "id":          str(f.id),
                "vuln_type":   f.vuln_type,
                "severity":    f.severity,
                "line_number": f.line_number,
                "description": f.description,
                "evidence":    f.evidence,
                "attack_worked": f.attack_worked,
                "quick_fix":   f.quick_fix,
                "ai_fix":      f.ai_fix,
            })
        else:
            no_file.append({
                "id":        str(f.id),
                "vuln_type": f.vuln_type,
                "severity":  f.severity,
                "url":       f.url,
                "description": f.description,
                "attack_worked": f.attack_worked,
            })

    return {
        "findings_by_file": by_file,
        "no_file":          no_file,
        "total":            len(findings),
        "total_attacked":   sum(
            1 for f in findings
            if f.attack_worked
        ),
    }


@router.post("/{session_id}/fix")
async def apply_fix(
    session_id: str,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(IDESession).filter(
        IDESession.id == uuid.UUID(session_id),
        IDESession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(404, "Session not found")

    file_path = payload.get("file_path", "")
    line_num = payload.get("line_number", 0)
    fixed_code = payload.get("fixed_code", "")
    finding_id = payload.get("finding_id")

    if not file_path or not fixed_code:
        raise HTTPException(
            400, "file_path and fixed_code required"
        )

    contents = dict(session.file_contents or {})
    if file_path in contents:
        lines = contents[file_path].split("\n")
        if 0 < line_num <= len(lines):
            lines[line_num - 1] = fixed_code
            contents[file_path] = "\n".join(lines)
            session.file_contents = contents

    db.query(IDEAnnotation).filter(
        IDEAnnotation.session_id ==
        uuid.UUID(session_id),
        IDEAnnotation.file_path == file_path,
        IDEAnnotation.line_number == line_num,
    ).update({"is_resolved": True,
              "resolved_at": datetime.utcnow()})

    if finding_id:
        db.query(Finding).filter(
            Finding.id == uuid.UUID(finding_id)
        ).update({
            "fix_verified":    True,
            "fix_verified_at": datetime.utcnow(),
        })

    db.commit()

    if session.scan_id:
        file_scores = dict(session.file_scores or {})
        current_score = file_scores.get(
            file_path, 100
        )
        file_scores[file_path] = min(
            100, current_score + 15
        )
        session.file_scores = file_scores
        db.commit()

    return {
        "status":     "applied",
        "file_path":  file_path,
        "line":       line_num,
        "new_score":
            (session.file_scores or {})
            .get(file_path, 100),
    }


@router.post("/{session_id}/fix-all")
async def fix_all(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(IDESession).filter(
        IDESession.id == uuid.UUID(session_id),
        IDESession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(404, "Session not found")

    if not session.scan_id:
        return {"applied": 0, "skipped": 0}

    findings = db.query(Finding).filter(
        Finding.scan_id == session.scan_id,
        Finding.attack_worked == True,
        Finding.severity.in_(
            ["critical", "high"]
        ),
        Finding.file_path != None,
        Finding.line_number != None,
    ).all()

    contents = dict(session.file_contents or {})
    file_scores = dict(session.file_scores or {})
    applied_count = 0
    skipped_count = 0
    modified_files = set()

    for f in findings:
        ai = f.ai_fix
        qf = f.quick_fix
        fix = None

        if ai and isinstance(ai, dict):
            defs = ai.get("defense_examples", [])
            if defs:
                fix = defs[0].get("code_after")
        if not fix and qf:
            fix = qf

        if not fix or f.file_path not in contents:
            skipped_count += 1
            continue

        lines = contents[f.file_path].split("\n")
        ln = f.line_number
        if 0 < ln <= len(lines):
            lines[ln - 1] = fix
            contents[f.file_path] = "\n".join(lines)
            applied_count += 1
            modified_files.add(f.file_path)

            f.fix_verified = True
            f.fix_verified_at = datetime.utcnow()
        else:
            skipped_count += 1

    for fp in modified_files:
        file_scores[fp] = min(
            100,
            file_scores.get(fp, 50) + 25,
        )

    session.file_contents = contents
    session.file_scores = file_scores
    db.commit()

    db.query(IDEAnnotation).filter(
        IDEAnnotation.session_id ==
        uuid.UUID(session_id),
        IDEAnnotation.file_path.in_(
            list(modified_files)
        ),
    ).update(
        {"is_resolved": True,
         "resolved_at": datetime.utcnow()},
        synchronize_session="fetch",
    )
    db.commit()

    return {
        "applied":        applied_count,
        "skipped":        skipped_count,
        "modified_files": list(modified_files),
    }


@router.get("/{session_id}/download")
async def download_zip(
    session_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(IDESession).filter(
        IDESession.id == uuid.UUID(session_id),
        IDESession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(404, "Session not found")

    contents = session.file_contents or {}
    if not contents:
        raise HTTPException(
            400, "No file contents available"
        )

    tmp = tempfile.NamedTemporaryFile(
        suffix=".zip", delete=False
    )
    tmp.close()

    report_lines = [
        "# ShieldSentinel Security Report",
        f"Repo: {session.repo_name or 'uploaded code'}",
        f"Score: {session.security_score or 'N/A'}/100",
        f"Date: {datetime.utcnow().strftime('%Y-%m-%d')}",
        "",
        "## Findings Summary",
    ]

    if session.scan_id:
        findings = db.query(Finding).filter(
            Finding.scan_id == session.scan_id,
            Finding.attack_worked == True,
        ).all()
        for f in findings:
            report_lines.append(
                f"- [{f.severity.upper()}] "
                f"{f.vuln_type} in "
                f"{f.file_path or 'N/A'}"
                f" line {f.line_number or 'N/A'}"
            )

    with zipfile.ZipFile(
        tmp.name, "w",
        compression=zipfile.ZIP_DEFLATED,
    ) as zf:
        for fp, content in contents.items():
            zf.writestr(fp, content)
        zf.writestr(
            "SECURITY_REPORT.md",
            "\n".join(report_lines),
        )

    name = (
        session.repo_name or "code"
    ).replace("/", "_")
    date_str = datetime.utcnow().strftime(
        "%Y%m%d"
    )
    filename = f"{name}_secured_{date_str}.zip"

    return FileResponse(
        tmp.name,
        filename=filename,
        media_type="application/zip",
    )


@router.post("/{session_id}/chat")
async def ide_chat(
    session_id: str,
    payload: dict,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    session = db.query(IDESession).filter(
        IDESession.id == uuid.UUID(session_id),
        IDESession.user_id == current_user.id,
    ).first()
    if not session:
        raise HTTPException(404, "Session not found")

    message = payload.get("message", "")
    current_file = payload.get("current_file", "")
    current_line = payload.get("current_line", 0)

    if not message:
        raise HTTPException(400, "Message required")

    ctx_parts = [
        f"Repository: "
        f"{session.repo_name or 'uploaded code'}",
        f"Security Score: "
        f"{session.security_score or 'N/A'}/100",
        f"Total Findings: {session.total_findings}",
    ]

    if current_file and session.file_contents:
        fc = session.file_contents.get(current_file)
        if fc:
            lines = fc.split("\n")
            start = max(0, current_line - 5)
            end = min(
                len(lines), current_line + 10
            )
            snippet = "\n".join(
                lines[start:end]
            )
            ctx_parts.append(
                f"\nCurrent file: {current_file}"
                f" (near line {current_line}):\n"
                f"```\n{snippet[:500]}\n```"
            )

    system = (
        "You are ShieldSentinel IDE Agent — an expert "
        "security engineer reviewing code.\n"
        f"{chr(10).join(ctx_parts)}\n\n"
        "Rules:\n"
        "- Give specific, actionable code fixes.\n"
        "- Show before/after code examples.\n"
        "- Reference exact file paths and lines.\n"
        "- Be concise. Max 3 paragraphs.\n"
        "- Use markdown with code blocks."
    )

    import redis as sync_redis, json as _json
    r = sync_redis.from_url(
        os.getenv("REDIS_URL", "redis://redis:6379/0"),
        decode_responses=True,
    )
    hist_key = f"ide_chat:{session_id}"
    history = _json.loads(
        r.get(hist_key) or "[]"
    )
    history.append({
        "role": "user", "content": message
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
            500, f"AI unavailable: {str(e)[:80]}"
        )

    history.append({
        "role": "assistant", "content": reply
    })
    r.setex(hist_key, 86400,
            _json.dumps(history[-20:]))

    return {"reply": reply}
