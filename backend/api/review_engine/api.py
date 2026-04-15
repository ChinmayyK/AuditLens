"""
Review Engine API — FastAPI router exposing the review engine.

Config-driven: All scoring weights, thresholds, and custom rules
are loaded from review_config.json on EVERY request (hot-reload).

Endpoints:
  POST /api/v1/review             → Full review
  POST /api/v1/review/score       → Score-only
  POST /api/v1/review/comments    → Comments-only
  POST /api/v1/review/pr          → Full PR review (v2)
  POST /api/v1/review/advanced    → Full advanced review (v3)
  POST /api/v1/review/intelligent → Intelligence report (v4)
  GET  /api/v1/review/config      → View current config
  PUT  /api/v1/review/config      → Update config (hot-reload)
"""
import json
import logging
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse

from core.dependencies import (
    get_current_user,
    get_current_user_optional,
)
from models.user import User
from review_engine.schemas.review import (
    ReviewRequest,
    ReviewResult,
    ScoreResult,
    ReviewComment,
    GitHubPRReview,
    FindingInput,
    DecisionResult,
    MergeDecision,
)
from review_engine.schemas.intelligence import (
    IntelligenceReport,
)
from review_engine.service import ReviewEngine
from pydantic import BaseModel, Field
from typing import Optional

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/review",
    tags=["review-engine"],
)

# Singleton engine instance — config is HOT-RELOADED from
# review_config.json on every request. No restart needed.
_engine = ReviewEngine()


@router.post(
    "",
    response_model=ReviewResult,
    summary="Full Security Review",
    description=(
        "Runs the complete review pipeline: "
        "relevance filtering, scoring, comment "
        "generation, merge decision, and summary."
    ),
)
async def full_review(
    request: ReviewRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Execute a full security review on the provided findings.

    Input:
    - findings: list of scanner findings
    - changed_lines: map of file → changed line numbers

    Returns: ReviewResult with comments, score, decision,
    and markdown summary.
    """
    logger.info(
        f"Full review requested by user "
        f"{current_user.id}: "
        f"{len(request.findings)} findings"
    )
    return _engine.execute(request)


@router.post(
    "/score",
    response_model=ScoreResult,
    summary="Score Only",
    description=(
        "Computes only the weighted score — no comments "
        "or summary. Fast path for CI/CD gate checks."
    ),
)
async def score_only(
    request: ReviewRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Compute only the weighted score from findings.
    Skips comment generation and summary rendering.
    Ideal for fast CI gate checks.
    """
    logger.info(
        f"Score-only review requested by user "
        f"{current_user.id}"
    )
    return _engine.score_only(request)


@router.post(
    "/comments",
    response_model=list[ReviewComment],
    summary="Comments Only",
    description=(
        "Generates only file+line review comments. "
        "Useful for inline PR annotations."
    ),
)
async def comments_only(
    request: ReviewRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Generate only the review comments from findings.
    Skips scoring summary and merge decision.
    Useful for inline PR annotation workflows.
    """
    logger.info(
        f"Comments-only review requested by user "
        f"{current_user.id}"
    )
    return _engine.comments_only(request)


@router.post(
    "/pr",
    response_model=ReviewResult,
    summary="Full PR Review (v2)",
    description=(
        "Runs the complete review pipeline with diff "
        "analysis, pattern detection, and GitHub PR "
        "formatted output. Accepts diffs for context-"
        "aware analysis."
    ),
)
async def pr_review(
    request: ReviewRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Execute a full PR security review.

    Input:
    - findings: list of scanner findings
    - changed_lines: map of file → changed line numbers
    - diffs: map of file → unified diff strings (v2)

    Returns: ReviewResult with pr_review field containing
    GitHub-formatted review payload.
    """
    logger.info(
        f"PR review requested by user "
        f"{current_user.id}: "
        f"{len(request.findings)} findings, "
        f"{len(request.diffs)} diffs"
    )
    return _engine.execute_pr(request)


@router.post(
    "/advanced",
    response_model=ReviewResult,
    summary="Advanced Review (v3)",
    description=(
        "Runs the full v3 pipeline: cross-tool "
        "correlation, status-aware scoring, change "
        "risk multipliers, policy overrides, and "
        "GitHub PR formatted output."
    ),
)
async def advanced_review(
    request: ReviewRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Execute a full v3 advanced security review.

    Input (enriched):
    - findings: list with tools[], status, change_risk
    - changed_lines: map of file → changed line numbers
    - diffs: map of file → unified diff strings
    - change_risk: map of file → risk level

    Returns: ReviewResult with cross-tool correlation,
    status breakdown, policy overrides, and PR output.
    """
    logger.info(
        f"Advanced review requested by user "
        f"{current_user.id}: "
        f"{len(request.findings)} findings, "
        f"{len(request.diffs)} diffs, "
        f"{len(request.change_risk)} risk-mapped files"
    )
    return _engine.execute_advanced(request)


# ── v4: Intelligence Report Request ────────────────


class IntelligentReviewRequest(BaseModel):
    """Input for the v4 intelligent review endpoint."""
    review_request: ReviewRequest
    history: Optional[list[dict]] = Field(
        None,
        description="Past review snapshots for trends",
    )
    repo_context: Optional[dict] = Field(
        None,
        description=(
            "Repo metadata (name, language, etc.)"
        ),
    )


class ReEvaluateReviewRequest(BaseModel):
    """Input for re-evaluating a review after fixes."""
    original_findings: list[FindingInput]
    fixed_file_paths: list[str] = Field(
        default_factory=list,
        description="Files updated by the developer",
    )
    changed_lines: dict[str, list[int]] = Field(
        default_factory=dict,
    )
    diffs: dict[str, str] = Field(
        default_factory=dict,
    )


@router.post(
    "/intelligent",
    response_model=IntelligenceReport,
    summary="Intelligence Report (v4)",
    description=(
        "Runs the full v4 pipeline: scoring, "
        "correlation, policy overrides, then "
        "priority ranking, explainability, "
        "insights, and narrative generation."
    ),
)
async def intelligent_review(
    payload: IntelligentReviewRequest,
    current_user: User = Depends(get_current_user),
):
    """
    Execute a full v4 intelligent security review.

    Input:
    - review_request: Standard ReviewRequest
    - history: Past review snapshots (optional)
    - repo_context: {repo, language} (optional)

    Returns: IntelligenceReport with prioritized
    findings, decision explanation, insights,
    risk assessment, and human-like narrative.
    """
    logger.info(
        f"Intelligent review requested by user "
        f"{current_user.id}: "
        f"{len(payload.review_request.findings)} "
        f"findings"
    )
    return _engine.execute_intelligent(
        request=payload.review_request,
        history=payload.history,
        repo_context=payload.repo_context,
    )


@router.post(
    "/pr-public",
    response_model=ReviewResult,
    summary="Public PR review demo endpoint",
)
async def pr_review_public(
    request: ReviewRequest,
    current_user: User | None = Depends(get_current_user_optional),
):
    logger.info(
        "Public PR review requested%s: %s findings, %s diffs",
        f" by user {current_user.id}" if current_user else "",
        len(request.findings),
        len(request.diffs),
    )
    return _engine.execute_pr(request)


@router.post(
    "/re-evaluate",
    response_model=ReviewResult,
    summary="Re-evaluate a review after fixes",
)
async def re_evaluate_review(
    payload: ReEvaluateReviewRequest,
    current_user: User = Depends(get_current_user),
):
    fixed_paths = set(payload.fixed_file_paths)
    remaining_findings = []
    fixed_count = 0

    for finding in payload.original_findings:
        if finding.file_path and finding.file_path in fixed_paths:
            fixed_count += 1
            continue
        remaining_findings.append(finding.model_dump())

    if not remaining_findings:
        logger.info(
            "Review re-evaluation requested by user %s: all findings fixed",
            current_user.id,
        )
        return ReviewResult(
            comments=[],
            score=ScoreResult(
                total_score=0.0,
                max_score=100,
                severity_breakdown=[],
                tool_breakdown=[],
                fixed_findings_count=fixed_count,
            ),
            decision=DecisionResult(
                decision=MergeDecision.APPROVE,
                reasons=[
                    "All selected findings were marked fixed.",
                ],
                hard_blockers=[],
            ),
            summary_markdown=(
                "## Security Review\n\n"
                "Score: 0/100\n"
                "Decision: approve\n"
                "Total Findings: 0\n"
            ),
            total_findings=0,
            relevant_count=0,
            contextual_count=0,
            unrelated_count=0,
            pattern_findings_count=0,
            new_findings_count=0,
            existing_findings_count=0,
            correlated_groups=0,
        )

    request = ReviewRequest(
        findings=remaining_findings,
        changed_lines=payload.changed_lines,
        diffs=payload.diffs,
    )

    logger.info(
        "Review re-evaluation requested by user %s: %s fixed files",
        current_user.id,
        len(fixed_paths),
    )
    return _engine.execute_pr(request)


# ── Config Hot-Reload API ─────────────────────────────
# Judges can view and edit the config via API.
# Changes take effect on the very next request.

from review_engine.config_loader import load_config, _CONFIG_PATH


@router.get(
    "/config",
    summary="View current review config",
    description=(
        "Returns the current review_config.json. "
        "All scoring weights, thresholds, and custom "
        "rules are loaded from this file on every request."
    ),
)
async def get_config():
    """
    Return the current review_config.json contents.
    This is the single source of truth for all scoring.
    """
    config = load_config()
    return JSONResponse(content=config)


@router.put(
    "/config",
    summary="Update review config (hot-reload)",
    description=(
        "Replace the entire review_config.json. The next "
        "review request will use the new values immediately. "
        "No restart needed."
    ),
)
async def update_config(
    new_config: dict,
    current_user: User = Depends(get_current_user),
):
    """
    Update review_config.json on disk.

    The next review request will hot-reload the new config.
    Judges: edit weights, thresholds, or add custom_rules
    and they take effect immediately.
    """
    # Validate structure
    required_keys = {"weights", "thresholds", "custom_rules"}
    missing = required_keys - set(new_config.keys())
    if missing:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Missing required top-level keys: "
                f"{', '.join(missing)}. "
                f"Config must have: weights, thresholds, custom_rules"
            ),
        )

    try:
        with open(_CONFIG_PATH, "w") as f:
            json.dump(new_config, f, indent=2)

        logger.info(
            f"Config updated by user {current_user.id}. "
            f"{len(new_config.get('custom_rules', []))} rules, "
            f"hot-reload active."
        )

        return {
            "status": "updated",
            "message": (
                "Config saved. Next review request will "
                "use the new values immediately."
            ),
            "custom_rules_count": len(
                new_config.get("custom_rules", [])
            ),
        }
    except Exception as e:
        logger.error(f"Config update failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to write config: {str(e)}",
        )
