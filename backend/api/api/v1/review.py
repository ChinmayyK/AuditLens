"""
PR Review API — Endpoints for GitHub PR review pipeline.

POST /api/v1/review/github-pr
    Triggers a PR-specific security scan.
    Called by GitHub Actions or manually.
    Auth: X-Webhook-Secret header (NOT JWT).
"""
import os
import uuid
import logging

from fastapi import (
    APIRouter, HTTPException, Request,
    status,
)
from fastapi.responses import JSONResponse

from schemas.review import (
    PRReviewRequest,
    PRReviewResponse,
)
from packages.scanner.github_service import (
    GitHubService,
)
from review_engine.engine.diff_analyzer import (
    DiffAnalyzer,
)
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/review",
    tags=["pr-review"],
)

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")


def _verify_webhook_secret(request: Request):
    """
    Verify the X-Webhook-Secret header matches
    our configured secret. This is used instead
    of JWT because GitHub Actions calls this
    endpoint.
    """
    if not WEBHOOK_SECRET:
        logger.warning(
            "WEBHOOK_SECRET not configured — "
            "skipping auth"
        )
        return

    provided = request.headers.get(
        "X-Webhook-Secret", ""
    )
    if provided != WEBHOOK_SECRET:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook secret",
        )


@router.post(
    "/github-pr",
    response_model=PRReviewResponse,
    summary="Trigger PR Security Review",
    description=(
        "Fetches PR diff from GitHub, clones the repo, "
        "and dispatches a SAST scan filtered to changed "
        "lines. Called by GitHub Actions on pull_request "
        "events."
    ),
)
async def trigger_pr_review(
    payload: PRReviewRequest,
    request: Request,
):
    """
    Trigger a PR-specific security review.

    1. Verify webhook secret
    2. Parse repo URL → (owner, repo)
    3. Fetch PR metadata (head_sha, branches)
    4. Fetch PR unified diff
    5. Split diff into per-file diffs
    6. Derive changed_lines_map from diffs
    7. Dispatch run_pr_scan Celery task
    """
    _verify_webhook_secret(request)

    gh = GitHubService()
    review_id = str(uuid.uuid4())

    try:
        # Parse repo URL
        owner, repo_name = gh.parse_repo_url(
            payload.repo_url
        )
        logger.info(
            f"PR review {review_id}: "
            f"{owner}/{repo_name}#{payload.pr_number}"
        )

        # Fetch PR metadata
        pr_metadata = gh.fetch_pr_metadata(
            owner, repo_name, payload.pr_number
        )

        # Fetch unified diff
        raw_diff = gh.fetch_pr_diff(
            owner, repo_name, payload.pr_number
        )

        # Split into per-file diffs
        per_file_diffs = gh.split_diff_by_file(
            raw_diff
        )

        # Derive changed_lines_map using Dev 2's
        # DiffAnalyzer for consistency
        analyzer = DiffAnalyzer()
        parsed_diffs = analyzer.parse(per_file_diffs)
        changed_lines_map = (
            analyzer.backfill_changed_lines(
                parsed_diffs, {}
            )
        )

        logger.info(
            f"PR review {review_id}: "
            f"{len(per_file_diffs)} files changed, "
            f"{sum(len(v) for v in changed_lines_map.values())} "
            f"lines modified"
        )

        # Clone repo at PR head
        clone_url = (
            pr_metadata.get("clone_url")
            or payload.repo_url
        )
        clone_result = gh.clone_repo(
            clone_url, review_id
        )
        code_path = clone_result["clone_path"]

        # Dispatch Celery task
        task = celery_app.send_task(
            "workers.tasks.sast.run_pr_scan",
            args=[
                review_id,
                code_path,
                changed_lines_map,
                per_file_diffs,
                pr_metadata,
            ],
            queue="sast",
        )

        logger.info(
            f"PR review {review_id}: "
            f"Celery task dispatched: {task.id}"
        )

        return PRReviewResponse(
            review_id=review_id,
            status="queued",
            message=(
                f"PR review queued for "
                f"{owner}/{repo_name}#{payload.pr_number} "
                f"— {len(per_file_diffs)} files, "
                f"{sum(len(v) for v in changed_lines_map.values())} "
                f"changed lines"
            ),
            pr_number=payload.pr_number,
            repo=f"{owner}/{repo_name}",
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        logger.error(
            f"PR review {review_id} failed: {e}",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PR review failed: {str(e)[:200]}",
        )
