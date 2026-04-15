"""
GitHub Webhook Listener — Re-review trigger.

POST /api/v1/webhooks/github
    Listens for GitHub issue_comment events.
    If a user comments "fixed" on a PR, triggers
    a delta-scan (re-fetches diff, re-scans).

Security: HMAC-SHA256 signature verification
using X-Hub-Signature-256 header.
"""
import os
import hmac
import hashlib
import uuid
import logging

from fastapi import (
    APIRouter, HTTPException, Request,
    status,
)

from packages.scanner.github_service import (
    GitHubService,
)
from packages.scanner.github_publisher import (
    GitHubPublisher,
)
from review_engine.engine.diff_analyzer import (
    DiffAnalyzer,
)
from workers.celery_app import celery_app

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/webhooks",
    tags=["webhooks"],
)

WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "")


def _verify_github_signature(
    payload: bytes, signature: str
) -> bool:
    """
    Verify GitHub webhook HMAC-SHA256 signature.

    Args:
        payload: Raw request body bytes.
        signature: X-Hub-Signature-256 header value.

    Returns:
        True if signature is valid.
    """
    if not WEBHOOK_SECRET:
        logger.warning(
            "WEBHOOK_SECRET not set — "
            "skipping signature verification"
        )
        return True

    expected = (
        "sha256="
        + hmac.new(
            WEBHOOK_SECRET.encode(),
            payload,
            hashlib.sha256,
        ).hexdigest()
    )
    return hmac.compare_digest(expected, signature)


@router.post(
    "/github",
    summary="GitHub Webhook Listener",
    description=(
        "Receives GitHub webhook events. Currently "
        "handles issue_comment events to detect "
        "'fixed' comments and trigger PR re-scans."
    ),
)
async def github_webhook(request: Request):
    """
    GitHub webhook handler for re-review triggers.

    Flow:
    1. Verify HMAC-SHA256 signature
    2. Check event type (issue_comment only)
    3. Check if comment contains 'fixed'
    4. Check if the issue is a PR (not a regular issue)
    5. Post acknowledgment comment
    6. Dispatch run_pr_scan (delta-scan)
    7. Return 200 OK
    """
    # Read raw body for signature verification
    body = await request.body()

    # Verify signature
    signature = request.headers.get(
        "X-Hub-Signature-256", ""
    )
    if not _verify_github_signature(body, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature",
        )

    # Parse event
    event_type = request.headers.get(
        "X-GitHub-Event", ""
    )
    payload = await request.json()

    logger.info(
        f"Webhook received: event={event_type}, "
        f"action={payload.get('action', 'unknown')}"
    )

    # Only handle issue_comment events
    if event_type != "issue_comment":
        return {
            "status": "ignored",
            "reason": f"Event '{event_type}' not handled",
        }

    # Check action is 'created' (not edited/deleted)
    if payload.get("action") != "created":
        return {
            "status": "ignored",
            "reason": "Only 'created' actions handled",
        }

    # Check if comment contains 'fixed'
    comment_body = (
        payload.get("comment", {})
        .get("body", "")
        .lower()
    )
    if "fixed" not in comment_body:
        return {
            "status": "ignored",
            "reason": "Comment does not contain 'fixed'",
        }

    # Check if this is a PR (not a regular issue)
    issue = payload.get("issue", {})
    if "pull_request" not in issue:
        return {
            "status": "ignored",
            "reason": "Comment is on an issue, not a PR",
        }

    # Extract PR info
    repo_data = payload.get("repository", {})
    repo_url = repo_data.get(
        "html_url", ""
    )
    pr_number = issue.get("number")
    commenter = (
        payload.get("comment", {})
        .get("user", {})
        .get("login", "unknown")
    )

    if not repo_url or not pr_number:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing repo_url or pr_number",
        )

    logger.info(
        f"Re-review triggered by @{commenter} "
        f"on {repo_url}#{pr_number}"
    )

    gh = GitHubService()
    publisher = GitHubPublisher()
    review_id = str(uuid.uuid4())

    try:
        # Parse repo URL
        owner, repo_name = gh.parse_repo_url(repo_url)

        # Post acknowledgment comment
        publisher.post_acknowledgment(
            owner,
            repo_name,
            pr_number,
            (
                "🔄 **AuditLens Re-Scan Triggered**\n\n"
                f"@{commenter} commented `fixed`. "
                "Re-scanning PR with latest changes...\n\n"
                f"Review ID: `{review_id}`"
            ),
        )

        # Fetch fresh PR data
        pr_metadata = gh.fetch_pr_metadata(
            owner, repo_name, pr_number
        )
        raw_diff = gh.fetch_pr_diff(
            owner, repo_name, pr_number
        )
        per_file_diffs = gh.split_diff_by_file(
            raw_diff
        )

        # Derive changed_lines_map
        analyzer = DiffAnalyzer()
        parsed_diffs = analyzer.parse(per_file_diffs)
        changed_lines_map = (
            analyzer.backfill_changed_lines(
                parsed_diffs, {}
            )
        )

        # Clone at latest head SHA
        clone_url = (
            pr_metadata.get("clone_url")
            or repo_url
        )
        clone_result = gh.clone_repo(
            clone_url, review_id
        )
        code_path = clone_result["clone_path"]

        # Dispatch Celery task (same task as WS2)
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
            f"Re-review {review_id}: "
            f"Celery task dispatched: {task.id}"
        )

        return {
            "status": "re_scan_queued",
            "review_id": review_id,
            "pr_number": pr_number,
            "triggered_by": commenter,
        }

    except Exception as e:
        logger.error(
            f"Re-review {review_id} failed: {e}",
            exc_info=True,
        )
        # Still return 200 to GitHub
        # (avoid webhook retry storms)
        return {
            "status": "error",
            "message": str(e)[:200],
        }
