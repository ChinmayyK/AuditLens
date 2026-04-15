"""
GitHubPublisher — Posts review results to GitHub PRs.

This is a pure HTTP transport layer. All formatting,
scoring, and comment generation is handled by Dev 2's
ReviewEngine. This module just POSTs the ready-made
payloads to the GitHub REST API.
"""
import os
import logging
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

GITHUB_API_BASE = "https://api.github.com"


class GitHubPublisher:
    """Posts review results to GitHub Pull Requests."""

    def __init__(
        self, token: Optional[str] = None
    ):
        self.token = token or os.getenv(
            "GITHUB_TOKEN", ""
        )
        if not self.token:
            logger.warning(
                "GITHUB_TOKEN not set — "
                "publishing will fail"
            )

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": (
                "application/vnd.github.v3+json"
            ),
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def post_pr_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        head_sha: str,
        pr_review,
    ) -> dict:
        """
        Submit a pull request review to GitHub.

        POST /repos/{owner}/{repo}/pulls/{pr_number}/reviews

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: Pull request number.
            head_sha: Commit SHA to attach review to.
            pr_review: GitHubPRReview object from Dev 2's
                       PRFormatter. Contains event, body,
                       and inline comments.

        Returns:
            GitHub API response as dict.
        """
        url = (
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
            f"/pulls/{pr_number}/reviews"
        )

        # Build payload from Dev 2's GitHubPRReview
        payload = {
            "commit_id": head_sha,
            "event": pr_review.event,
            "body": pr_review.body,
            "comments": [
                {
                    "path": c.path,
                    "line": c.line,
                    "side": c.side,
                    "body": c.body,
                }
                for c in pr_review.comments
            ],
        }

        logger.info(
            f"Posting PR review: {pr_review.event} "
            f"with {len(pr_review.comments)} inline "
            f"comments to {owner}/{repo}#{pr_number}"
        )

        try:
            resp = httpx.post(
                url,
                json=payload,
                headers=self._headers(),
                timeout=30,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                f"PR review posted: "
                f"{result.get('id', 'unknown')}"
            )
            return result
        except httpx.HTTPStatusError as e:
            logger.error(
                f"GitHub API error posting review: "
                f"{e.response.status_code} — "
                f"{e.response.text[:300]}"
            )
            raise
        except Exception as e:
            logger.error(
                f"Failed to post PR review: {e}"
            )
            raise

    def post_summary_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        summary_markdown: str,
    ) -> dict:
        """
        Post a standalone summary comment on the PR.

        POST /repos/{owner}/{repo}/issues/{pr_number}/comments

        Uses the Issues API (PRs are issues in GitHub).

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: Pull request number.
            summary_markdown: Full summary markdown
                from ReviewResult.summary_markdown.

        Returns:
            GitHub API response as dict.
        """
        url = (
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
            f"/issues/{pr_number}/comments"
        )

        payload = {"body": summary_markdown}

        logger.info(
            f"Posting summary comment to "
            f"{owner}/{repo}#{pr_number}"
        )

        try:
            resp = httpx.post(
                url,
                json=payload,
                headers=self._headers(),
                timeout=30,
            )
            resp.raise_for_status()
            result = resp.json()
            logger.info(
                f"Summary comment posted: "
                f"{result.get('id', 'unknown')}"
            )
            return result
        except httpx.HTTPStatusError as e:
            logger.error(
                f"GitHub API error posting comment: "
                f"{e.response.status_code} — "
                f"{e.response.text[:300]}"
            )
            raise
        except Exception as e:
            logger.error(
                f"Failed to post summary comment: {e}"
            )
            raise

    def post_acknowledgment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        message: str,
    ) -> dict:
        """
        Post an acknowledgment comment on the PR.

        Used for re-scan triggers when a user
        comments 'fixed'.

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: Pull request number.
            message: Comment body text.

        Returns:
            GitHub API response as dict.
        """
        url = (
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
            f"/issues/{pr_number}/comments"
        )

        payload = {"body": message}

        try:
            resp = httpx.post(
                url,
                json=payload,
                headers=self._headers(),
                timeout=15,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.warning(
                f"Acknowledgment comment failed: {e}"
            )
            return {}
