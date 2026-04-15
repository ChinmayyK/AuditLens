"""
PRFormatter — Transforms ReviewResult into GitHub-native
PR Review API format.

Output is ready to POST directly to:
  POST /repos/{owner}/{repo}/pulls/{pull_number}/reviews

Features:
  - Maps MergeDecision → GitHub event type
  - Converts ReviewComments → inline comments
  - Groups adjacent findings into threaded comments
  - Generates summary body from summary_markdown
"""
import logging
from typing import Optional

from review_engine.schemas.review import (
    ReviewResult,
    ReviewComment,
    MergeDecision,
    GitHubPRReview,
    GitHubInlineComment,
)

logger = logging.getLogger(__name__)

# Map our decisions to GitHub PR review events
_EVENT_MAP = {
    MergeDecision.APPROVE: "APPROVE",
    MergeDecision.REQUEST_CHANGES: "REQUEST_CHANGES",
    MergeDecision.BLOCK: "REQUEST_CHANGES",
    # GitHub doesn't have "BLOCK" — we use
    # REQUEST_CHANGES with strong language
}


class PRFormatter:
    """
    Formats ReviewResult for the GitHub PR Review API.
    """

    def format(
        self, result: ReviewResult
    ) -> GitHubPRReview:
        """
        Transform a ReviewResult into a GitHub PR
        review payload.

        Args:
            result: Complete review result.

        Returns:
            GitHubPRReview ready for GitHub API.
        """
        event = _EVENT_MAP.get(
            result.decision.decision,
            "COMMENT",
        )

        # Build inline comments from review comments
        inline = self._build_inline_comments(
            result.comments
        )

        # Group adjacent comments on same file
        inline = self._group_adjacent(inline)

        body = result.summary_markdown or (
            f"ShieldSentinel Security Review: "
            f"{result.decision.decision.value}"
        )

        review = GitHubPRReview(
            event=event,
            body=body,
            comments=inline,
        )

        logger.info(
            f"PRFormatter: {event} with "
            f"{len(inline)} inline comments"
        )
        return review

    def _build_inline_comments(
        self, comments: list[ReviewComment]
    ) -> list[GitHubInlineComment]:
        """Convert ReviewComments to GitHub inline format."""
        inline: list[GitHubInlineComment] = []

        for c in comments:
            if not c.file_path or not c.line_number:
                continue  # Skip comments without location

            body = c.body

            # Append suggestion block if available
            if c.suggestion:
                body += (
                    f"\n\n```suggestion\n"
                    f"{c.suggestion}\n```"
                )

            inline.append(
                GitHubInlineComment(
                    path=c.file_path,
                    line=c.line_number,
                    side=c.side,
                    body=body,
                )
            )

        return inline

    def _group_adjacent(
        self,
        comments: list[GitHubInlineComment],
    ) -> list[GitHubInlineComment]:
        """
        Group comments on adjacent lines (±1) in the
        same file into a single threaded comment.
        This avoids flooding PRs with comment noise.
        """
        if len(comments) <= 1:
            return comments

        # Sort by path then line
        comments.sort(
            key=lambda c: (c.path, c.line)
        )

        grouped: list[GitHubInlineComment] = []
        current: Optional[GitHubInlineComment] = None

        for c in comments:
            if (
                current
                and c.path == current.path
                and abs(c.line - current.line) <= 1
            ):
                # Merge into current comment
                current.body += f"\n\n---\n\n{c.body}"
                # Keep the earlier line number
                current.line = min(
                    current.line, c.line
                )
            else:
                if current:
                    grouped.append(current)
                current = GitHubInlineComment(
                    path=c.path,
                    line=c.line,
                    side=c.side,
                    body=c.body,
                )

        if current:
            grouped.append(current)

        if len(grouped) < len(comments):
            logger.info(
                f"Grouped {len(comments)} comments "
                f"into {len(grouped)}"
            )

        return grouped
