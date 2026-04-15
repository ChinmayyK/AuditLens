"""
SummaryBuilder — Assembles all engine outputs into a
structured ReviewResult with a rendered Markdown summary.
"""
import logging
from pathlib import Path
from typing import Optional

import yaml
from jinja2 import Environment, BaseLoader

from review_engine.schemas.review import (
    FilteredFindings,
    ReviewComment,
    ScoreResult,
    DecisionResult,
    ReviewResult,
)

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = (
    Path(__file__).parent.parent
    / "config"
    / "comment_templates.yaml"
)


class SummaryBuilder:
    """
    Assembles comments, score, and decision into the
    final ReviewResult with a Markdown summary.
    """

    def __init__(
        self, config_path: Optional[Path] = None
    ):
        path = config_path or _DEFAULT_CONFIG_PATH
        with open(path, "r") as f:
            self._config = yaml.safe_load(f)

        self._summary_template: str = self._config.get(
            "summary", ""
        )
        self._decision_emojis: dict = self._config.get(
            "decision_emojis",
            {
                "approve": "✅",
                "request_changes": "⚠️",
                "block": "🚫",
            },
        )
        self._jinja_env = Environment(
            loader=BaseLoader(),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def build(
        self,
        comments: list[ReviewComment],
        score: ScoreResult,
        decision: DecisionResult,
        filtered: FilteredFindings,
    ) -> ReviewResult:
        """
        Build the complete ReviewResult.

        Args:
            comments: Rendered review comments.
            score: Computed score.
            decision: Merge decision.
            filtered: Classified findings.

        Returns:
            ReviewResult with all data + summary markdown.
        """
        relevant_count = len(filtered.relevant)
        contextual_count = len(filtered.contextual)
        unrelated_count = len(filtered.unrelated)
        total_findings = (
            relevant_count
            + contextual_count
            + unrelated_count
        )

        # Build top issues (top 5 by impact)
        top_issues = sorted(
            comments,
            key=lambda c: c.impact,
            reverse=True,
        )[:5]

        # Render summary markdown
        summary_md = self._render_summary(
            score=score,
            decision=decision,
            total_findings=total_findings,
            relevant_count=relevant_count,
            contextual_count=contextual_count,
            top_issues=top_issues,
            # v3 context
            new_count=score.new_findings_count,
            existing_count=(
                score.existing_findings_count
            ),
            correlated_groups=(
                score.correlated_groups
            ),
            policy_overrides=(
                decision.policy_overrides_applied
            ),
        )

        result = ReviewResult(
            comments=comments,
            score=score,
            decision=decision,
            summary_markdown=summary_md,
            total_findings=total_findings,
            relevant_count=relevant_count,
            contextual_count=contextual_count,
            unrelated_count=unrelated_count,
        )

        logger.info(
            f"Review built: {total_findings} findings, "
            f"score={score.total_score}, "
            f"decision={decision.decision.value}"
        )
        return result

    def _render_summary(
        self,
        score: ScoreResult,
        decision: DecisionResult,
        total_findings: int,
        relevant_count: int,
        contextual_count: int,
        top_issues: list[ReviewComment],
        # v3 context
        new_count: int = 0,
        existing_count: int = 0,
        correlated_groups: int = 0,
        policy_overrides: Optional[list[str]] = None,
    ) -> str:
        """Render the Markdown summary using Jinja2."""
        if not self._summary_template:
            return self._fallback_summary(
                score, decision, total_findings
            )

        decision_emoji = self._decision_emojis.get(
            decision.decision.value, "❓"
        )

        # Combine hard_blockers + reasons for template
        all_blockers = (
            decision.hard_blockers + decision.reasons
        )

        try:
            template = self._jinja_env.from_string(
                self._summary_template
            )
            return template.render(
                score=score.total_score,
                max_score=score.max_score,
                decision=decision.decision.value,
                decision_emoji=decision_emoji,
                total_findings=total_findings,
                relevant_count=relevant_count,
                contextual_count=contextual_count,
                severity_breakdown=[
                    s.model_dump()
                    for s in score.severity_breakdown
                ],
                tool_breakdown=[
                    t.model_dump()
                    for t in score.tool_breakdown
                ],
                blockers=all_blockers,
                top_issues=[
                    c.model_dump() for c in top_issues
                ],
                # v3 context
                new_count=new_count,
                existing_count=existing_count,
                correlated_groups=correlated_groups,
                policy_overrides=(
                    policy_overrides or []
                ),
            ).strip()
        except Exception as e:
            logger.warning(
                f"Summary template render failed: {e}"
            )
            return self._fallback_summary(
                score, decision, total_findings
            )

    def _fallback_summary(
        self,
        score: ScoreResult,
        decision: DecisionResult,
        total_findings: int,
    ) -> str:
        """Plain-text fallback if template fails."""
        return (
            f"## Security Review\n\n"
            f"Score: {score.total_score}/{score.max_score}\n"
            f"Decision: {decision.decision.value}\n"
            f"Total Findings: {total_findings}\n"
        )
