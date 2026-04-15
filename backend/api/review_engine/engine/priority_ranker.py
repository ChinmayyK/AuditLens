"""
PriorityRanker — 100% Config-driven multi-factor priority scoring.

ZERO HARDCODED VALUES. All factor weights, exploitability scores,
blast radius patterns, fix effort, recency/corroboration mappings
are loaded from review_config.json via the config dict passed to
rank().

Re-ranks findings beyond raw severity using:
  1. Exploitability (0.35) — how easily can this be exploited?
  2. Blast radius   (0.25) — what's the scope of damage?
  3. Fix effort     (0.15) — how hard is the fix? (easy = higher priority)
  4. Recency        (0.15) — new findings > existing debt
  5. Corroboration  (0.10) — multi-tool agreement = higher confidence
"""
import logging
import re
from typing import Optional

from review_engine.schemas.review import (
    ReviewResult,
    ReviewComment,
)
from review_engine.schemas.intelligence import (
    PrioritizedFinding,
    PriorityFactors,
)

logger = logging.getLogger(__name__)


class PriorityRanker:
    """
    Re-ranks findings using multi-factor priority scoring.

    All config is received per-call via rank(config=...).
    No __init__-time loading. No caching.
    """

    def rank(
        self,
        result: ReviewResult,
        config: dict,
    ) -> list[PrioritizedFinding]:
        """
        Rank all comments by multi-factor priority.

        Args:
            result: ReviewResult from the pipeline.
            config: Live config dict from review_config.json.

        Returns:
            Priority-ranked list of PrioritizedFinding objects.
        """
        w = config.get("weights", {})

        factor_weights = w.get(
            "priority_factor_weights",
            {
                "exploitability": 0.35,
                "blast_radius": 0.25,
                "fix_effort": 0.15,
                "recency": 0.15,
                "corroboration": 0.10,
            },
        )
        exploitability_map = w.get("exploitability", {})
        blast_config = w.get("blast_radius", {})
        fix_effort_map = w.get("fix_effort", {})
        recency_map = w.get(
            "recency",
            {"new": 1.0, "existing": 0.3, "fixed": 0.0},
        )
        corroboration_map = w.get(
            "corroboration_priority",
            {"1": 0.3, "2": 0.7, "3": 0.9, "default": 1.0},
        )

        # Compile blast radius patterns fresh
        blast_patterns = []
        for p in blast_config.get("patterns", []):
            try:
                blast_patterns.append({
                    "regex": re.compile(
                        p["pattern"], re.IGNORECASE
                    ),
                    "score": p["score"],
                    "label": p.get("label", ""),
                })
            except re.error:
                logger.warning(
                    f"Invalid blast radius pattern: "
                    f"{p['pattern']}"
                )

        scored: list[PrioritizedFinding] = []

        for comment in result.comments:
            factors = self._compute_factors(
                comment,
                exploitability_map,
                blast_patterns,
                blast_config,
                fix_effort_map,
                recency_map,
                corroboration_map,
            )
            priority = self._composite_score(
                factors, factor_weights
            )
            reasoning = self._generate_reasoning(
                comment, factors, priority
            )

            scored.append(PrioritizedFinding(
                file_path=comment.file_path,
                line_number=comment.line_number,
                vuln_type=comment.vuln_type,
                severity=comment.severity,
                tool=comment.tool,
                message=comment.body,
                status=comment.status,
                priority_score=round(priority, 1),
                factors=factors,
                reasoning=reasoning,
                fix_suggestion=comment.suggestion,
                category=comment.category,
                tools=comment.corroborated_by or [],
            ))

        scored.sort(
            key=lambda f: f.priority_score,
            reverse=True,
        )

        for i, finding in enumerate(scored):
            finding.priority_rank = i + 1

        logger.info(
            f"Ranked {len(scored)} findings"
        )
        return scored

    def _compute_factors(
        self,
        comment: ReviewComment,
        exploitability_map: dict,
        blast_patterns: list,
        blast_config: dict,
        fix_effort_map: dict,
        recency_map: dict,
        corroboration_map: dict,
    ) -> PriorityFactors:
        """Compute individual factor scores from config."""
        return PriorityFactors(
            exploitability=self._score_exploitability(
                comment, exploitability_map
            ),
            blast_radius=self._score_blast_radius(
                comment, blast_patterns, blast_config
            ),
            fix_effort=self._score_fix_effort(
                comment, fix_effort_map
            ),
            recency=self._score_recency(
                comment, recency_map
            ),
            corroboration=self._score_corroboration(
                comment, corroboration_map
            ),
        )

    def _composite_score(
        self,
        factors: PriorityFactors,
        factor_weights: dict,
    ) -> float:
        """Weighted sum of all factors, scaled 0–100."""
        raw = (
            factors.exploitability
            * factor_weights.get("exploitability", 0.35)
            + factors.blast_radius
            * factor_weights.get("blast_radius", 0.25)
            + factors.fix_effort
            * factor_weights.get("fix_effort", 0.15)
            + factors.recency
            * factor_weights.get("recency", 0.15)
            + factors.corroboration
            * factor_weights.get("corroboration", 0.10)
        )
        return raw * 100

    def _score_exploitability(
        self,
        comment: ReviewComment,
        exploitability_map: dict,
    ) -> float:
        """Score exploitability by category from config."""
        cat = (comment.category or "").lower()
        score = exploitability_map.get(cat)
        if score is not None:
            return float(score)
        return float(
            exploitability_map.get("default", 0.5)
        )

    def _score_blast_radius(
        self,
        comment: ReviewComment,
        blast_patterns: list,
        blast_config: dict,
    ) -> float:
        """Score blast radius by file path from config."""
        fp = comment.file_path or ""
        for pattern in blast_patterns:
            if pattern["regex"].search(fp):
                return pattern["score"]
        return float(
            blast_config.get("default", 0.5)
        )

    def _score_fix_effort(
        self,
        comment: ReviewComment,
        fix_effort_map: dict,
    ) -> float:
        """Score fix effort (inverted) from config."""
        vt = comment.vuln_type or ""
        effort = fix_effort_map.get(vt)
        if effort is None:
            effort = fix_effort_map.get(
                "default", 0.4
            )
        return 1.0 - float(effort)

    def _score_recency(
        self,
        comment: ReviewComment,
        recency_map: dict,
    ) -> float:
        """Score by finding status from config."""
        status = comment.status or "new"
        return float(
            recency_map.get(status, 0.5)
        )

    def _score_corroboration(
        self,
        comment: ReviewComment,
        corroboration_map: dict,
    ) -> float:
        """Score by corroborating tools from config."""
        tools = comment.corroborated_by or []
        count = max(len(tools), 1)
        score = corroboration_map.get(str(count))
        if score is not None:
            return float(score)
        score = corroboration_map.get(count)
        if score is not None:
            return float(score)
        return float(
            corroboration_map.get("default", 0.5)
        )

    def _generate_reasoning(
        self,
        comment: ReviewComment,
        factors: PriorityFactors,
        score: float,
    ) -> str:
        """Generate human-readable priority reasoning."""
        parts = []

        factor_map = {
            "exploitability": factors.exploitability,
            "blast radius": factors.blast_radius,
            "fix ease": factors.fix_effort,
            "recency": factors.recency,
            "corroboration": factors.corroboration,
        }
        top_factor = max(
            factor_map, key=factor_map.get
        )
        parts.append(
            f"Highest factor: {top_factor} "
            f"({factor_map[top_factor]:.0%})"
        )

        if comment.severity in ("critical", "high"):
            parts.append(
                f"{comment.severity} severity"
            )

        if comment.status == "new":
            parts.append("newly introduced")
        elif comment.status == "existing":
            parts.append("pre-existing debt")

        tools = comment.corroborated_by or []
        if len(tools) > 1:
            parts.append(
                f"confirmed by {len(tools)} tools"
            )

        return "; ".join(parts)
