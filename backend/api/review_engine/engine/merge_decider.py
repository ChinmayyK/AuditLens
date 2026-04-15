"""
MergeDecider — 100% Config-driven merge/block decision engine.

ZERO HARDCODED VALUES. Every threshold, blocker, and policy
override is loaded from review_config.json via the config dict
passed to decide().

Evaluates:
  1. Policy overrides (v3)
  2. Hard blockers (instant block if any match)
  3. Score + severity count thresholds
  4. Returns approve / request_changes / block
"""
import logging
from typing import Optional

from review_engine.schemas.review import (
    FilteredFindings,
    ScoreResult,
    MergeDecision,
    DecisionResult,
)

logger = logging.getLogger(__name__)


class MergeDecider:
    """
    Evaluates findings and score against config-driven
    thresholds to produce a merge decision.

    All config is received per-call via decide(config=...).
    No __init__-time loading. No caching.
    """

    def decide(
        self,
        score: ScoreResult,
        filtered: FilteredFindings,
        config: dict,
    ) -> DecisionResult:
        """
        Evaluate the merge decision.

        Args:
            score: The computed ScoreResult.
            filtered: Classified findings.
            config: Live config dict from review_config.json.

        Returns:
            DecisionResult with decision + reasons.
        """
        t = config.get("thresholds", {})

        thresholds = {
            "approve": t.get("approve", {}),
            "request_changes": t.get("request_changes", {}),
        }
        hard_blockers = t.get("hard_blockers", [])
        severity_order = t.get(
            "severity_order",
            {
                "critical": 4,
                "high": 3,
                "medium": 2,
                "low": 1,
                "info": 0,
            },
        )
        policy_overrides = t.get("policy_overrides", {})

        reasons: list[str] = []
        hard_blocker_reasons: list[str] = []

        # ── Step 0: Policy overrides ─────────────
        policy_result = self._evaluate_policy_overrides(
            filtered, policy_overrides
        )
        if policy_result:
            logger.info(
                f"Policy override: "
                f"{policy_result.decision.value}"
            )
            return policy_result

        # ── Step 1: Hard blockers ─────────────────────
        for blocker in hard_blockers:
            blocker_category = blocker["category"].lower()
            min_sev = blocker.get(
                "min_severity", "low"
            ).lower()
            min_sev_rank = severity_order.get(
                min_sev, 0
            )
            reason = blocker.get(
                "reason",
                f"Hard blocker: {blocker_category} "
                f"finding at {min_sev}+ severity",
            )

            for cf in filtered.all_actionable:
                finding_sev_rank = severity_order.get(
                    cf.finding.severity, 0
                )
                if (
                    cf.resolved_category == blocker_category
                    and finding_sev_rank >= min_sev_rank
                ):
                    hard_blocker_reasons.append(reason)
                    break

        if hard_blocker_reasons:
            logger.info(
                f"Merge BLOCKED by {len(hard_blocker_reasons)} "
                f"hard blocker(s)"
            )
            return DecisionResult(
                decision=MergeDecision.BLOCK,
                reasons=[
                    "Hard blocker conditions met"
                ],
                hard_blockers=hard_blocker_reasons,
            )

        # ── Step 2: Count severities ───────────────────
        severity_counts = self._count_severities(filtered)
        total_score = score.total_score

        # ── Step 3: Evaluate approve ───────────────────
        approve_cfg = thresholds.get("approve", {})
        if self._meets_threshold(
            total_score, severity_counts, approve_cfg
        ):
            logger.info("Merge decision: APPROVE")
            reasons.append(
                f"Score {total_score} within approve "
                f"threshold (≤{approve_cfg.get('max_score', 'N/A')})"
            )
            return DecisionResult(
                decision=MergeDecision.APPROVE,
                reasons=reasons,
            )

        # ── Step 4: Evaluate request_changes ───────────
        rc_cfg = thresholds.get(
            "request_changes", {}
        )
        if self._meets_threshold(
            total_score, severity_counts, rc_cfg
        ):
            logger.info(
                "Merge decision: REQUEST_CHANGES"
            )
            reasons.append(
                f"Score {total_score} within "
                f"request_changes threshold "
                f"(≤{rc_cfg.get('max_score', 'N/A')})"
            )
            for sev, count in severity_counts.items():
                if count > 0 and sev in (
                    "critical", "high", "medium",
                ):
                    reasons.append(
                        f"{count} {sev} finding(s) "
                        f"need attention"
                    )
            return DecisionResult(
                decision=MergeDecision.REQUEST_CHANGES,
                reasons=reasons,
            )

        # ── Step 5: Block (exceeded all thresholds) ────
        logger.info("Merge decision: BLOCK")
        reasons.append(
            f"Score {total_score} exceeds all "
            f"thresholds"
        )
        for sev, count in severity_counts.items():
            if count > 0 and sev in (
                "critical", "high",
            ):
                reasons.append(
                    f"{count} {sev} finding(s) "
                    f"exceed limits"
                )
        return DecisionResult(
            decision=MergeDecision.BLOCK,
            reasons=reasons,
        )

    def _count_severities(
        self, filtered: FilteredFindings
    ) -> dict[str, int]:
        """Count findings per severity."""
        counts: dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }
        for cf in filtered.all_actionable:
            sev = cf.finding.severity.lower()
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def _meets_threshold(
        self,
        total_score: float,
        severity_counts: dict[str, int],
        threshold_cfg: dict,
    ) -> bool:
        """Check if score + counts are within threshold."""
        max_score = threshold_cfg.get("max_score")
        if max_score is not None and total_score > max_score:
            return False

        max_critical = threshold_cfg.get("max_critical")
        if (
            max_critical is not None
            and severity_counts.get("critical", 0)
            > max_critical
        ):
            return False

        max_high = threshold_cfg.get("max_high")
        if (
            max_high is not None
            and severity_counts.get("high", 0) > max_high
        ):
            return False

        return True

    # ── Policy overrides ───────────────────────

    def _evaluate_policy_overrides(
        self,
        filtered: FilteredFindings,
        policy_overrides: dict,
    ) -> Optional[DecisionResult]:
        """
        Evaluate policy overrides from config.
        Returns DecisionResult if a policy fires.
        """
        if not policy_overrides:
            return None

        overrides_applied: list[str] = []
        actionable = filtered.all_actionable

        if not actionable:
            return None

        # Policy: block_any_new_critical
        if policy_overrides.get(
            "block_any_new_critical", False
        ):
            for cf in actionable:
                if (
                    cf.finding.status == "new"
                    and cf.finding.severity == "critical"
                ):
                    overrides_applied.append(
                        "block_any_new_critical: "
                        f"New critical finding "
                        f"{cf.finding.vuln_type} at "
                        f"{cf.finding.file_path}:"
                        f"{cf.finding.line_number}"
                    )
                    return DecisionResult(
                        decision=MergeDecision.BLOCK,
                        reasons=[
                            "Policy override: new "
                            "critical finding detected"
                        ],
                        policy_overrides_applied=(
                            overrides_applied
                        ),
                    )

        # Policy: require_fix_for_new_secrets
        if policy_overrides.get(
            "require_fix_for_new_secrets", False
        ):
            for cf in actionable:
                if (
                    cf.finding.status == "new"
                    and cf.resolved_category == "secrets"
                    and cf.bucket.value == "relevant"
                ):
                    overrides_applied.append(
                        "require_fix_for_new_secrets: "
                        f"New secret at "
                        f"{cf.finding.file_path}:"
                        f"{cf.finding.line_number}"
                    )
                    return DecisionResult(
                        decision=MergeDecision.BLOCK,
                        reasons=[
                            "Policy override: new "
                            "secret on changed lines"
                        ],
                        policy_overrides_applied=(
                            overrides_applied
                        ),
                    )

        # Policy: auto_approve_existing_only
        if policy_overrides.get(
            "auto_approve_existing_only", False
        ):
            all_existing = all(
                cf.finding.status == "existing"
                for cf in actionable
            )
            if all_existing:
                overrides_applied.append(
                    "auto_approve_existing_only: "
                    "All findings are pre-existing"
                )
                return DecisionResult(
                    decision=MergeDecision.APPROVE,
                    reasons=[
                        "Policy override: all findings "
                        "are pre-existing debt — "
                        "no new issues introduced"
                    ],
                    policy_overrides_applied=(
                        overrides_applied
                    ),
                )

        return None
