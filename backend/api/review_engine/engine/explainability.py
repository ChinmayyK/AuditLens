"""
ExplainabilityEngine — Decision reasoning and what-if analysis.

Generates structured explanations for WHY a review decision
was made. Mimics a senior engineer's reasoning:

  1. Causal chain — step-by-step logic to the decision
  2. Key factors — top drivers of the decision
  3. What-if analysis — what would change the outcome
  4. Confidence assessment — how certain the engine is

Operates as a post-processor on ReviewResult.
"""
import logging
from typing import Optional

from review_engine.schemas.review import (
    ReviewResult,
    DecisionResult,
    ScoreResult,
    ReviewComment,
)
from review_engine.schemas.intelligence import (
    DecisionExplanation,
    CausalStep,
    WhatIfScenario,
    PrioritizedFinding,
)

logger = logging.getLogger(__name__)

# Severity rank for comparison
_SEV_RANK = {
    "critical": 4, "high": 3, "medium": 2,
    "low": 1, "info": 0,
}


class ExplainabilityEngine:
    """
    Generates structured decision explanations.
    """

    def explain(
        self,
        result: ReviewResult,
        prioritized: Optional[
            list[PrioritizedFinding]
        ] = None,
    ) -> DecisionExplanation:
        """
        Generate a full decision explanation.

        Args:
            result: Completed ReviewResult from v3
            prioritized: Optional priority-ranked findings

        Returns:
            DecisionExplanation with causal chain,
            key factors, what-if, and confidence.
        """
        decision = result.decision
        score = result.score

        causal_chain = self._build_causal_chain(
            result, prioritized
        )
        key_factors = self._extract_key_factors(
            result
        )
        what_if = self._generate_what_if(
            result, prioritized
        )
        confidence = self._assess_confidence(result)
        confidence_text = self._confidence_text(
            confidence, result
        )

        explanation = DecisionExplanation(
            decision=decision.decision.value,
            confidence=confidence,
            causal_chain=causal_chain,
            key_factors=key_factors,
            what_if=what_if,
            confidence_assessment=confidence_text,
        )

        logger.info(
            f"Explanation generated: "
            f"{decision.decision.value} "
            f"(confidence={confidence:.0%})"
        )
        return explanation

    def _build_causal_chain(
        self,
        result: ReviewResult,
        prioritized: Optional[
            list[PrioritizedFinding]
        ],
    ) -> list[CausalStep]:
        """Build step-by-step reasoning chain."""
        steps = []
        step_num = 1
        decision = result.decision
        score = result.score

        # Step 1: What triggered the review
        steps.append(CausalStep(
            step=step_num,
            description=(
                f"Analyzed {result.total_findings} "
                f"finding(s) across "
                f"{result.relevant_count} changed "
                f"line(s)"
            ),
            evidence=(
                f"{result.new_findings_count} new, "
                f"{result.existing_findings_count} "
                f"existing"
            ),
        ))
        step_num += 1

        # Step 2: Correlated findings
        if result.correlated_groups > 0:
            steps.append(CausalStep(
                step=step_num,
                description=(
                    f"Cross-tool correlation merged "
                    f"findings into "
                    f"{result.correlated_groups} "
                    f"corroborated group(s)"
                ),
                evidence=(
                    "Multiple tools agree on "
                    "the same vulnerability"
                ),
            ))
            step_num += 1

        # Step 3: Top finding
        if prioritized and len(prioritized) > 0:
            top = prioritized[0]
            steps.append(CausalStep(
                step=step_num,
                description=(
                    f"Highest priority: "
                    f"{top.vuln_type} ({top.severity})"
                    f" in {top.file_path or 'unknown'}"
                    f":{top.line_number or '?'}"
                ),
                evidence=(
                    f"Priority score: "
                    f"{top.priority_score}/100"
                ),
            ))
            step_num += 1

        # Step 4: Score computation
        steps.append(CausalStep(
            step=step_num,
            description=(
                f"Risk score computed: "
                f"{score.total_score}/{score.max_score}"
            ),
            evidence=(
                f"Based on severity weights, "
                f"tool trust, status, and "
                f"change risk multipliers"
            ),
        ))
        step_num += 1

        # Step 5: Policy overrides
        if decision.policy_overrides_applied:
            for override in (
                decision.policy_overrides_applied
            ):
                steps.append(CausalStep(
                    step=step_num,
                    description=(
                        f"Policy override fired: "
                        f"{override.split(':')[0]}"
                    ),
                    evidence=override,
                ))
                step_num += 1

        # Step 6: Hard blockers
        if decision.hard_blockers:
            for blocker in decision.hard_blockers:
                steps.append(CausalStep(
                    step=step_num,
                    description=(
                        f"Hard blocker triggered"
                    ),
                    evidence=blocker,
                ))
                step_num += 1

        # Final step: Decision
        steps.append(CausalStep(
            step=step_num,
            description=(
                f"Final decision: "
                f"{decision.decision.value.upper()}"
            ),
            evidence=(
                "; ".join(decision.reasons)
                if decision.reasons
                else "Based on score thresholds"
            ),
        ))

        return steps

    def _extract_key_factors(
        self, result: ReviewResult
    ) -> list[str]:
        """Extract top 3 factors that drove the decision."""
        factors = []
        decision = result.decision
        score = result.score

        # Factor 1: Score
        factors.append(
            f"Risk score: {score.total_score}"
            f"/{score.max_score}"
        )

        # Factor 2: Policy overrides
        if decision.policy_overrides_applied:
            factors.append(
                f"Policy override: "
                f"{decision.policy_overrides_applied[0]}"
            )
        elif decision.hard_blockers:
            factors.append(
                f"Hard blocker: "
                f"{decision.hard_blockers[0]}"
            )

        # Factor 3: New vs existing
        if result.new_findings_count > 0:
            factors.append(
                f"{result.new_findings_count} new "
                f"finding(s) introduced in this PR"
            )
        elif result.existing_findings_count > 0:
            factors.append(
                f"All {result.existing_findings_count}"
                f" finding(s) are pre-existing"
            )
        else:
            factors.append("No findings detected")

        # Factor 4: Corroboration
        if result.correlated_groups > 0:
            factors.append(
                f"{result.correlated_groups} "
                f"finding(s) confirmed by multiple "
                f"tools"
            )

        return factors[:4]

    def _generate_what_if(
        self,
        result: ReviewResult,
        prioritized: Optional[
            list[PrioritizedFinding]
        ],
    ) -> list[WhatIfScenario]:
        """Generate what-if scenarios."""
        scenarios = []
        decision = result.decision.decision.value

        # What if top finding were fixed?
        if (
            prioritized
            and len(prioritized) > 0
            and decision in ("block", "request_changes")
        ):
            top = prioritized[0]
            if top.status == "new":
                # Estimate new decision
                remaining_new = (
                    result.new_findings_count - 1
                )
                if remaining_new == 0:
                    new_decision = "approve"
                else:
                    new_decision = "request_changes"

                scenarios.append(WhatIfScenario(
                    condition=(
                        f"the {top.vuln_type} at "
                        f"{top.file_path}:"
                        f"{top.line_number} were fixed"
                    ),
                    outcome=(
                        f"risk score would decrease "
                        f"significantly"
                    ),
                    new_decision=new_decision,
                ))

        # What if all findings were fixed?
        if (
            decision != "approve"
            and result.new_findings_count > 1
        ):
            scenarios.append(WhatIfScenario(
                condition=(
                    f"all {result.new_findings_count} "
                    f"new findings were resolved"
                ),
                outcome=(
                    "no new issues would remain"
                ),
                new_decision="approve",
            ))

        # What if this were existing debt?
        if (
            result.new_findings_count > 0
            and decision == "block"
        ):
            scenarios.append(WhatIfScenario(
                condition=(
                    "all findings were pre-existing "
                    "(not introduced by this PR)"
                ),
                outcome=(
                    "auto_approve_existing_only "
                    "policy would apply"
                ),
                new_decision="approve",
            ))

        return scenarios

    def _assess_confidence(
        self, result: ReviewResult
    ) -> float:
        """
        Assess confidence in the decision.
        Higher when: more tools agree, more findings
        are on changed lines, policy overrides fire.
        """
        confidence = 0.5  # Base

        # Boost for corroboration
        if result.correlated_groups > 0:
            confidence += 0.15

        # Boost for high relevance ratio
        if result.total_findings > 0:
            relevance_pct = (
                result.relevant_count
                / result.total_findings
            )
            confidence += relevance_pct * 0.15

        # Boost for policy override (clear-cut decision)
        if result.decision.policy_overrides_applied:
            confidence += 0.15

        # Boost for hard blockers
        if result.decision.hard_blockers:
            confidence += 0.10

        # Penalty for mixed new/existing
        if (
            result.new_findings_count > 0
            and result.existing_findings_count > 0
        ):
            confidence -= 0.05

        return min(max(confidence, 0.1), 1.0)

    def _confidence_text(
        self, confidence: float, result: ReviewResult
    ) -> str:
        """Generate human-readable confidence text."""
        if confidence >= 0.85:
            level = "Very high"
            reason = (
                "multiple signals align on this "
                "decision"
            )
        elif confidence >= 0.70:
            level = "High"
            reason = (
                "strong evidence supports this "
                "decision"
            )
        elif confidence >= 0.50:
            level = "Moderate"
            reason = (
                "some uncertainty remains — "
                "manual review recommended"
            )
        else:
            level = "Low"
            reason = (
                "limited evidence available — "
                "manual review strongly recommended"
            )

        return (
            f"{level} confidence "
            f"({confidence:.0%}): {reason}"
        )
