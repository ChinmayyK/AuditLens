"""
NarrativeBuilder — Human-like narrative summary generation.

Produces a compelling, readable narrative that sounds like
a senior engineer wrote it. Uses Jinja2 templates from
config/narrative_templates.yaml.

Also generates:
  - Executive summary (one paragraph)
  - Risk assessment
  - Full intelligence report narrative
"""
import logging
from pathlib import Path
from typing import Optional

import yaml
from jinja2 import Template

from review_engine.schemas.review import ReviewResult
from review_engine.schemas.intelligence import (
    IntelligenceReport,
    DecisionExplanation,
    ReviewInsight,
    RiskAssessment,
    PrioritizedFinding,
)

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = (
    Path(__file__).parent.parent
    / "config"
    / "narrative_templates.yaml"
)

# Category → data exposure mapping
_DATA_EXPOSURE = {
    "injection": "high",
    "secrets": "critical",
    "authentication": "high",
    "authorization": "high",
    "xss": "medium",
    "crypto": "medium",
    "ssrf": "medium",
    "misconfiguration": "low",
    "information_disclosure": "medium",
}

# Category → auth impact mapping
_AUTH_IMPACT = {
    "authentication": "direct",
    "authorization": "direct",
    "secrets": "indirect",
    "injection": "potential",
}


class NarrativeBuilder:
    """
    Generates human-like narrative summaries.
    """

    def __init__(
        self, config_path: Optional[Path] = None
    ):
        path = config_path or _DEFAULT_CONFIG
        with open(path, "r") as f:
            self._config = yaml.safe_load(f)

        self._exec_template = None
        self._narrative_template = None

        exec_src = self._config.get(
            "executive_summary", ""
        )
        if exec_src:
            self._exec_template = Template(exec_src)

        narr_src = self._config.get("narrative", "")
        if narr_src:
            self._narrative_template = Template(
                narr_src
            )

        logger.info("NarrativeBuilder initialized")

    def build(
        self,
        result: ReviewResult,
        prioritized: list[PrioritizedFinding],
        explanation: DecisionExplanation,
        insights: list[ReviewInsight],
        repo_context: Optional[dict] = None,
    ) -> IntelligenceReport:
        """
        Build the full IntelligenceReport.

        Args:
            result: Completed ReviewResult from v3
            prioritized: Priority-ranked findings
            explanation: Decision explanation
            insights: Generated insights
            repo_context: Optional repo metadata

        Returns:
            IntelligenceReport with all intelligence.
        """
        # Risk assessment
        risk = self._assess_risk(
            result, prioritized
        )

        # Executive summary
        top_finding = (
            prioritized[0] if prioritized else None
        )
        exec_summary = self._render_executive(
            result, top_finding
        )

        # Full narrative
        narrative = self._render_narrative(
            result=result,
            prioritized=prioritized,
            explanation=explanation,
            insights=insights,
            risk_assessment=risk,
            executive_summary=exec_summary,
        )

        report = IntelligenceReport(
            score=result.score.total_score,
            decision=result.decision.decision.value,
            total_findings=result.total_findings,
            new_findings=result.new_findings_count,
            existing_findings=(
                result.existing_findings_count
            ),
            correlated_groups=result.correlated_groups,
            prioritized_findings=prioritized,
            explanation=explanation,
            insights=insights,
            risk_assessment=risk,
            narrative=narrative,
            executive_summary=exec_summary,
            engine_version="v4",
            repo_context=repo_context or {},
        )

        logger.info(
            f"Intelligence report built: "
            f"{result.decision.decision.value} "
            f"with {len(insights)} insights"
        )
        return report

    def _render_executive(
        self,
        result: ReviewResult,
        top_finding: Optional[PrioritizedFinding],
    ) -> str:
        """Render the executive summary paragraph."""
        if not self._exec_template:
            return self._fallback_executive(
                result, top_finding
            )

        try:
            ctx = {
                "new_count": result.new_findings_count,
                "existing_count": (
                    result.existing_findings_count
                ),
                "decision": (
                    result.decision.decision.value
                ),
                "score": result.score.total_score,
                "top_finding": (
                    top_finding.model_dump()
                    if top_finding
                    else None
                ),
                "total_findings": result.total_findings,
            }
            return self._exec_template.render(
                **ctx
            ).strip()
        except Exception as e:
            logger.warning(
                f"Executive template error: {e}"
            )
            return self._fallback_executive(
                result, top_finding
            )

    def _render_narrative(
        self,
        result: ReviewResult,
        prioritized: list[PrioritizedFinding],
        explanation: DecisionExplanation,
        insights: list[ReviewInsight],
        risk_assessment: RiskAssessment,
        executive_summary: str,
    ) -> str:
        """Render the full narrative."""
        if not self._narrative_template:
            return executive_summary

        try:
            ctx = {
                "executive_summary": executive_summary,
                "prioritized": [
                    f.model_dump()
                    for f in prioritized
                ],
                "explanation": (
                    explanation.model_dump()
                ),
                "insights": [
                    i.model_dump() for i in insights
                ],
                "risk_assessment": (
                    risk_assessment.model_dump()
                ),
                "decision": (
                    result.decision.decision.value
                ),
                "score": result.score.total_score,
                "new_count": result.new_findings_count,
                "existing_count": (
                    result.existing_findings_count
                ),
            }
            return self._narrative_template.render(
                **ctx
            ).strip()
        except Exception as e:
            logger.warning(
                f"Narrative template error: {e}"
            )
            return executive_summary

    def _assess_risk(
        self,
        result: ReviewResult,
        prioritized: list[PrioritizedFinding],
    ) -> RiskAssessment:
        """Generate risk assessment from findings."""
        score = result.score.total_score

        # Risk level from score
        if score >= 70:
            level = "critical"
        elif score >= 50:
            level = "high"
        elif score >= 25:
            level = "medium"
        elif score > 0:
            level = "low"
        else:
            level = "safe"

        # Attack surface
        if result.new_findings_count > 0:
            attack_surface = "expanded"
        elif (
            result.score.fixed_findings_count > 0
        ):
            attack_surface = "reduced"
        else:
            attack_surface = "unchanged"

        # Data exposure
        data_exposure = "none"
        auth_impact = "none"
        for c in result.comments:
            cat = (c.category or "").lower()
            de = _DATA_EXPOSURE.get(cat)
            if de and _sev_rank(de) > _sev_rank(
                data_exposure
            ):
                data_exposure = de
            ai = _AUTH_IMPACT.get(cat)
            if ai:
                auth_impact = ai

        # Summary
        if level == "safe":
            summary = (
                "No significant security risk "
                "detected in this change."
            )
        elif level == "low":
            summary = (
                "Minor security observations. "
                "Low risk to production."
            )
        elif level == "medium":
            summary = (
                "Moderate security concerns that "
                "should be addressed before "
                "deployment."
            )
        elif level == "high":
            summary = (
                "Significant security issues "
                "detected. Remediation required "
                "before merge."
            )
        else:
            summary = (
                "Critical security vulnerabilities "
                "detected. Immediate attention "
                "required."
            )

        return RiskAssessment(
            risk_level=level,
            risk_score=score,
            risk_summary=summary,
            attack_surface_change=attack_surface,
            data_exposure_risk=data_exposure,
            auth_impact=auth_impact,
        )

    def _fallback_executive(
        self,
        result: ReviewResult,
        top_finding: Optional[PrioritizedFinding],
    ) -> str:
        """Fallback executive summary without template."""
        decision = result.decision.decision.value
        new = result.new_findings_count
        existing = result.existing_findings_count

        if new == 0 and existing == 0:
            return (
                "This PR looks clean — no security "
                "findings detected. ✅"
            )
        elif new == 0:
            return (
                f"This PR doesn't introduce new "
                f"security issues. {existing} "
                f"pre-existing finding(s) noted."
            )
        else:
            top_desc = ""
            if top_finding:
                top_desc = (
                    f", most critically a "
                    f"{top_finding.severity} "
                    f"{top_finding.vuln_type} in "
                    f"{top_finding.file_path}"
                )
            return (
                f"This PR introduces {new} new "
                f"security issue(s){top_desc}. "
                f"Decision: {decision.upper()}."
            )


def _sev_rank(level: str) -> int:
    """Rank severity/risk levels."""
    return {
        "none": 0, "low": 1, "medium": 2,
        "high": 3, "critical": 4, "direct": 4,
        "indirect": 3, "potential": 2,
    }.get(level, 0)
