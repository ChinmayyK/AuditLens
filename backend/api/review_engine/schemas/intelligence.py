"""
Intelligence Layer Schemas (v4).

Output models for the intelligence post-processing layer:
  - PrioritizedFinding: re-ranked finding with multi-factor priority
  - DecisionExplanation: WHY the decision was made
  - ReviewInsight: pattern-level observation
  - IntelligenceReport: top-level wrapper with narrative
"""
from typing import Optional
from pydantic import BaseModel, Field


# ── Priority Ranking ──────────────────────────────────


class PriorityFactors(BaseModel):
    """Breakdown of priority scoring factors."""
    exploitability: float = Field(
        0.0,
        description="How easily exploitable (0–1)",
    )
    blast_radius: float = Field(
        0.0,
        description="Scope of potential damage (0–1)",
    )
    fix_effort: float = Field(
        0.0,
        description=(
            "Estimated fix difficulty "
            "(0=easy, 1=hard). Inverted: "
            "easy fixes get higher priority."
        ),
    )
    recency: float = Field(
        0.0,
        description="New vs existing (0–1)",
    )
    corroboration: float = Field(
        0.0,
        description="Multi-tool agreement (0–1)",
    )


class PrioritizedFinding(BaseModel):
    """A finding re-ranked with intelligent priority."""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    vuln_type: str = ""
    severity: str = ""
    tool: str = ""
    message: str = ""
    status: str = "new"
    # Priority intelligence
    priority_score: float = Field(
        0.0,
        description="Composite priority score (0–100)",
    )
    priority_rank: int = Field(
        0,
        description="1-indexed rank (1 = highest priority)",
    )
    factors: PriorityFactors = Field(
        default_factory=PriorityFactors,
    )
    reasoning: str = Field(
        "",
        description=(
            "Human-readable explanation of "
            "why this priority was assigned"
        ),
    )
    fix_suggestion: Optional[str] = None
    category: Optional[str] = None
    tools: list[str] = Field(default_factory=list)


# ── Decision Explainability ───────────────────────────


class CausalStep(BaseModel):
    """One step in a causal reasoning chain."""
    step: int = 0
    description: str = ""
    evidence: str = ""


class WhatIfScenario(BaseModel):
    """What would change if a condition were different."""
    condition: str = ""
    outcome: str = ""
    new_decision: str = ""


class DecisionExplanation(BaseModel):
    """
    Structured explanation of WHY a decision was made.
    Mimics a senior engineer's reasoning process.
    """
    decision: str = ""
    confidence: float = Field(
        0.0,
        description="Engine confidence in decision (0–1)",
    )
    causal_chain: list[CausalStep] = Field(
        default_factory=list,
        description="Step-by-step reasoning chain",
    )
    key_factors: list[str] = Field(
        default_factory=list,
        description="Top factors that drove the decision",
    )
    what_if: list[WhatIfScenario] = Field(
        default_factory=list,
        description=(
            "What would change if conditions "
            "were different"
        ),
    )
    confidence_assessment: str = Field(
        "",
        description=(
            "Human-readable confidence "
            "assessment"
        ),
    )


# ── Review Insights ───────────────────────────────────


class InsightEvidence(BaseModel):
    """Evidence supporting an insight."""
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    detail: str = ""


class ReviewInsight(BaseModel):
    """A pattern-level observation about the review."""
    insight_type: str = Field(
        "",
        description=(
            "hotspot | category_cluster | "
            "false_positive_signal | fix_group | "
            "trend"
        ),
    )
    severity: str = Field(
        "info",
        description=(
            "Impact level of the insight itself"
        ),
    )
    title: str = ""
    description: str = ""
    evidence: list[InsightEvidence] = Field(
        default_factory=list,
    )
    recommendation: str = ""
    emoji: str = "💡"


# ── Risk Assessment ───────────────────────────────────


class RiskAssessment(BaseModel):
    """Overall risk assessment for the PR."""
    risk_level: str = Field(
        "medium",
        description="critical | high | medium | low | safe",
    )
    risk_score: float = Field(
        0.0, description="Normalized 0–100",
    )
    risk_summary: str = ""
    attack_surface_change: str = Field(
        "unchanged",
        description=(
            "expanded | unchanged | reduced"
        ),
    )
    data_exposure_risk: str = "none"
    auth_impact: str = "none"


# ── Intelligence Report ──────────────────────────────


class IntelligenceReport(BaseModel):
    """
    Top-level intelligence output — wraps ReviewResult
    with narrative, insights, priority ranking,
    and explainability.

    This is the final product of the v4 engine.
    """
    # From v3 pipeline (included for completeness)
    score: float = 0.0
    decision: str = ""
    total_findings: int = 0
    new_findings: int = 0
    existing_findings: int = 0
    correlated_groups: int = 0

    # v4: Intelligence additions
    prioritized_findings: list[PrioritizedFinding] = (
        Field(default_factory=list)
    )
    explanation: DecisionExplanation = Field(
        default_factory=DecisionExplanation,
    )
    insights: list[ReviewInsight] = Field(
        default_factory=list,
    )
    risk_assessment: RiskAssessment = Field(
        default_factory=RiskAssessment,
    )
    narrative: str = Field(
        "",
        description=(
            "Human-like narrative summary "
            "of the entire review"
        ),
    )
    executive_summary: str = Field(
        "",
        description=(
            "One-paragraph executive summary"
        ),
    )

    # Metadata
    engine_version: str = "v4"
    repo_context: dict = Field(
        default_factory=dict,
    )
