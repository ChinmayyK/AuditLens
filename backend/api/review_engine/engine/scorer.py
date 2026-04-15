"""
Scorer — 100% Config-driven weighted scoring engine.

ZERO HARDCODED VALUES. Every weight, multiplier, and threshold
is loaded from review_config.json via the config dict passed
to compute().

For each finding:
  impact = severity_weight × tool_trust × category_multiplier
           × relevance_boost × confidence × diminishing_factor
           × status_weight × change_risk_weight
           × corroboration_boost

Total score = min(sum(impacts), max_score)
"""
import logging
from typing import Optional

from review_engine.schemas.review import (
    ClassifiedFinding,
    FilteredFindings,
    RelevanceBucket,
    ScoreResult,
    SeverityBreakdown,
    ToolBreakdown,
)

logger = logging.getLogger(__name__)

_SEVERITY_EMOJIS = {
    "critical": "🚨",
    "high": "🔴",
    "medium": "🟡",
    "low": "🔵",
    "info": "ℹ️",
}


class Scorer:
    """
    Computes a composite weighted score from classified
    findings using config-driven weights and multipliers.

    All config is received per-call via compute(config=...).
    No __init__-time loading. No caching.
    """

    def compute(
        self,
        filtered: FilteredFindings,
        config: dict,
    ) -> ScoreResult:
        """
        Score all actionable findings.

        Args:
            filtered: Classified findings from RelevanceFilter.
            config: Live config dict from review_config.json.

        Returns:
            ScoreResult with total, severity, and tool breakdown.
        """
        w = config.get("weights", {})

        severity_weights = w.get("severity_weights", {})
        tool_trust = w.get("tool_trust", {})
        category_multipliers = w.get("category_multipliers", {})
        category_keywords = w.get("category_keywords", {})
        relevance_boost = w.get("relevance_boost", 1.5)
        max_score = w.get("max_score", 100)
        dedup_line_window = w.get("dedup_line_window", 2)
        diminishing_start = w.get("diminishing_start", 3)
        diminishing_decay = w.get("diminishing_decay", 0.6)
        status_weights = w.get(
            "status_weights",
            {"new": 1.0, "existing": 0.3, "fixed": 0.0},
        )
        change_risk_weights = w.get(
            "change_risk_weights",
            {
                "critical": 1.5,
                "high": 1.2,
                "medium": 1.0,
                "low": 0.7,
                "none": 0.5,
            },
        )
        corroboration_boost_map = w.get(
            "corroboration_boost",
            {"1": 1.0, "2": 1.4, "3": 1.7, "default": 1.8},
        )
        new_finding_boost = w.get("new_finding_boost", 1.3)

        # Mark adjacent-line duplicates
        self._mark_duplicates(filtered, dedup_line_window)

        severity_agg: dict[str, SeverityBreakdown] = {}
        tool_agg: dict[str, ToolBreakdown] = {}
        category_counts: dict[str, int] = {}
        new_count = 0
        existing_count = 0
        fixed_count = 0

        for classified in filtered.all_actionable:
            if classified.is_duplicate:
                continue

            status = classified.finding.status
            if status == "new":
                new_count += 1
            elif status == "existing":
                existing_count += 1
            elif status == "fixed":
                fixed_count += 1

            # Resolve category
            category = self._resolve_category(
                classified.finding.vuln_type,
                classified.finding.category,
                category_multipliers,
                category_keywords,
            )
            classified.resolved_category = category

            category_counts[category] = (
                category_counts.get(category, 0) + 1
            )
            cat_count = category_counts[category]

            # Status/risk/corroboration weights
            classified.status_weight = (
                status_weights.get(status, 1.0)
            )
            classified.change_risk_weight = (
                change_risk_weights.get(
                    classified.finding.change_risk, 1.0
                )
            )
            tool_count = len(
                classified.finding.tools
            ) if classified.finding.tools else 1
            classified.corroboration_score = (
                self._get_corroboration_boost(
                    tool_count, corroboration_boost_map
                )
            )
            classified.corroborated_by = (
                classified.finding.tools
            )

            # Compute impact
            impact = self._compute_impact(
                classified,
                category,
                cat_count,
                severity_weights,
                tool_trust,
                category_multipliers,
                relevance_boost,
                diminishing_start,
                diminishing_decay,
                new_finding_boost,
            )
            classified.impact = impact
            classified.confidence = (
                classified.finding.confidence
            )

            # Aggregate by severity
            sev = classified.finding.severity
            if sev not in severity_agg:
                severity_agg[sev] = SeverityBreakdown(
                    severity=sev,
                    emoji=_SEVERITY_EMOJIS.get(sev, ""),
                )
            severity_agg[sev].count += 1
            severity_agg[sev].impact += impact

            # Aggregate by tool
            tool = classified.finding.tool
            if tool not in tool_agg:
                trust = tool_trust.get(
                    tool,
                    tool_trust.get("default", 0.8),
                )
                tool_agg[tool] = ToolBreakdown(
                    tool=tool, trust=trust
                )
            tool_agg[tool].count += 1
            tool_agg[tool].contribution += impact

        total = sum(
            s.impact for s in severity_agg.values()
        )
        total = min(total, max_score)

        sev_order = [
            "critical", "high", "medium", "low", "info",
        ]
        severity_list = sorted(
            severity_agg.values(),
            key=lambda s: sev_order.index(s.severity)
            if s.severity in sev_order
            else 99,
        )

        tool_list = sorted(
            tool_agg.values(),
            key=lambda t: t.contribution,
            reverse=True,
        )

        result = ScoreResult(
            total_score=round(total, 2),
            max_score=max_score,
            severity_breakdown=severity_list,
            tool_breakdown=tool_list,
            new_findings_count=new_count,
            existing_findings_count=existing_count,
            fixed_findings_count=fixed_count,
        )

        logger.info(
            f"Score computed: {result.total_score}"
            f"/{result.max_score} "
            f"(new={new_count}, existing={existing_count})"
        )
        return result

    def _compute_impact(
        self,
        classified: ClassifiedFinding,
        category: str,
        category_count: int,
        severity_weights: dict,
        tool_trust: dict,
        category_multipliers: dict,
        relevance_boost: float,
        diminishing_start: int,
        diminishing_decay: float,
        new_finding_boost: float,
    ) -> float:
        """
        Compute weighted impact for a single finding.
        ALL values come from config — zero hardcoding.
        """
        finding = classified.finding

        base = severity_weights.get(
            finding.severity, 0
        )
        trust = tool_trust.get(
            finding.tool,
            tool_trust.get("default", 0.8),
        )
        cat_mult = category_multipliers.get(
            category,
            category_multipliers.get("default", 1.0),
        )
        relevance = (
            relevance_boost
            if classified.bucket == RelevanceBucket.RELEVANT
            else 1.0
        )

        confidence = finding.confidence

        # Diminishing returns
        diminishing = 1.0
        if category_count > diminishing_start:
            excess = (
                category_count - diminishing_start
            )
            diminishing = diminishing_decay ** excess

        # Status weight
        status_w = classified.status_weight

        # Change risk weight
        risk_w = classified.change_risk_weight

        # Corroboration boost
        corr_boost = classified.corroboration_score

        # New finding on changed lines bonus
        new_boost = 1.0
        if (
            finding.status == "new"
            and classified.bucket == RelevanceBucket.RELEVANT
        ):
            new_boost = new_finding_boost

        return (
            base * trust * cat_mult
            * relevance * confidence * diminishing
            * status_w * risk_w * corr_boost * new_boost
        )

    def _resolve_category(
        self,
        vuln_type: str,
        explicit_category: Optional[str],
        category_multipliers: dict,
        category_keywords: dict,
    ) -> str:
        """Resolve category from config-driven keywords."""
        if explicit_category:
            normalized = explicit_category.lower().strip()
            if normalized in category_multipliers:
                return normalized

        vt_lower = vuln_type.lower()
        for category, keywords in (
            category_keywords.items()
        ):
            for kw in keywords:
                if kw.lower() in vt_lower:
                    return category

        return "default"

    def _mark_duplicates(
        self,
        filtered: FilteredFindings,
        dedup_line_window: int,
    ) -> None:
        """Mark adjacent-line duplicates."""
        seen: dict[
            tuple[str, str], list[ClassifiedFinding]
        ] = {}

        for cf in filtered.all_actionable:
            fp = cf.finding.file_path or ""
            vt = cf.finding.vuln_type
            key = (fp, vt)

            if key not in seen:
                seen[key] = [cf]
                continue

            is_adjacent = False
            for existing in seen[key]:
                if (
                    existing.finding.line_number
                    and cf.finding.line_number
                ):
                    delta = abs(
                        existing.finding.line_number
                        - cf.finding.line_number
                    )
                    if delta <= dedup_line_window:
                        is_adjacent = True
                        break

            if is_adjacent:
                cf.is_duplicate = True
                logger.debug(
                    f"Dedup: {vt} at {fp}:"
                    f"{cf.finding.line_number}"
                )
            else:
                seen[key].append(cf)

    def _get_corroboration_boost(
        self,
        tool_count: int,
        corroboration_boost_map: dict,
    ) -> float:
        """Get corroboration boost for N tools from config."""
        boost = corroboration_boost_map.get(
            str(tool_count)
        )
        if boost is not None:
            return float(boost)
        # Try int key fallback
        boost = corroboration_boost_map.get(tool_count)
        if boost is not None:
            return float(boost)
        return float(
            corroboration_boost_map.get(
                "default", 1.0
            )
        )
