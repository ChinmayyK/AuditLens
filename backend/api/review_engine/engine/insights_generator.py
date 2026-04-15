"""
InsightsGenerator — Pattern analysis and actionable insights.

Analyzes the review to surface high-level observations:
  1. Hotspot detection — files with disproportionate findings
  2. Category clustering — dominant vuln categories
  3. False positive signals — findings likely to be FPs
  4. Fix recommendations — grouped actionable fixes
  5. Trend indicators — improvement/regression (if history)

Operates as a post-processor on ReviewResult + prioritized.
"""
import logging
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Optional

import yaml

from review_engine.schemas.review import (
    ReviewResult,
    ReviewComment,
)
from review_engine.schemas.intelligence import (
    ReviewInsight,
    InsightEvidence,
    PrioritizedFinding,
)

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG = (
    Path(__file__).parent.parent
    / "config"
    / "priority_rules.yaml"
)


class InsightsGenerator:
    """
    Generates actionable insights from review results.
    """

    def __init__(
        self, config_path: Optional[Path] = None
    ):
        path = config_path or _DEFAULT_CONFIG
        with open(path, "r") as f:
            config = yaml.safe_load(f)

        fp_config = config.get(
            "false_positive_indicators", {}
        )
        self._fp_file_patterns = []
        for p in fp_config.get("file_patterns", []):
            try:
                self._fp_file_patterns.append(
                    re.compile(p, re.IGNORECASE)
                )
            except re.error:
                pass

        self._fp_vuln_in_tests = fp_config.get(
            "vuln_type_in_test_files", []
        )

        logger.info("InsightsGenerator initialized")

    def generate(
        self,
        result: ReviewResult,
        prioritized: Optional[
            list[PrioritizedFinding]
        ] = None,
        history: Optional[list[dict]] = None,
    ) -> list[ReviewInsight]:
        """
        Generate all insights from the review.

        Args:
            result: Completed ReviewResult
            prioritized: Priority-ranked findings
            history: Past review snapshots (optional)

        Returns:
            List of ReviewInsight objects.
        """
        insights = []

        comments = result.comments

        if not comments:
            return insights

        # 1. Hotspot detection
        hotspot = self._detect_hotspots(comments)
        if hotspot:
            insights.append(hotspot)

        # 2. Category clustering
        cluster = self._detect_category_clusters(
            comments
        )
        if cluster:
            insights.append(cluster)

        # 3. False positive signals
        fp_insights = self._detect_false_positives(
            comments
        )
        insights.extend(fp_insights)

        # 4. Fix recommendations
        fix_groups = self._group_fix_recommendations(
            comments, prioritized
        )
        insights.extend(fix_groups)

        # 5. Trend indicators (if history provided)
        if history:
            trend = self._analyze_trends(
                result, history
            )
            if trend:
                insights.append(trend)

        logger.info(
            f"Generated {len(insights)} insights"
        )
        return insights

    def _detect_hotspots(
        self, comments: list[ReviewComment]
    ) -> Optional[ReviewInsight]:
        """Detect files with disproportionate findings."""
        file_counts: Counter = Counter()
        file_findings: defaultdict = defaultdict(list)

        for c in comments:
            fp = c.file_path or "unknown"
            file_counts[fp] += 1
            file_findings[fp].append(c)

        if len(file_counts) <= 1:
            return None

        # Find the most concentrated file
        top_file, top_count = (
            file_counts.most_common(1)[0]
        )
        total = sum(file_counts.values())

        if total < 2:
            return None

        concentration = top_count / total

        # Only flag if > 50% of findings in one file
        if concentration < 0.5:
            return None

        # Gather severity info
        severities = [
            c.severity
            for c in file_findings[top_file]
        ]
        high_count = sum(
            1 for s in severities
            if s in ("critical", "high")
        )

        evidence = [
            InsightEvidence(
                file_path=top_file,
                detail=(
                    f"{top_count}/{total} findings "
                    f"({concentration:.0%}), "
                    f"{high_count} critical/high"
                ),
            )
        ]

        return ReviewInsight(
            insight_type="hotspot",
            severity=(
                "high" if high_count > 0 else "medium"
            ),
            title=f"Security Hotspot: {top_file}",
            description=(
                f"`{top_file}` concentrates "
                f"{concentration:.0%} of all findings "
                f"({top_count} of {total}). "
                f"This file may need focused "
                f"security review."
            ),
            evidence=evidence,
            recommendation=(
                f"Consider a dedicated security review "
                f"of {top_file} — it's an outlier in "
                f"finding density."
            ),
            emoji="🔥",
        )

    def _detect_category_clusters(
        self, comments: list[ReviewComment]
    ) -> Optional[ReviewInsight]:
        """Detect dominant vulnerability categories."""
        cat_counts: Counter = Counter()
        for c in comments:
            cat = c.category or "uncategorized"
            cat_counts[cat] += 1

        if len(cat_counts) < 1:
            return None

        total = sum(cat_counts.values())
        top_cat, top_count = (
            cat_counts.most_common(1)[0]
        )
        concentration = top_count / total

        # Only interesting if > 60% of one category
        if concentration < 0.6 or total < 2:
            return None

        _CATEGORY_FIXES = {
            "injection": (
                "adding input validation and "
                "parameterized queries project-wide"
            ),
            "secrets": (
                "implementing a secrets management "
                "solution (e.g. HashiCorp Vault, "
                "AWS Secrets Manager)"
            ),
            "xss": (
                "adding output encoding/escaping "
                "middleware"
            ),
            "crypto": (
                "standardizing on strong crypto "
                "primitives (AES-256, SHA-256+)"
            ),
            "authentication": (
                "reviewing the authentication "
                "architecture"
            ),
            "misconfiguration": (
                "creating a security settings "
                "checklist for deployments"
            ),
        }

        rec = _CATEGORY_FIXES.get(
            top_cat,
            f"addressing the root cause of "
            f"{top_cat} issues systematically",
        )

        return ReviewInsight(
            insight_type="category_cluster",
            severity="medium",
            title=(
                f"{concentration:.0%} of issues are "
                f"{top_cat}-related"
            ),
            description=(
                f"{top_count} of {total} findings "
                f"fall under the '{top_cat}' category. "
                f"This suggests a systemic pattern "
                f"rather than isolated incidents."
            ),
            evidence=[
                InsightEvidence(
                    detail=(
                        f"{top_cat}: {top_count}/"
                        f"{total} findings"
                    ),
                ),
            ],
            recommendation=(
                f"Consider {rec} to address the "
                f"root cause."
            ),
            emoji="📊",
        )

    def _detect_false_positives(
        self, comments: list[ReviewComment]
    ) -> list[ReviewInsight]:
        """Flag findings that are likely false positives."""
        fp_findings = []

        for c in comments:
            fp = c.file_path or ""

            # Check file pattern
            is_test_file = any(
                p.search(fp)
                for p in self._fp_file_patterns
            )

            if is_test_file:
                # Check if vuln type is typically FP
                # in test files
                is_typical_fp = any(
                    vt.lower() in c.vuln_type.lower()
                    for vt in self._fp_vuln_in_tests
                )

                if is_typical_fp:
                    fp_findings.append(c)

        if not fp_findings:
            return []

        evidence = [
            InsightEvidence(
                file_path=c.file_path,
                line_number=c.line_number,
                detail=(
                    f"{c.vuln_type} in test file — "
                    f"likely intentional"
                ),
            )
            for c in fp_findings
        ]

        return [ReviewInsight(
            insight_type="false_positive_signal",
            severity="info",
            title=(
                f"{len(fp_findings)} likely false "
                f"positive(s) in test files"
            ),
            description=(
                f"{len(fp_findings)} finding(s) were "
                f"detected in test/fixture files. "
                f"Security patterns in test code "
                f"are often intentional (testing "
                f"edge cases, fixtures with dummy "
                f"credentials)."
            ),
            evidence=evidence,
            recommendation=(
                "Review these findings manually — "
                "they're likely safe to ignore."
            ),
            emoji="🏷️",
        )]

    def _group_fix_recommendations(
        self,
        comments: list[ReviewComment],
        prioritized: Optional[
            list[PrioritizedFinding]
        ],
    ) -> list[ReviewInsight]:
        """Group findings by fix type."""
        fix_groups: defaultdict = defaultdict(list)

        for c in comments:
            if c.suggestion:
                # Normalize fix text for grouping
                fix_key = c.suggestion.strip()[
                    :50
                ].lower()
                fix_groups[fix_key].append(c)

        insights = []
        for fix_key, findings in fix_groups.items():
            if len(findings) < 2:
                continue

            # Use first finding's suggestion as representative
            fix_text = findings[0].suggestion
            types = list(set(
                f.vuln_type for f in findings
            ))

            insights.append(ReviewInsight(
                insight_type="fix_group",
                severity="medium",
                title=(
                    f"Batch fix: {len(findings)} "
                    f"issues with similar resolution"
                ),
                description=(
                    f"{len(findings)} findings of "
                    f"type(s) {', '.join(types)} can "
                    f"be resolved with a similar fix."
                ),
                evidence=[
                    InsightEvidence(
                        file_path=f.file_path,
                        line_number=f.line_number,
                        detail=f.vuln_type,
                    )
                    for f in findings[:5]
                ],
                recommendation=fix_text,
                emoji="🔧",
            ))

        return insights

    def _analyze_trends(
        self,
        result: ReviewResult,
        history: list[dict],
    ) -> Optional[ReviewInsight]:
        """Analyze trends vs historical reviews."""
        if not history:
            return None

        # Compare current score to average
        past_scores = [
            h.get("score", 0) for h in history
            if "score" in h
        ]
        if not past_scores:
            return None

        avg_past = sum(past_scores) / len(past_scores)
        current = result.score.total_score
        delta = current - avg_past

        if abs(delta) < 5:
            trend = "stable"
            emoji = "➡️"
            desc = (
                f"Risk score ({current:.0f}) is "
                f"consistent with the "
                f"{len(past_scores)}-review average "
                f"({avg_past:.0f})."
            )
        elif delta > 0:
            trend = "regressing"
            emoji = "📈"
            desc = (
                f"Risk score ({current:.0f}) is "
                f"{delta:.0f} points higher than the "
                f"{len(past_scores)}-review average "
                f"({avg_past:.0f}). Security posture "
                f"is worsening."
            )
        else:
            trend = "improving"
            emoji = "📉"
            desc = (
                f"Risk score ({current:.0f}) is "
                f"{abs(delta):.0f} points lower than "
                f"the {len(past_scores)}-review "
                f"average ({avg_past:.0f}). "
                f"Security posture is improving."
            )

        return ReviewInsight(
            insight_type="trend",
            severity=(
                "high" if trend == "regressing"
                else "info"
            ),
            title=f"Trend: {trend}",
            description=desc,
            recommendation=(
                "Investigate the regression — "
                "check for new patterns or "
                "tech debt accumulation."
                if trend == "regressing"
                else "Keep up the good work!"
                if trend == "improving"
                else "Monitor for changes."
            ),
            emoji=emoji,
        )
