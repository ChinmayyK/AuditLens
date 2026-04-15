"""
Correlator — Cross-tool finding correlation engine.

Groups findings from multiple tools that point to the
same vulnerability (same file, similar line, same type)
into correlated clusters.

The representative finding gets:
  - tools[] populated with all corroborating tools
  - Highest severity from the group
  - corroboration_score boost from config
  - Combined message

Subordinate findings are marked as correlated and
skipped during scoring.

Runs BEFORE RelevanceFilter in the pipeline.
"""
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from review_engine.schemas.review import (
    FindingInput,
)

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = (
    Path(__file__).parent.parent
    / "config"
    / "scoring_rules.yaml"
)

# Severity ranking for selecting the highest
_SEV_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

# Normalization patterns for vuln_type matching
_NORMALIZE_RE = re.compile(r"[^a-z0-9]")


@dataclass
class CorrelatedGroup:
    """A group of findings from multiple tools."""
    file_path: str
    line_number: int
    normalized_type: str
    findings: list[FindingInput] = field(
        default_factory=list
    )
    tools: list[str] = field(default_factory=list)

    @property
    def is_corroborated(self) -> bool:
        return len(self.tools) > 1

    @property
    def highest_severity(self) -> str:
        if not self.findings:
            return "info"
        return max(
            self.findings,
            key=lambda f: _SEV_RANK.get(
                f.severity, 0
            ),
        ).severity


class Correlator:
    """
    Cross-tool correlation engine.

    Groups findings by (file, line±window, vuln_type)
    across all tools and merges them into representative
    findings with corroboration metadata.
    """

    def __init__(
        self,
        config_path: Optional[Path] = None,
        line_window: int = 3,
    ):
        path = config_path or _DEFAULT_CONFIG_PATH
        with open(path, "r") as f:
            config = yaml.safe_load(f)

        self._corroboration_boost: dict = config.get(
            "corroboration_boost",
            {1: 1.0, 2: 1.4, 3: 1.7, "default": 1.8},
        )
        self._line_window = line_window

        logger.info(
            f"Correlator initialized: "
            f"window=±{line_window}"
        )

    def correlate(
        self, findings: list[FindingInput]
    ) -> tuple[list[FindingInput], int]:
        """
        Correlate findings across tools.

        Args:
            findings: All findings (scanner + synthetic).

        Returns:
            (merged_findings, group_count)
            - merged_findings: Deduplicated list where
              multi-tool groups are merged into a single
              representative finding with tools[] and
              corroboration metadata.
            - group_count: Number of groups with 2+ tools.
        """
        if len(findings) <= 1:
            return findings, 0

        # Step 1: Build groups
        groups = self._build_groups(findings)

        # Step 2: Merge groups into findings
        merged: list[FindingInput] = []
        corroborated_count = 0

        for group in groups:
            if group.is_corroborated:
                corroborated_count += 1
                representative = self._merge_group(
                    group
                )
                merged.append(representative)
            else:
                # Single-tool finding — pass through
                merged.append(group.findings[0])

        logger.info(
            f"Correlator: {len(findings)} findings → "
            f"{len(merged)} merged, "
            f"{corroborated_count} corroborated groups"
        )
        return merged, corroborated_count

    def get_corroboration_boost(
        self, tool_count: int
    ) -> float:
        """
        Get the corroboration boost for a given
        number of corroborating tools.
        """
        boost = self._corroboration_boost.get(
            tool_count
        )
        if boost is not None:
            return float(boost)
        return float(
            self._corroboration_boost.get(
                "default", 1.0
            )
        )

    def _build_groups(
        self, findings: list[FindingInput]
    ) -> list[CorrelatedGroup]:
        """
        Group findings by (file, line±window, vuln_type).
        """
        groups: list[CorrelatedGroup] = []

        for finding in findings:
            fp = finding.file_path or ""
            ln = finding.line_number or 0
            nt = self._normalize_type(
                finding.vuln_type
            )

            # Try to find an existing group
            matched_group = None
            for group in groups:
                if (
                    group.file_path == fp
                    and group.normalized_type == nt
                    and abs(
                        group.line_number - ln
                    ) <= self._line_window
                ):
                    matched_group = group
                    break

            if matched_group:
                matched_group.findings.append(finding)
                tool = finding.tool
                if tool not in matched_group.tools:
                    matched_group.tools.append(tool)
            else:
                groups.append(
                    CorrelatedGroup(
                        file_path=fp,
                        line_number=ln,
                        normalized_type=nt,
                        findings=[finding],
                        tools=[finding.tool],
                    )
                )

        return groups

    def _merge_group(
        self, group: CorrelatedGroup
    ) -> FindingInput:
        """
        Merge a corroborated group into a single
        representative finding.
        """
        # Use the finding with highest severity as base
        primary = max(
            group.findings,
            key=lambda f: _SEV_RANK.get(
                f.severity, 0
            ),
        )

        # Combine messages from all tools
        tool_msgs = []
        for f in group.findings:
            if f.message:
                tool_msgs.append(
                    f"[{f.tool}] {f.message}"
                )

        combined_msg = (
            primary.message
            if len(tool_msgs) <= 1
            else " | ".join(tool_msgs)
        )

        # Boost confidence based on corroboration
        boost = self.get_corroboration_boost(
            len(group.tools)
        )

        # Use the best fix suggestion available
        fix = None
        for f in group.findings:
            if f.fix:
                fix = f.fix
                break

        # Merge into a new finding
        return FindingInput(
            file_path=primary.file_path,
            line_number=primary.line_number,
            vuln_type=primary.vuln_type,
            severity=group.highest_severity,
            tool=primary.tool,  # Primary tool
            message=combined_msg,
            cvss_score=primary.cvss_score,
            cve_id=primary.cve_id,
            cwe_id=primary.cwe_id,
            category=primary.category,
            code_snippet=primary.code_snippet,
            fix=fix or primary.fix,
            confidence=min(
                primary.confidence * boost, 1.0
            ),
            rule_id=primary.rule_id,
            is_synthetic=primary.is_synthetic,
            # v3 fields
            tools=group.tools,
            status=primary.status,
            diff_context=primary.diff_context,
            change_risk=primary.change_risk,
        )

    @staticmethod
    def _normalize_type(vuln_type: str) -> str:
        """
        Normalize vuln_type for cross-tool matching.
        Strips non-alphanumeric chars and lowercases.

        'SQL Injection' and 'sql-injection' → 'sqlinjection'
        """
        return _NORMALIZE_RE.sub(
            "", vuln_type.lower()
        )
