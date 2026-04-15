"""
CommentBuilder — Renders file+line review comments from
Jinja2 templates loaded from comment_templates.yaml.

v2: Injects diff context and generates GitHub suggestion
    blocks for findings with available fixes.
"""
import logging
from pathlib import Path
from typing import Optional

import yaml
from jinja2 import Environment, BaseLoader

from review_engine.schemas.review import (
    ClassifiedFinding,
    FilteredFindings,
    ReviewComment,
)

logger = logging.getLogger(__name__)

_DEFAULT_CONFIG_PATH = (
    Path(__file__).parent.parent
    / "config"
    / "comment_templates.yaml"
)


class CommentBuilder:
    """
    Builds review comments by rendering findings through
    severity-keyed Jinja2 templates.
    """

    def __init__(
        self, config_path: Optional[Path] = None
    ):
        path = config_path or _DEFAULT_CONFIG_PATH
        with open(path, "r") as f:
            self._config = yaml.safe_load(f)

        self._templates: dict[str, str] = self._config.get(
            "templates", {}
        )
        self._jinja_env = Environment(
            loader=BaseLoader(),
            trim_blocks=True,
            lstrip_blocks=True,
        )

    def build(
        self,
        filtered: FilteredFindings,
        diff_contexts: Optional[
            dict[str, object]
        ] = None,
    ) -> list[ReviewComment]:
        """
        Build review comments for all actionable findings
        (relevant + contextual). Sort by severity then file.

        Args:
            filtered: Classified findings from RelevanceFilter.
            diff_contexts: Optional parsed diffs from
                DiffAnalyzer for context enrichment.

        Returns:
            List of ReviewComment objects.
        """
        comments: list[ReviewComment] = []

        for classified in filtered.all_actionable:
            # Skip deduplicated findings
            if getattr(
                classified, "is_duplicate", False
            ):
                continue

            comment = self._render_comment(
                classified, diff_contexts
            )
            if comment:
                comments.append(comment)

        # Sort: critical first, then high, etc.
        # Within same severity, sort by file_path
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4,
        }
        comments.sort(
            key=lambda c: (
                severity_order.get(c.severity, 99),
                c.file_path or "",
                c.line_number or 0,
            )
        )

        logger.info(
            f"Built {len(comments)} review comments"
        )
        return comments

    def _render_comment(
        self,
        classified: ClassifiedFinding,
        diff_contexts: Optional[
            dict[str, object]
        ] = None,
    ) -> Optional[ReviewComment]:
        """Render a single finding into a ReviewComment."""
        finding = classified.finding
        severity = finding.severity.lower()

        # v2: Extract diff context if available
        diff_context_str = None
        diff_hunk_str = None
        if (
            diff_contexts
            and finding.file_path
            and finding.file_path in diff_contexts
        ):
            parsed = diff_contexts[finding.file_path]
            if finding.line_number and hasattr(
                parsed, "added_lines"
            ):
                from review_engine.engine.diff_analyzer \
                    import DiffAnalyzer
                analyzer = DiffAnalyzer()
                diff_context_str = (
                    analyzer.get_context(
                        parsed, finding.line_number
                    )
                )
                diff_hunk_str = (
                    analyzer.get_diff_hunk(
                        parsed, finding.line_number
                    )
                )

        # Get template for this severity level
        template_str = self._templates.get(severity)
        if not template_str:
            # Fallback to info template
            template_str = self._templates.get(
                "info",
                "{{ vuln_type }}: {{ message }}",
            )

        try:
            template = self._jinja_env.from_string(
                template_str
            )
            body = template.render(
                vuln_type=finding.vuln_type,
                tool=finding.tool,
                message=finding.message,
                severity=severity,
                cvss=finding.cvss_score,
                fix=finding.fix,
                file_path=finding.file_path,
                line_number=finding.line_number,
                category=classified.resolved_category,
                cwe_id=finding.cwe_id,
                cve_id=finding.cve_id,
                code_snippet=finding.code_snippet,
                diff_context=diff_context_str,
                confidence=finding.confidence,
                rule_id=finding.rule_id,
                # v3 context
                status=finding.status,
                corroborated_by=(
                    classified.corroborated_by
                ),
                change_risk=finding.change_risk,
            ).strip()
        except Exception as e:
            logger.warning(
                f"Template render failed for "
                f"{finding.vuln_type}: {e}"
            )
            body = (
                f"**{severity.upper()}: "
                f"{finding.vuln_type}** — "
                f"{finding.message}"
            )

        # v2: Append diff context block
        if diff_context_str:
            body += (
                f"\n\n<details>\n"
                f"<summary>📝 Code context</summary>\n\n"
                f"```\n{diff_context_str}\n```\n"
                f"</details>"
            )

        # v2: Build suggestion block
        suggestion = None
        if finding.fix and finding.code_snippet:
            suggestion = finding.fix

        return ReviewComment(
            file_path=finding.file_path,
            line_number=finding.line_number,
            severity=severity,
            vuln_type=finding.vuln_type,
            tool=finding.tool,
            category=classified.resolved_category,
            body=body,
            impact=classified.impact,
            suggestion=suggestion,
            diff_hunk=diff_hunk_str,
            confidence=finding.confidence,
            rule_id=finding.rule_id,
            # v3 fields
            status=finding.status,
            corroborated_by=(
                classified.corroborated_by
            ),
            change_risk=finding.change_risk,
        )
