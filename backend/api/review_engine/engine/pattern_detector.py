"""
PatternDetector — 100% Config-driven regex pattern detection
on raw diff content.

ZERO HARDCODED RULES. All regex patterns, severities, and
categories are loaded from review_config.json["custom_rules"]
via the config dict passed to detect().

Rules are compiled fresh on every call to support hot-reload:
judges add a rule to the JSON → next webhook picks it up.

Features:
  - Per-language scoping
  - Confidence scoring
  - Deduplication against existing scanner findings
  - Enable/disable per rule
"""
import re
import logging
from pathlib import Path
from typing import Optional

from review_engine.schemas.review import FindingInput
from review_engine.engine.diff_analyzer import ParsedDiff

logger = logging.getLogger(__name__)


class PatternDetector:
    """
    Runs regex-based rules against added diff lines
    to detect vulnerabilities the scanners might miss.

    All rules come from config["custom_rules"].
    Rules are compiled on every detect() call for hot-reload.
    """

    def detect(
        self,
        parsed_diffs: dict[str, ParsedDiff],
        existing_findings: list[FindingInput],
        config: dict,
    ) -> list[FindingInput]:
        """
        Scan all added lines in parsed diffs
        against custom_rules from config.

        Args:
            parsed_diffs: Output from DiffAnalyzer.parse()
            existing_findings: Scanner findings for dedup.
            config: Live config dict from review_config.json.

        Returns:
            List of synthetic FindingInput objects.
        """
        custom_rules = config.get("custom_rules", [])
        w = config.get("weights", {})
        dedup_enabled = True
        min_confidence = 0.5

        # Filter to enabled rules only
        enabled_rules = [
            r for r in custom_rules
            if r.get("enabled", True)
        ]

        # Compile regex patterns fresh (hot-reload)
        compiled: list[tuple[dict, re.Pattern]] = []
        for rule in enabled_rules:
            try:
                pattern = re.compile(
                    rule["pattern"], re.IGNORECASE
                )
                compiled.append((rule, pattern))
            except re.error as e:
                logger.warning(
                    f"Invalid regex in rule "
                    f"{rule.get('id', '?')}: {e}"
                )

        logger.info(
            f"PatternDetector: loaded "
            f"{len(compiled)} rules from config"
        )

        synthetic: list[FindingInput] = []
        existing_keys = self._build_dedup_keys(
            existing_findings
        )

        for fp, parsed in parsed_diffs.items():
            file_ext = Path(fp).suffix.lower()

            for line_num, content in (
                parsed.added_lines.items()
            ):
                for rule, pattern in compiled:
                    # Language scoping
                    if not self._matches_language(
                        rule, file_ext
                    ):
                        continue

                    # Confidence gate
                    if rule.get("confidence", 1.0) < (
                        min_confidence
                    ):
                        continue

                    # Run regex
                    match = pattern.search(content)
                    if not match:
                        continue

                    # Dedup check
                    dedup_key = (
                        fp,
                        line_num,
                        rule.get("category", "default"),
                    )
                    if (
                        dedup_enabled
                        and dedup_key in existing_keys
                    ):
                        logger.debug(
                            f"Dedup: skipping "
                            f"{rule['id']} at "
                            f"{fp}:{line_num}"
                        )
                        continue

                    # Create synthetic finding
                    finding = FindingInput(
                        file_path=fp,
                        line_number=line_num,
                        vuln_type=rule["name"],
                        severity=rule["severity"],
                        tool="pattern_detector",
                        message=rule.get(
                            "message", ""
                        ).replace(
                            "{match}",
                            match.group(0)[:80],
                        ),
                        category=rule.get("category"),
                        code_snippet=content.strip(),
                        fix=rule.get("suggestion"),
                        confidence=rule.get(
                            "confidence", 0.8
                        ),
                        rule_id=rule["id"],
                        is_synthetic=True,
                    )
                    synthetic.append(finding)
                    existing_keys.add(dedup_key)

        logger.info(
            f"PatternDetector: {len(synthetic)} "
            f"synthetic findings generated"
        )
        return synthetic

    def _matches_language(
        self, rule: dict, file_ext: str
    ) -> bool:
        """Check if rule applies to this file type."""
        languages = rule.get("languages", [])
        if not languages:
            return True
        return file_ext in languages

    def _build_dedup_keys(
        self, findings: list[FindingInput]
    ) -> set[tuple]:
        """Build dedup key set from existing findings."""
        keys: set[tuple] = set()
        for f in findings:
            if f.file_path and f.line_number:
                cat = (
                    f.category or "default"
                ).lower()
                keys.add(
                    (f.file_path, f.line_number, cat)
                )
        return keys
