"""
RelevanceFilter — Partitions findings by their relationship
to changed lines in the diff.

Buckets:
  - relevant:   file_path in changed_lines AND line_number in the set
  - contextual: file_path in changed_lines but line_number NOT in the set
  - unrelated:  file_path not in changed_lines at all
"""
import logging
from review_engine.schemas.review import (
    FindingInput,
    ReviewRequest,
    ClassifiedFinding,
    FilteredFindings,
    RelevanceBucket,
)

logger = logging.getLogger(__name__)


class RelevanceFilter:
    """Stateless filter that classifies findings by diff relevance."""

    def filter(
        self, request: ReviewRequest
    ) -> FilteredFindings:
        """
        Partition all findings into relevance buckets.

        Args:
            request: The full review request containing
                     findings and changed_lines.

        Returns:
            FilteredFindings with populated buckets.
        """
        result = FilteredFindings()

        # Pre-build sets for O(1) lookup
        changed_sets: dict[str, set[int]] = {
            fp: set(lines)
            for fp, lines in request.changed_lines.items()
        }

        for finding in request.findings:
            bucket = self._classify(finding, changed_sets)
            classified = ClassifiedFinding(
                finding=finding,
                bucket=bucket,
            )

            if bucket == RelevanceBucket.RELEVANT:
                result.relevant.append(classified)
            elif bucket == RelevanceBucket.CONTEXTUAL:
                result.contextual.append(classified)
            else:
                result.unrelated.append(classified)

        logger.info(
            f"Relevance filter: "
            f"{len(result.relevant)} relevant, "
            f"{len(result.contextual)} contextual, "
            f"{len(result.unrelated)} unrelated"
        )
        return result

    def _classify(
        self,
        finding: FindingInput,
        changed_sets: dict[str, set[int]],
    ) -> RelevanceBucket:
        """Classify a single finding into a relevance bucket."""
        fp = finding.file_path
        ln = finding.line_number

        # No file_path → unrelated
        if not fp:
            return RelevanceBucket.UNRELATED

        # Check exact match first
        if fp in changed_sets:
            if ln is not None and ln in changed_sets[fp]:
                return RelevanceBucket.RELEVANT
            return RelevanceBucket.CONTEXTUAL

        # Fuzzy match: finding path might be a suffix
        # e.g. finding has "app.py", changed_lines has "src/app.py"
        for changed_fp, line_set in changed_sets.items():
            if changed_fp.endswith(fp) or fp.endswith(changed_fp):
                if ln is not None and ln in line_set:
                    return RelevanceBucket.RELEVANT
                return RelevanceBucket.CONTEXTUAL

        return RelevanceBucket.UNRELATED
