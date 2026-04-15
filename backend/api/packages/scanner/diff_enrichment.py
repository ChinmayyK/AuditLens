"""
Diff Enrichment — Data Intelligence Layer (Dev 1).

Pure functions for enriching raw scanner findings with
PR-aware context BEFORE handing off to Dev 2's engine.

Functions:
    classify_finding_status — new vs existing detection
    extract_diff_context    — ±3 line code context
    compute_change_risk     — keyword-based file risk map
    correlate_scanner_findings — pre-merge multi-tool grouping

Architecture note:
    Dev 2's Correlator performs a second, fuzzier pass
    (±3 line window, normalized vuln_type) on FindingInput
    models. Our correlate_scanner_findings() operates on
    raw scanner dicts and does EXACT (file, line, type)
    matching as a pre-merge step.
"""
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)

# ── Risk keyword patterns ──────────────────────────

_RISK_PATTERNS = {
    "critical": [
        re.compile(
            r"""(?:password|passwd|secret|private[_\-]?key"""
            r"""|api[_\-]?key|access[_\-]?token)""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""['"][A-Za-z0-9+/=]{20,}['"]""",
        ),
    ],
    "high": [
        re.compile(
            r"""(?:auth|login|session|jwt|oauth"""
            r"""|verify|credential|permission)""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:query|execute|cursor|sql|SELECT"""
            r"""|INSERT|UPDATE|DELETE|DROP)""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:\beval\b|\bexec\b|subprocess"""
            r"""|os\.system|shell)""",
            re.IGNORECASE,
        ),
    ],
    "medium": [
        re.compile(
            r"""(?:http://|redirect|cors|header"""
            r"""|cookie|csrf|referrer)""",
            re.IGNORECASE,
        ),
        re.compile(
            r"""(?:open\(|write\(|chmod|chown"""
            r"""|mkdir|unlink|rmdir)""",
            re.IGNORECASE,
        ),
    ],
}


# ── 1. Status classification ──────────────────────


def classify_finding_status(
    finding: dict,
    changed_lines_map: dict[str, list[int]],
) -> str:
    """
    Determine if a finding is new or existing.

    Args:
        finding: Raw scanner dict with file_path
                 and line_number.
        changed_lines_map: Map of file_path to
            changed line numbers.

    Returns:
        "new" if finding is on a changed line,
        "existing" otherwise.
    """
    fp = finding.get("file_path")
    ln = finding.get("line_number")

    if not fp or not ln:
        return "existing"

    changed = changed_lines_map.get(fp, [])
    if not changed:
        return "existing"

    if ln in changed:
        return "new"

    return "existing"


# ── 2. Diff context extraction ────────────────────


def extract_diff_context(
    finding: dict,
    parsed_diffs: dict,
    window: int = 3,
) -> Optional[str]:
    """
    Extract ±window lines of code context from the
    parsed diff for a given finding.

    Args:
        finding: Raw scanner dict with file_path
                 and line_number.
        parsed_diffs: Map of file_path → ParsedDiff
            (from DiffAnalyzer.parse()).
        window: Number of context lines above/below.

    Returns:
        Formatted context string, or None if the
        finding's file/line is not in any diff.
    """
    fp = finding.get("file_path")
    ln = finding.get("line_number")

    if not fp or not ln:
        return None

    parsed = parsed_diffs.get(fp)
    if not parsed:
        return None

    # Use DiffAnalyzer's get_context logic inline
    # to avoid circular imports and keep it self-
    # contained. Same algorithm as DiffAnalyzer.
    start = ln - window
    end = ln + window
    context_lines: list[str] = []

    for hunk in parsed.hunks:
        for dl in hunk.lines:
            if start <= dl.line_number <= end:
                prefix = (
                    "+" if dl.origin == "+"
                    else "-" if dl.origin == "-"
                    else " "
                )
                marker = ""
                if dl.line_number == ln:
                    marker = " ← "
                context_lines.append(
                    f"{dl.line_number:4d} "
                    f"{prefix} {dl.content}{marker}"
                )

    if not context_lines:
        return None

    return "\n".join(context_lines)


# ── 3. Change risk computation ────────────────────


def compute_change_risk(
    changed_lines_map: dict[str, list[int]],
    per_file_diffs: dict[str, str],
) -> dict[str, str]:
    """
    Compute per-file risk level by scanning ONLY
    the added lines for security-relevant keywords.

    Args:
        changed_lines_map: Map of file_path to
            changed line numbers.
        per_file_diffs: Map of file_path to raw
            unified diff string.

    Returns:
        Map of file_path to risk level string:
        "critical", "high", "medium", "low", "none".
    """
    risk_map: dict[str, str] = {}

    for fp in changed_lines_map:
        diff_text = per_file_diffs.get(fp, "")
        if not diff_text:
            risk_map[fp] = "low"
            continue

        # Extract only added lines (start with +,
        # but not the +++ header)
        added_content = "\n".join(
            line[1:]
            for line in diff_text.splitlines()
            if line.startswith("+")
            and not line.startswith("+++")
        )

        if not added_content.strip():
            risk_map[fp] = "none"
            continue

        # Check patterns from highest to lowest risk
        found_risk = "low"
        for level in ("critical", "high", "medium"):
            for pat in _RISK_PATTERNS[level]:
                if pat.search(added_content):
                    found_risk = level
                    break
            if found_risk != "low":
                break

        risk_map[fp] = found_risk

    logger.info(
        f"Change risk computed for "
        f"{len(risk_map)} files: "
        + ", ".join(
            f"{k}={v}" for k, v in risk_map.items()
        )
    )

    return risk_map


# ── 4. Multi-tool pre-correlation ─────────────────


def _normalize_vuln_type(vuln_type: str) -> str:
    """Normalize vuln_type for matching."""
    return re.sub(
        r"[^a-z0-9]", "", vuln_type.lower()
    )


def correlate_scanner_findings(
    findings: list[dict],
) -> list[dict]:
    """
    Pre-merge step: group raw scanner dicts that
    are IDENTICAL (same file, line, vuln_type) but
    from different tools into a single finding with
    a populated tools[] array.

    This runs BEFORE _convert_to_finding_inputs().
    Dev 2's Correlator does a fuzzier pass later.

    Args:
        findings: List of raw scanner output dicts.

    Returns:
        Deduplicated list of dicts. Multi-tool
        matches have tools=["semgrep", "bandit"].
        Single-tool findings have tools=["semgrep"].
    """
    if not findings:
        return []

    # Severity ranking for picking the best
    sev_rank = {
        "critical": 4, "high": 3, "medium": 2,
        "low": 1, "info": 0,
    }

    # Group by (file_path, line_number, normalized_type)
    groups: dict[tuple, list[dict]] = {}
    for f in findings:
        fp = f.get("file_path", "")
        ln = f.get("line_number", 0)
        vt = _normalize_vuln_type(
            f.get("vuln_type", "unknown")
        )
        key = (fp, ln, vt)

        if key not in groups:
            groups[key] = []
        groups[key].append(f)

    # Merge each group
    merged: list[dict] = []
    multi_tool_count = 0

    for key, group in groups.items():
        # Collect unique tools
        tools = list(
            dict.fromkeys(
                g.get("tool_source", "unknown")
                for g in group
            )
        )

        if len(tools) > 1:
            multi_tool_count += 1

        # Pick the primary (highest severity)
        primary = max(
            group,
            key=lambda g: sev_rank.get(
                g.get("severity", "info").lower(), 0
            ),
        )

        # Create the merged dict
        result = dict(primary)
        result["tools"] = tools

        # Take the best code_snippet available
        for g in group:
            if g.get("code_snippet") and not result.get(
                "code_snippet"
            ):
                result["code_snippet"] = g["code_snippet"]
            if g.get("quick_fix") and not result.get(
                "quick_fix"
            ):
                result["quick_fix"] = g["quick_fix"]

        merged.append(result)

    logger.info(
        f"Pre-correlation: {len(findings)} → "
        f"{len(merged)} findings, "
        f"{multi_tool_count} multi-tool groups"
    )

    return merged
