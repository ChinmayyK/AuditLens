"""
DiffAnalyzer — Parses unified diff strings into structured
data for pattern detection and context enrichment.

Capabilities:
  - Parse unified diffs into per-file hunks
  - Extract added/removed/context lines with line numbers
  - Auto-derive changed_lines from diffs
  - Provide code context window (±N lines) around a given line
  - Detect file language from extension
"""
import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Map file extensions to language identifiers
_LANG_MAP = {
    ".py": "python", ".js": "javascript",
    ".ts": "typescript", ".jsx": "javascript",
    ".tsx": "typescript", ".java": "java",
    ".rb": "ruby", ".php": "php",
    ".go": "go", ".rs": "rust",
    ".c": "c", ".cpp": "cpp",
    ".cs": "csharp", ".swift": "swift",
    ".kt": "kotlin", ".scala": "scala",
    ".html": "html", ".css": "css",
    ".sql": "sql", ".sh": "shell",
    ".yaml": "yaml", ".yml": "yaml",
    ".json": "json", ".xml": "xml",
    ".env": "env", ".toml": "toml",
    ".jinja": "jinja", ".jinja2": "jinja",
    ".hbs": "handlebars",
}


@dataclass
class DiffLine:
    """A single line from a parsed diff."""
    content: str
    line_number: int  # Line number in the new file
    origin: str       # "+" added, "-" removed, " " context
    raw: str = ""     # Original line with prefix


@dataclass
class DiffHunk:
    """A single hunk from a unified diff."""
    old_start: int
    old_count: int
    new_start: int
    new_count: int
    header: str
    lines: list[DiffLine] = field(default_factory=list)


@dataclass
class ParsedDiff:
    """Complete parsed diff for a single file."""
    file_path: str
    hunks: list[DiffHunk] = field(default_factory=list)
    added_lines: dict[int, str] = field(
        default_factory=dict
    )
    removed_lines: dict[int, str] = field(
        default_factory=dict
    )
    all_new_lines: dict[int, str] = field(
        default_factory=dict
    )
    language: str = "unknown"

    @property
    def changed_line_numbers(self) -> list[int]:
        """Line numbers of added lines."""
        return sorted(self.added_lines.keys())


_HUNK_RE = re.compile(
    r"^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@"
)


class DiffAnalyzer:
    """Parses unified diffs into structured, queryable data."""

    def parse(
        self, diffs: dict[str, str]
    ) -> dict[str, ParsedDiff]:
        """
        Parse all diffs into structured data.

        Args:
            diffs: Map of file_path → unified diff string.

        Returns:
            Map of file_path → ParsedDiff.
        """
        results: dict[str, ParsedDiff] = {}

        for file_path, diff_text in diffs.items():
            parsed = self._parse_single(
                file_path, diff_text
            )
            results[file_path] = parsed

        total_added = sum(
            len(p.added_lines) for p in results.values()
        )
        logger.info(
            f"DiffAnalyzer: parsed {len(results)} files, "
            f"{total_added} added lines"
        )
        return results

    def backfill_changed_lines(
        self,
        parsed_diffs: dict[str, ParsedDiff],
        existing_changed: dict[str, list[int]],
    ) -> dict[str, list[int]]:
        """
        Merge diff-derived changed lines with any
        explicitly provided changed_lines.

        Returns the unified changed_lines map.
        """
        result = dict(existing_changed)

        for fp, parsed in parsed_diffs.items():
            derived = parsed.changed_line_numbers
            if fp in result:
                merged = sorted(
                    set(result[fp]) | set(derived)
                )
                result[fp] = merged
            else:
                result[fp] = derived

        return result

    def get_context(
        self,
        parsed: ParsedDiff,
        line_number: int,
        window: int = 3,
    ) -> Optional[str]:
        """
        Get code context around a line from the diff.

        Args:
            parsed: ParsedDiff for the file.
            line_number: Target line number.
            window: Number of context lines above/below.

        Returns:
            Formatted context string, or None if line
            not found in diff.
        """
        start = line_number - window
        end = line_number + window
        context_lines: list[str] = []

        for hunk in parsed.hunks:
            for dl in hunk.lines:
                if start <= dl.line_number <= end:
                    marker = ""
                    if dl.line_number == line_number:
                        marker = " ← "
                    prefix = (
                        "+" if dl.origin == "+"
                        else "-" if dl.origin == "-"
                        else " "
                    )
                    context_lines.append(
                        f"{dl.line_number:4d} "
                        f"{prefix} {dl.content}{marker}"
                    )

        if not context_lines:
            return None

        return "\n".join(context_lines)

    def get_diff_hunk(
        self,
        parsed: ParsedDiff,
        line_number: int,
    ) -> Optional[str]:
        """
        Get the raw diff hunk containing a given line.
        Used for GitHub PR inline comments.
        """
        for hunk in parsed.hunks:
            line_nums = [
                dl.line_number for dl in hunk.lines
            ]
            if not line_nums:
                continue
            if (
                min(line_nums) <= line_number
                <= max(line_nums)
            ):
                lines = [hunk.header]
                for dl in hunk.lines:
                    prefix = (
                        "+" if dl.origin == "+"
                        else "-" if dl.origin == "-"
                        else " "
                    )
                    lines.append(
                        f"{prefix}{dl.content}"
                    )
                return "\n".join(lines)

        return None

    def _parse_single(
        self, file_path: str, diff_text: str
    ) -> ParsedDiff:
        """Parse a single file's unified diff."""
        ext = Path(file_path).suffix.lower()
        language = _LANG_MAP.get(ext, "unknown")

        parsed = ParsedDiff(
            file_path=file_path,
            language=language,
        )

        lines = diff_text.split("\n")
        current_hunk: Optional[DiffHunk] = None
        new_line_num = 0

        for raw_line in lines:
            # Check for hunk header
            hunk_match = _HUNK_RE.match(raw_line)
            if hunk_match:
                current_hunk = DiffHunk(
                    old_start=int(hunk_match.group(1)),
                    old_count=int(
                        hunk_match.group(2) or 1
                    ),
                    new_start=int(hunk_match.group(3)),
                    new_count=int(
                        hunk_match.group(4) or 1
                    ),
                    header=raw_line,
                )
                parsed.hunks.append(current_hunk)
                new_line_num = current_hunk.new_start
                continue

            if current_hunk is None:
                continue

            if raw_line.startswith("+"):
                content = raw_line[1:]
                dl = DiffLine(
                    content=content,
                    line_number=new_line_num,
                    origin="+",
                    raw=raw_line,
                )
                current_hunk.lines.append(dl)
                parsed.added_lines[new_line_num] = content
                parsed.all_new_lines[
                    new_line_num
                ] = content
                new_line_num += 1

            elif raw_line.startswith("-"):
                content = raw_line[1:]
                dl = DiffLine(
                    content=content,
                    line_number=new_line_num,
                    origin="-",
                    raw=raw_line,
                )
                current_hunk.lines.append(dl)
                parsed.removed_lines[
                    new_line_num
                ] = content
                # Don't increment — removed lines
                # don't exist in new file

            elif raw_line.startswith(" ") or (
                raw_line == "" and current_hunk
            ):
                content = (
                    raw_line[1:]
                    if raw_line.startswith(" ")
                    else ""
                )
                dl = DiffLine(
                    content=content,
                    line_number=new_line_num,
                    origin=" ",
                    raw=raw_line,
                )
                current_hunk.lines.append(dl)
                parsed.all_new_lines[
                    new_line_num
                ] = content
                new_line_num += 1

        return parsed
