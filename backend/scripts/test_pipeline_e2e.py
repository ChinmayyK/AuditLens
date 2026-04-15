#!/usr/bin/env python3
"""
End-to-End Pipeline Test — Validates Dev 1's pipeline
independently from the server and Celery.

Tests the FULL data flow offline:
  1. Simulated PR diff → split_diff_by_file()
  2. DiffAnalyzer → changed_lines_map
  3. Fake scanner findings → _convert_to_finding_inputs()
  4. ReviewEngine.execute_pr() → ReviewResult
  5. Validates GitHubPRReview output is POST-ready

Runs without: FastAPI server, Celery, Redis, GitHub API.

Usage:
    cd api && python -m scripts.test_pipeline_e2e
    # or
    cd api && python ../scripts/test_pipeline_e2e.py
"""
import sys
import json
from pathlib import Path

# Ensure api/ is importable
api_dir = Path(__file__).resolve().parent.parent / "api"
sys.path.insert(0, str(api_dir))


def separator(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


# ── Test 1: split_diff_by_file ─────────────────────

def test_split_diff():
    separator("TEST 1: split_diff_by_file()")

    from packages.scanner.github_service import (
        GitHubService,
    )

    # Simulate a full PR diff (as GitHub API would return)
    full_diff = """diff --git a/src/db.py b/src/db.py
index abc1234..def5678 100644
--- a/src/db.py
+++ b/src/db.py
@@ -10,4 +10,8 @@ class Database:
     def __init__(self):
         self.conn = None

+    def get_user(self, user_id):
+        query = "SELECT * FROM users WHERE id = " + user_id
+        return self.conn.execute(query)
+
diff --git a/src/auth.py b/src/auth.py
index 111aaaa..222bbbb 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -5,3 +5,5 @@ import os
 SECRET_KEY = os.getenv("SECRET_KEY")

+API_TOKEN = "ghp_fake1234567890abcdefghijklmnop"
+PASSWORD = "admin123"
"""

    gh = GitHubService()
    per_file = gh.split_diff_by_file(full_diff)

    assert "src/db.py" in per_file, (
        f"Missing src/db.py, got: {list(per_file.keys())}"
    )
    assert "src/auth.py" in per_file, (
        f"Missing src/auth.py, got: {list(per_file.keys())}"
    )
    assert "@@" in per_file["src/db.py"], (
        "db.py diff missing hunk headers"
    )

    print(f"  ✅ Split into {len(per_file)} files:")
    for fp, diff in per_file.items():
        lines = diff.count("\n") + 1
        print(f"     📄 {fp} ({lines} lines)")

    return per_file


# ── Test 2: DiffAnalyzer → changed_lines ───────────

def test_diff_analyzer(per_file_diffs: dict):
    separator("TEST 2: DiffAnalyzer + changed_lines_map")

    from review_engine.engine.diff_analyzer import (
        DiffAnalyzer,
    )

    analyzer = DiffAnalyzer()
    parsed = analyzer.parse(per_file_diffs)
    changed_lines = analyzer.backfill_changed_lines(
        parsed, {}
    )

    assert len(changed_lines) > 0, "No changed lines!"

    print(f"  ✅ Parsed {len(parsed)} files")
    for fp, cl in changed_lines.items():
        print(f"     📍 {fp}: lines {cl}")

    return changed_lines, per_file_diffs


# ── Test 3: Finding adapter ───────────────────────

def test_finding_adapter():
    separator("TEST 3: _convert_to_finding_inputs()")

    # Inline adapter (same logic as sast.py) to avoid
    # importing Celery which isn't needed locally
    from review_engine.schemas.review import (
        FindingInput,
    )

    def _convert_to_finding_inputs(findings):
        inputs = []
        for f in findings:
            severity = f.get("severity", "info").lower()
            if severity not in {
                "critical", "high", "medium",
                "low", "info",
            }:
                severity = "info"
            try:
                inp = FindingInput(
                    file_path=f.get("file_path"),
                    line_number=f.get("line_number"),
                    vuln_type=f.get("vuln_type", "Unknown"),
                    severity=severity,
                    tool=f.get("tool_source", "unknown"),
                    message=f.get("description", ""),
                    cvss_score=f.get("cvss_score"),
                    cve_id=f.get("cve_id"),
                    cwe_id=f.get("cwe_id"),
                    category=f.get("category"),
                    code_snippet=f.get("code_snippet"),
                    fix=f.get("quick_fix"),
                )
                inputs.append(inp)
            except Exception as e:
                print(f"     ⚠️ Skipping: {e}")
                continue
        return inputs

    # Simulate scanner output (raw dicts)
    raw_findings = [
        {
            "file_path": "src/db.py",
            "line_number": 13,
            "vuln_type": "SQL Injection",
            "severity": "high",
            "tool_source": "semgrep",
            "description": "String concatenation in SQL query",
            "cwe_id": "CWE-89",
            "code_snippet": 'query = "SELECT * FROM users WHERE id = " + user_id',
            "quick_fix": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "category": "injection",
        },
        {
            "file_path": "src/auth.py",
            "line_number": 7,
            "vuln_type": "Hardcoded API Key",
            "severity": "critical",
            "tool_source": "gitleaks",
            "description": "GitHub Personal Access Token found",
            "category": "secrets",
        },
        {
            "file_path": "src/auth.py",
            "line_number": 8,
            "vuln_type": "Hardcoded Password",
            "severity": "high",
            "tool_source": "gitleaks",
            "description": "Hardcoded password in source",
            "category": "secrets",
        },
        {
            # Edge case: missing fields
            "vuln_type": "Outdated Dependency",
            "severity": "medium",
            "tool_source": "trivy",
            "description": "lodash@4.17.19 has CVE-2021-23337",
            "cve_id": "CVE-2021-23337",
        },
        {
            # Edge case: invalid severity
            "file_path": "test.py",
            "vuln_type": "Test Finding",
            "severity": "INVALID_LEVEL",
            "tool_source": "unknown_tool",
            "description": "Should be mapped to 'info'",
        },
    ]

    inputs = _convert_to_finding_inputs(raw_findings)

    assert len(inputs) >= 4, (
        f"Expected ≥4 inputs, got {len(inputs)}"
    )

    # Verify the invalid severity got mapped to info
    test_finding = [
        i for i in inputs if i.vuln_type == "Test Finding"
    ]
    if test_finding:
        assert test_finding[0].severity == "info", (
            f"Invalid severity not mapped to 'info': "
            f"{test_finding[0].severity}"
        )

    print(f"  ✅ Converted {len(inputs)} / "
          f"{len(raw_findings)} findings")
    for inp in inputs:
        print(
            f"     [{inp.severity}] {inp.vuln_type} "
            f"({inp.tool}) @ {inp.file_path}:{inp.line_number}"
        )

    return inputs


# ── Test 4: ReviewEngine.execute_pr() ──────────────

def test_review_engine(
    finding_inputs,
    changed_lines: dict,
    per_file_diffs: dict,
):
    separator("TEST 4: ReviewEngine.execute_pr()")

    from review_engine.schemas.review import (
        ReviewRequest,
    )
    from review_engine.service import ReviewEngine

    request = ReviewRequest(
        findings=finding_inputs,
        changed_lines=changed_lines,
        diffs=per_file_diffs,
    )

    engine = ReviewEngine()
    result = engine.execute_pr(request)

    # Assertions
    assert result.score is not None
    assert result.decision is not None
    assert result.pr_review is not None
    assert result.score.total_score >= 0
    assert result.decision.decision.value in {
        "approve", "request_changes", "block"
    }
    assert result.pr_review.event in {
        "APPROVE", "REQUEST_CHANGES", "COMMENT"
    }
    assert len(result.pr_review.body) > 0

    print(f"  📊 Score:     {result.score.total_score}"
          f"/{result.score.max_score}")
    print(f"  🔍 Decision:  {result.decision.decision.value}")
    print(f"  📝 Comments:  {len(result.comments)}")
    print(f"  📂 Relevant:  {result.relevant_count}")
    print(f"  📂 Context:   {result.contextual_count}")
    print(f"  📂 Filtered:  {result.unrelated_count}")
    print(f"  🔎 Patterns:  {result.pattern_findings_count}")

    # PR review output
    print(f"\n  🐙 GitHub PR Review:")
    print(f"     Event: {result.pr_review.event}")
    print(f"     Inline comments: "
          f"{len(result.pr_review.comments)}")
    for c in result.pr_review.comments[:5]:
        body_preview = c.body[:60].replace("\n", " ")
        print(f"     📍 {c.path}:{c.line} → {body_preview}...")

    # Severity breakdown
    if result.score.severity_breakdown:
        print(f"\n  📉 Severity Breakdown:")
        for sb in result.score.severity_breakdown:
            print(
                f"     {sb.emoji} {sb.severity}: "
                f"{sb.count} findings, "
                f"impact={sb.impact:.2f}"
            )

    # Decision reasons
    if result.decision.reasons:
        print(f"\n  📋 Decision Reasons:")
        for r in result.decision.reasons:
            print(f"     • {r}")
    if result.decision.hard_blockers:
        print(f"\n  ⛔ Hard Blockers:")
        for b in result.decision.hard_blockers:
            print(f"     • {b}")

    print(f"\n  ✅ ReviewEngine pipeline complete!")

    return result


# ── Test 5: GitHubPRReview payload validation ──────

def test_github_payload(result):
    separator("TEST 5: GitHubPRReview Payload Validation")

    pr_review = result.pr_review
    assert pr_review is not None

    # Build the exact payload we'd POST to GitHub
    payload = {
        "commit_id": "abc123fake",
        "event": pr_review.event,
        "body": pr_review.body,
        "comments": [
            {
                "path": c.path,
                "line": c.line,
                "side": c.side,
                "body": c.body,
            }
            for c in pr_review.comments
        ],
    }

    # Validate structure
    assert isinstance(payload["event"], str)
    assert isinstance(payload["body"], str)
    assert isinstance(payload["comments"], list)

    for c in payload["comments"]:
        assert "path" in c, f"Missing 'path' in comment"
        assert "line" in c, f"Missing 'line' in comment"
        assert "body" in c, f"Missing 'body' in comment"
        assert isinstance(c["line"], int), (
            f"'line' must be int, got {type(c['line'])}"
        )

    payload_json = json.dumps(payload, indent=2)
    print(f"  📦 Payload size: {len(payload_json)} bytes")
    print(f"  📦 Comments: {len(payload['comments'])}")
    print(f"\n  📝 Payload preview (first 500 chars):")
    print(f"  {payload_json[:500]}")

    print(f"\n  ✅ Payload is valid for GitHub API!")
    print(f"     POST /repos/:owner/:repo/pulls/:pr/reviews")


# ── Run all tests ──────────────────────────────────

def main():
    print()
    print("🧪 AuditLens E2E Pipeline Test")
    print("   Testing Dev 1's pipeline independently")
    print("   No server, no Celery, no GitHub API needed")

    passed = 0
    failed = 0

    try:
        per_file_diffs = test_split_diff()
        passed += 1
    except Exception as e:
        print(f"\n  ❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
        return

    try:
        changed_lines, diffs = test_diff_analyzer(
            per_file_diffs
        )
        passed += 1
    except Exception as e:
        print(f"\n  ❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
        return

    try:
        finding_inputs = test_finding_adapter()
        passed += 1
    except Exception as e:
        print(f"\n  ❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
        return

    try:
        result = test_review_engine(
            finding_inputs, changed_lines, diffs
        )
        passed += 1
    except Exception as e:
        print(f"\n  ❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        failed += 1
        return

    try:
        test_github_payload(result)
        passed += 1
    except Exception as e:
        print(f"\n  ❌ FAILED: {e}")
        import traceback
        traceback.print_exc()
        failed += 1

    separator("RESULTS")
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print(f"  Total: {passed + failed}")
    print()

    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
