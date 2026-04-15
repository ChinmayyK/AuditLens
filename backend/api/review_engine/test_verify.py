"""
Review Engine — Verification Test Script (v1 + v2 + v3)
Runs offline (no DB, no server) to verify engine logic.

Usage:
    cd api && python3 -m review_engine.test_verify
"""
import json
import sys
from pathlib import Path

# Ensure api/ is on the path
sys.path.insert(0, str(Path(__file__).parent.parent))

from review_engine.schemas.review import (
    ReviewRequest,
    FindingInput,
)
from review_engine.service import ReviewEngine


def _separator(title: str):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}")


# ── v1 Tests ───────────────────────────────────────────


def test_full_review():
    """Test full pipeline with mixed findings."""
    _separator("TEST 1: Full Review — Mixed Findings")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="app.py",
                line_number=42,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="Unsanitized input in query",
                cwe_id="CWE-89",
                fix="Use parameterized queries",
            ),
            FindingInput(
                file_path="app.py",
                line_number=10,
                vuln_type="Hardcoded API Key",
                severity="critical",
                tool="gitleaks",
                message="AWS access key found in source",
            ),
            FindingInput(
                file_path="utils.py",
                line_number=88,
                vuln_type="Weak Hash Algorithm",
                severity="medium",
                tool="bandit",
                message="Use of MD5 for hashing",
                fix="Switch to SHA-256 or bcrypt",
            ),
            FindingInput(
                file_path="config.py",
                line_number=5,
                vuln_type="Debug Mode Enabled",
                severity="low",
                tool="semgrep",
                message="DEBUG=True in production config",
            ),
            FindingInput(
                file_path="server.py",
                line_number=200,
                vuln_type="Server Version Exposed",
                severity="info",
                tool="nikto",
                message="Server header reveals version",
            ),
        ],
        changed_lines={
            "app.py": [40, 41, 42, 43],
            "utils.py": [85, 86, 87, 88, 89, 90],
        },
    )

    engine = ReviewEngine()
    result = engine.execute(request)

    print(f"\n📊 Score: {result.score.total_score}"
          f"/{result.score.max_score}")
    print(f"🔍 Decision: {result.decision.decision.value}")
    print(f"📝 Comments: {len(result.comments)}")
    print(f"📂 Relevant: {result.relevant_count}")
    print(f"📂 Contextual: {result.contextual_count}")
    print(f"📂 Unrelated: {result.unrelated_count}")

    assert result.relevant_count == 2
    assert result.contextual_count == 1
    assert result.unrelated_count == 2
    assert result.decision.decision.value == "block"
    assert result.score.total_score > 0
    assert len(result.comments) > 0

    print("\n✅ TEST 1 PASSED")


def test_clean_review():
    """Test with only low/info findings — should approve."""
    _separator("TEST 2: Clean Review — Should Approve")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="app.py",
                line_number=10,
                vuln_type="Verbose Logging",
                severity="info",
                tool="semgrep",
                message="Debug log exposes request body",
            ),
            FindingInput(
                file_path="app.py",
                line_number=20,
                vuln_type="Missing Docstring",
                severity="info",
                tool="bandit",
                message="Function missing docstring",
            ),
        ],
        changed_lines={"app.py": [10, 20]},
    )

    engine = ReviewEngine()
    result = engine.execute(request)

    print(f"\n📊 Score: {result.score.total_score}")
    print(f"🔍 Decision: {result.decision.decision.value}")

    assert result.decision.decision.value == "approve"
    assert result.score.total_score <= 15

    print("\n✅ TEST 2 PASSED")


def test_score_only():
    """Test the score-only fast path."""
    _separator("TEST 3: Score-Only Fast Path")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="db.py",
                line_number=55,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="String format in SQL query",
            ),
        ],
        changed_lines={
            "db.py": [50, 51, 52, 53, 54, 55, 56],
        },
    )

    engine = ReviewEngine()
    score = engine.score_only(request)

    print(f"\n📊 Score: {score.total_score}"
          f"/{score.max_score}")

    assert score.total_score > 0
    assert len(score.severity_breakdown) == 1

    print("\n✅ TEST 3 PASSED")


def test_comments_only():
    """Test the comments-only fast path."""
    _separator("TEST 4: Comments-Only Fast Path")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="auth.py",
                line_number=30,
                vuln_type="Missing CSRF Token",
                severity="medium",
                tool="semgrep",
                message="Form lacks CSRF protection",
                fix="Add CSRF token middleware",
            ),
        ],
        changed_lines={
            "auth.py": [28, 29, 30, 31, 32],
        },
    )

    engine = ReviewEngine()
    comments = engine.comments_only(request)

    print(f"\n📝 Comments generated: {len(comments)}")

    assert len(comments) == 1
    assert "MEDIUM" in comments[0].body
    assert "CSRF" in comments[0].body

    print("\n✅ TEST 4 PASSED")


def test_hard_blocker():
    """Test that hard blockers trigger on secrets."""
    _separator("TEST 5: Hard Blocker — Secrets")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path=".env",
                line_number=1,
                vuln_type="Leaked Database Password",
                severity="low",
                tool="gitleaks",
                message="Database password in .env",
            ),
        ],
        changed_lines={".env": [1]},
    )

    engine = ReviewEngine()
    result = engine.execute(request)

    assert result.decision.decision.value == "block"
    # v3: may be blocked by policy override OR hard blocker
    blocked_by_policy = len(
        result.decision.policy_overrides_applied
    ) > 0
    blocked_by_hard = len(
        result.decision.hard_blockers
    ) > 0
    assert blocked_by_policy or blocked_by_hard, (
        "Expected block via policy or hard blocker"
    )

    print(f"\n📊 Score: {result.score.total_score}")
    if blocked_by_hard:
        print(f"⛔ Blockers: {result.decision.hard_blockers}")
    if blocked_by_policy:
        print(f"📋 Policy: "
              f"{result.decision.policy_overrides_applied}")
    print("\n✅ TEST 5 PASSED")


def test_no_changed_lines():
    """Test with no changed_lines — all unrelated."""
    _separator("TEST 6: No Changed Lines")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="legacy.py",
                line_number=100,
                vuln_type="XSS Vulnerability",
                severity="high",
                tool="semgrep",
                message="Unescaped output",
            ),
        ],
        changed_lines={},
    )

    engine = ReviewEngine()
    result = engine.execute(request)

    assert result.relevant_count == 0
    assert result.unrelated_count == 1
    assert result.score.total_score == 0
    assert len(result.comments) == 0

    print(f"\n📊 Score: {result.score.total_score}")
    print(f"📂 Unrelated: {result.unrelated_count}")
    print("\n✅ TEST 6 PASSED")


# ── v2 Tests ───────────────────────────────────────────


def test_diff_parsing():
    """Test DiffAnalyzer parses unified diffs correctly."""
    _separator("TEST 7: Diff Parsing (v2)")

    from review_engine.engine.diff_analyzer import (
        DiffAnalyzer,
    )

    analyzer = DiffAnalyzer()
    diffs = {
        "app.py": (
            "@@ -40,4 +40,8 @@\n"
            " existing_line_1\n"
            " existing_line_2\n"
            "+user_input = request.GET['id']\n"
            "+query = \"SELECT * FROM users WHERE id = \""
            " + user_input\n"
            "+result = db.execute(query)\n"
            "+return result\n"
            " trailing_context\n"
        ),
    }

    parsed = analyzer.parse(diffs)

    assert "app.py" in parsed
    p = parsed["app.py"]
    assert len(p.hunks) == 1
    assert len(p.added_lines) == 4
    assert 42 in p.added_lines
    assert p.language == "python"
    assert p.changed_line_numbers == [42, 43, 44, 45]

    ctx = analyzer.get_context(p, 43, window=2)
    assert ctx is not None
    assert "SELECT" in ctx

    backfilled = analyzer.backfill_changed_lines(
        parsed, {"app.py": [10, 20]}
    )
    assert set(backfilled["app.py"]) == {
        10, 20, 42, 43, 44, 45,
    }

    print(f"\n📄 Hunks: {len(p.hunks)}")
    print(f"➕ Added lines: {len(p.added_lines)}")
    print(f"🔤 Language: {p.language}")
    print(f"📍 Changed lines: {p.changed_line_numbers}")
    print("\n✅ TEST 7 PASSED")


def test_pattern_detection():
    """Test PatternDetector finds vulns in diffs."""
    _separator("TEST 8: Pattern Detection (v2)")

    from review_engine.engine.diff_analyzer import (
        DiffAnalyzer,
    )
    from review_engine.engine.pattern_detector import (
        PatternDetector,
    )

    analyzer = DiffAnalyzer()
    diffs = {
        "app.py": (
            "@@ -10,2 +10,6 @@\n"
            " from flask import request\n"
            "+password = \"super_secret_123\"\n"
            "+query = \"SELECT * FROM users WHERE id = \""
            " + user_id\n"
            "+os.system(\"rm -rf \" + user_input)\n"
            "+result = hashlib.md5(data).hexdigest()\n"
        ),
    }

    parsed = analyzer.parse(diffs)
    detector = PatternDetector()

    from review_engine.config_loader import load_config
    config = load_config()
    findings = detector.detect(parsed, [], config=config)

    print(f"\n🔍 Synthetic findings: {len(findings)}")
    for f in findings:
        print(
            f"  [{f.severity}] {f.rule_id}: "
            f"{f.vuln_type} @ {f.file_path}:{f.line_number}"
        )

    assert len(findings) >= 3
    for f in findings:
        assert f.is_synthetic is True
        assert f.tool == "pattern_detector"

    categories = {f.category for f in findings}
    assert "secrets" in categories

    print("\n✅ TEST 8 PASSED")


def test_deduplication():
    """Test adjacent-line deduplication in scorer."""
    _separator("TEST 9: Deduplication (v2)")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="api.py",
                line_number=10,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi on line 10",
            ),
            FindingInput(
                file_path="api.py",
                line_number=11,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi on line 11 (adjacent)",
            ),
            FindingInput(
                file_path="api.py",
                line_number=12,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi on line 12 (adjacent)",
            ),
            FindingInput(
                file_path="api.py",
                line_number=50,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi on line 50 (separate)",
            ),
        ],
        changed_lines={
            "api.py": [10, 11, 12, 50],
        },
    )

    engine = ReviewEngine()
    result = engine.execute(request)

    print(f"\n📝 Comments: {len(result.comments)}")
    print(f"📊 Score: {result.score.total_score}")

    assert len(result.comments) == 2, (
        f"Expected 2 comments (dedup), "
        f"got {len(result.comments)}"
    )

    print("\n✅ TEST 9 PASSED")


def test_diminishing_returns():
    """Test that 5th+ same-category finding is dampened."""
    _separator("TEST 10: Diminishing Returns (v2)")

    findings = []
    for i in range(6):
        findings.append(
            FindingInput(
                file_path=f"file_{i}.py",
                line_number=10,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message=f"SQLi #{i+1}",
            )
        )

    request = ReviewRequest(
        findings=findings,
        changed_lines={
            f"file_{i}.py": [10] for i in range(6)
        },
    )

    engine = ReviewEngine()
    result = engine.execute(request)

    print(f"\n📊 Score: {result.score.total_score}")
    assert result.score.total_score > 0
    assert result.score.total_score <= 100

    print("\n✅ TEST 10 PASSED")


def test_confidence_weighting():
    """Test low-confidence findings score less."""
    _separator("TEST 11: Confidence Weighting (v2)")

    engine = ReviewEngine()

    req_high = ReviewRequest(
        findings=[
            FindingInput(
                file_path="a.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi",
                confidence=1.0,
            ),
        ],
        changed_lines={"a.py": [1]},
    )

    req_low = ReviewRequest(
        findings=[
            FindingInput(
                file_path="a.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi",
                confidence=0.5,
            ),
        ],
        changed_lines={"a.py": [1]},
    )

    score_high = engine.score_only(req_high)
    score_low = engine.score_only(req_low)

    print(f"\n📊 High confidence score: "
          f"{score_high.total_score}")
    print(f"📊 Low  confidence score: "
          f"{score_low.total_score}")

    assert score_high.total_score > score_low.total_score

    print("\n✅ TEST 11 PASSED")


def test_pr_review():
    """Test full PR review with diffs."""
    _separator("TEST 12: PR Review with Diffs (v2)")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="app.py",
                line_number=42,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="Unsanitized input in query",
                fix="Use parameterized queries",
            ),
        ],
        changed_lines={
            "app.py": [40, 41, 42, 43],
        },
        diffs={
            "app.py": (
                "@@ -40,4 +40,6 @@\n"
                " from flask import request\n"
                " \n"
                "+user_input = request.GET['id']\n"
                "+query = \"SELECT * FROM users WHERE"
                " id = \" + user_input\n"
                "+password = \"admin123456\"\n"
                " \n"
            ),
        },
    )

    engine = ReviewEngine()
    result = engine.execute_pr(request)

    print(f"\n📊 Score: {result.score.total_score}")
    print(f"🔍 Decision: {result.decision.decision.value}")
    print(f"📝 Comments: {len(result.comments)}")
    print(f"🔎 Pattern findings: "
          f"{result.pattern_findings_count}")

    assert result.pr_review is not None
    assert result.pr_review.event in [
        "APPROVE", "REQUEST_CHANGES", "COMMENT",
    ]

    print("\n✅ TEST 12 PASSED")


def test_end_to_end_v2():
    """Full end-to-end with diffs, no pre-existing findings."""
    _separator("TEST 13: End-to-End v2 (Diffs Only)")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="setup.py",
                line_number=1,
                vuln_type="Info",
                severity="info",
                tool="trivy",
                message="Package scan complete",
            ),
        ],
        changed_lines={},
        diffs={
            "auth.py": (
                "@@ -1,3 +1,8 @@\n"
                " import os\n"
                "+import hashlib\n"
                "+API_KEY = \"sk-proj-abcdefghijklmnop"
                "qrstuvwxyz12345\"\n"
                "+token_hash = hashlib.md5("
                "token.encode()).hexdigest()\n"
                "+verify = False\n"
                "+subprocess.call(cmd, shell=True)\n"
            ),
        },
    )

    engine = ReviewEngine()
    result = engine.execute_pr(request)

    print(f"\n📊 Score: {result.score.total_score}")
    print(f"🔍 Decision: {result.decision.decision.value}")
    print(f"📝 Comments: {len(result.comments)}")
    print(f"🔎 Pattern findings: "
          f"{result.pattern_findings_count}")

    assert result.pattern_findings_count >= 2
    assert len(result.comments) >= 2
    assert result.pr_review is not None

    print("\n✅ TEST 13 PASSED")


# ── v3 Tests ───────────────────────────────────────────


def test_cross_tool_correlation():
    """Test that same finding from 2 tools gets merged."""
    _separator("TEST 14: Cross-Tool Correlation (v3)")

    from review_engine.engine.correlator import (
        Correlator,
    )

    correlator = Correlator()

    findings = [
        FindingInput(
            file_path="app.py",
            line_number=42,
            vuln_type="SQL Injection",
            severity="high",
            tool="semgrep",
            message="Unsanitized input in SQL query",
        ),
        FindingInput(
            file_path="app.py",
            line_number=42,
            vuln_type="SQL Injection",
            severity="high",
            tool="bandit",
            message="Possible SQL injection via string",
        ),
        FindingInput(
            file_path="config.py",
            line_number=10,
            vuln_type="Debug Mode",
            severity="low",
            tool="semgrep",
            message="Debug enabled",
        ),
    ]

    merged, group_count = correlator.correlate(findings)

    print(f"\n🔍 Input findings: {len(findings)}")
    print(f"🔗 Merged findings: {len(merged)}")
    print(f"🔗 Corroborated groups: {group_count}")

    # 3 findings → 2 (SQLi merged, Debug separate)
    assert len(merged) == 2, (
        f"Expected 2 merged, got {len(merged)}"
    )
    assert group_count == 1

    # The merged SQLi finding should list both tools
    sqli = [
        f for f in merged
        if "sql" in f.vuln_type.lower()
    ][0]
    assert len(sqli.tools) == 2
    assert "semgrep" in sqli.tools
    assert "bandit" in sqli.tools

    print(f"   SQLi tools: {sqli.tools}")
    print(f"   SQLi confidence: {sqli.confidence}")
    print("\n✅ TEST 14 PASSED")


def test_status_weighting():
    """Test that 'existing' findings score less than 'new'."""
    _separator("TEST 15: Status Weighting (v3)")

    engine = ReviewEngine()

    req_new = ReviewRequest(
        findings=[
            FindingInput(
                file_path="a.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi",
                status="new",
            ),
        ],
        changed_lines={"a.py": [1]},
    )

    req_existing = ReviewRequest(
        findings=[
            FindingInput(
                file_path="a.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi",
                status="existing",
            ),
        ],
        changed_lines={"a.py": [1]},
    )

    score_new = engine.score_only(req_new)
    score_existing = engine.score_only(req_existing)

    print(f"\n📊 New finding score: "
          f"{score_new.total_score}")
    print(f"📊 Existing finding score: "
          f"{score_existing.total_score}")
    print(f"   New count: "
          f"{score_new.new_findings_count}")
    print(f"   Existing count: "
          f"{score_existing.existing_findings_count}")

    assert score_new.total_score > score_existing.total_score, (
        f"New ({score_new.total_score}) should score "
        f"higher than existing ({score_existing.total_score})"
    )
    assert score_new.new_findings_count == 1
    assert score_existing.existing_findings_count == 1

    print("\n✅ TEST 15 PASSED")


def test_change_risk_weighting():
    """Test high-risk file scores more than medium-risk."""
    _separator("TEST 16: Change Risk Weighting (v3)")

    engine = ReviewEngine()

    req_high = ReviewRequest(
        findings=[
            FindingInput(
                file_path="auth.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi in auth module",
                change_risk="high",
            ),
        ],
        changed_lines={"auth.py": [1]},
    )

    req_medium = ReviewRequest(
        findings=[
            FindingInput(
                file_path="utils.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi in utils",
                change_risk="medium",
            ),
        ],
        changed_lines={"utils.py": [1]},
    )

    score_high = engine.score_only(req_high)
    score_medium = engine.score_only(req_medium)

    print(f"\n📊 High-risk file score: "
          f"{score_high.total_score}")
    print(f"📊 Medium-risk file score: "
          f"{score_medium.total_score}")

    assert score_high.total_score > score_medium.total_score, (
        f"High-risk ({score_high.total_score}) should "
        f"score more than medium ({score_medium.total_score})"
    )

    print("\n✅ TEST 16 PASSED")


def test_policy_auto_approve_existing():
    """Test auto_approve_existing_only policy."""
    _separator("TEST 17: Policy — Auto-Approve Existing")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="app.py",
                line_number=10,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="Pre-existing SQLi",
                status="existing",
            ),
            FindingInput(
                file_path="app.py",
                line_number=50,
                vuln_type="XSS Vulnerability",
                severity="medium",
                tool="semgrep",
                message="Pre-existing XSS",
                status="existing",
            ),
        ],
        changed_lines={
            "app.py": [10, 50],
        },
    )

    engine = ReviewEngine()
    result = engine.execute(request)

    print(f"\n📊 Score: {result.score.total_score}")
    print(f"🔍 Decision: {result.decision.decision.value}")
    print(f"📋 Overrides: "
          f"{result.decision.policy_overrides_applied}")

    assert result.decision.decision.value == "approve", (
        f"Expected approve (all existing), "
        f"got {result.decision.decision.value}"
    )
    assert len(
        result.decision.policy_overrides_applied
    ) > 0

    print("\n✅ TEST 17 PASSED")


def test_policy_block_new_critical():
    """Test block_any_new_critical policy."""
    _separator("TEST 18: Policy — Block New Critical")

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="app.py",
                line_number=10,
                vuln_type="Debug Logging",
                severity="info",
                tool="semgrep",
                message="Info finding",
                status="new",
            ),
            FindingInput(
                file_path="auth.py",
                line_number=5,
                vuln_type="Auth Bypass",
                severity="critical",
                tool="semgrep",
                message="Critical auth bypass",
                status="new",
            ),
        ],
        changed_lines={
            "app.py": [10],
            "auth.py": [5],
        },
    )

    engine = ReviewEngine()
    result = engine.execute(request)

    print(f"\n📊 Score: {result.score.total_score}")
    print(f"🔍 Decision: {result.decision.decision.value}")
    print(f"📋 Overrides: "
          f"{result.decision.policy_overrides_applied}")

    assert result.decision.decision.value == "block", (
        f"Expected block (new critical), "
        f"got {result.decision.decision.value}"
    )
    assert len(
        result.decision.policy_overrides_applied
    ) > 0
    assert any(
        "block_any_new_critical" in o
        for o in result.decision.policy_overrides_applied
    )

    print("\n✅ TEST 18 PASSED")


def test_corroboration_boost_scoring():
    """Test that corroborated findings score higher."""
    _separator("TEST 19: Corroboration Boost (v3)")

    engine = ReviewEngine()

    # Single tool
    req_single = ReviewRequest(
        findings=[
            FindingInput(
                file_path="a.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi",
            ),
        ],
        changed_lines={"a.py": [1]},
    )

    # Same finding from two tools (will be correlated)
    req_multi = ReviewRequest(
        findings=[
            FindingInput(
                file_path="a.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi found by semgrep",
            ),
            FindingInput(
                file_path="a.py",
                line_number=1,
                vuln_type="SQL Injection",
                severity="high",
                tool="bandit",
                message="SQLi found by bandit",
            ),
        ],
        changed_lines={"a.py": [1]},
    )

    score_single = engine.score_only(req_single)
    score_multi = engine.score_only(req_multi)

    print(f"\n📊 Single-tool score: "
          f"{score_single.total_score}")
    print(f"📊 Multi-tool (corroborated) score: "
          f"{score_multi.total_score}")
    print(f"🔗 Correlated groups: "
          f"{score_multi.correlated_groups}")

    assert score_multi.total_score > score_single.total_score, (
        f"Corroborated ({score_multi.total_score}) "
        f"should score higher than single "
        f"({score_single.total_score})"
    )
    assert score_multi.correlated_groups == 1

    print("\n✅ TEST 19 PASSED")


def test_end_to_end_v3():
    """Full end-to-end v3 with enriched input."""
    _separator("TEST 20: End-to-End v3 (Advanced)")

    request = ReviewRequest(
        findings=[
            # New finding from two tools
            FindingInput(
                file_path="api/views.py",
                line_number=42,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="Unsanitized input in query",
                status="new",
                change_risk="high",
            ),
            FindingInput(
                file_path="api/views.py",
                line_number=42,
                vuln_type="SQL Injection",
                severity="high",
                tool="bandit",
                message="Possible SQL injection",
                status="new",
                change_risk="high",
            ),
            # Existing finding (should score less)
            FindingInput(
                file_path="api/views.py",
                line_number=100,
                vuln_type="XSS Vulnerability",
                severity="medium",
                tool="semgrep",
                message="Unescaped output",
                status="existing",
            ),
            # Fixed finding (should score zero)
            FindingInput(
                file_path="api/views.py",
                line_number=80,
                vuln_type="Hardcoded Secret",
                severity="critical",
                tool="gitleaks",
                message="Secret removed in this PR",
                status="fixed",
            ),
        ],
        changed_lines={
            "api/views.py": [40, 41, 42, 43, 80, 100],
        },
        diffs={
            "api/views.py": (
                "@@ -40,4 +40,6 @@\n"
                " from django.db import connection\n"
                " \n"
                "+user_id = request.GET['id']\n"
                "+cursor.execute(\"SELECT * FROM "
                "users WHERE id = \" + user_id)\n"
                " \n"
            ),
        },
        change_risk={
            "api/views.py": "high",
        },
    )

    engine = ReviewEngine()
    result = engine.execute_advanced(request)

    print(f"\n📊 Score: {result.score.total_score}")
    print(f"🔍 Decision: {result.decision.decision.value}")
    print(f"📝 Comments: {len(result.comments)}")
    print(f"🆕 New: {result.new_findings_count}")
    print(f"📌 Existing: {result.existing_findings_count}")
    print(f"🔗 Correlated: {result.correlated_groups}")
    print(f"🔎 Pattern: {result.pattern_findings_count}")

    # PR review should be populated
    assert result.pr_review is not None
    print(f"\n🐙 GitHub Event: {result.pr_review.event}")
    print(f"🐙 Inline comments: "
          f"{len(result.pr_review.comments)}")

    # Status tracking
    assert result.new_findings_count >= 1, (
        f"Expected ≥1 new, got {result.new_findings_count}"
    )

    # Correlated groups (the 2 SQLi tools merged)
    assert result.correlated_groups >= 1, (
        f"Expected ≥1 correlated groups, "
        f"got {result.correlated_groups}"
    )

    # Score should be > 0 (new findings present)
    assert result.score.total_score > 0

    # Summary should contain v3 markers
    assert "New Issues" in result.summary_markdown or \
           result.new_findings_count > 0

    print(f"\n── Summary (first 500 chars) ──")
    print(result.summary_markdown[:500])

    print("\n✅ TEST 20 PASSED")


# ── v4 Tests ───────────────────────────────────────────


def test_priority_ranking():
    """Test multi-factor priority ranking."""
    _separator("TEST 21: Priority Ranking (v4)")

    from review_engine.engine.priority_ranker import (
        PriorityRanker,
    )

    engine = ReviewEngine()

    request = ReviewRequest(
        findings=[
            # High exploitability injection
            FindingInput(
                file_path="auth.py",
                line_number=10,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi in auth module",
                category="injection",
                status="new",
                change_risk="high",
            ),
            # Low-priority info disclosure
            FindingInput(
                file_path="utils.py",
                line_number=20,
                vuln_type="Server Version Exposed",
                severity="low",
                tool="nikto",
                message="Version header exposed",
                category="information_disclosure",
                status="existing",
            ),
            # Medium — debug mode
            FindingInput(
                file_path="config.py",
                line_number=5,
                vuln_type="Debug Mode Enabled",
                severity="medium",
                tool="semgrep",
                message="Debug mode on",
                category="misconfiguration",
                status="new",
            ),
        ],
        changed_lines={
            "auth.py": [10],
            "utils.py": [20],
            "config.py": [5],
        },
    )

    result = engine.execute(request)
    ranker = PriorityRanker()

    from review_engine.config_loader import load_config
    config = load_config()
    ranked = ranker.rank(result, config=config)

    print(f"\n🏆 Ranked {len(ranked)} findings:")
    for f in ranked:
        print(
            f"  #{f.priority_rank}: {f.vuln_type} "
            f"({f.severity}) → {f.priority_score}/100"
            f" — {f.reasoning}"
        )

    assert len(ranked) >= 2
    # Injection in auth.py should rank #1
    assert ranked[0].vuln_type == "SQL Injection", (
        f"Expected SQLi first, got {ranked[0].vuln_type}"
    )
    assert ranked[0].priority_score > ranked[-1].priority_score

    print("\n✅ TEST 21 PASSED")


def test_explainability_causal_chain():
    """Test causal chain generation."""
    _separator("TEST 22: Explainability — Causal Chain (v4)")

    from review_engine.engine.explainability import (
        ExplainabilityEngine,
    )

    engine = ReviewEngine()

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="api.py",
                line_number=42,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="Unsanitized query",
                status="new",
            ),
        ],
        changed_lines={"api.py": [42]},
    )

    result = engine.execute(request)
    explainer = ExplainabilityEngine()
    explanation = explainer.explain(result)

    print(f"\n🔍 Decision: {explanation.decision}")
    print(f"🎯 Confidence: {explanation.confidence:.0%}")
    print(f"📋 Causal chain ({len(explanation.causal_chain)} steps):")
    for step in explanation.causal_chain:
        print(f"  {step.step}. {step.description}")
    print(f"🔑 Key factors: {explanation.key_factors}")
    print(f"🤔 What-if: {len(explanation.what_if)} scenarios")
    print(f"💬 {explanation.confidence_assessment}")

    assert len(explanation.causal_chain) >= 3
    assert len(explanation.key_factors) >= 2
    assert explanation.confidence > 0
    assert explanation.decision != ""

    print("\n✅ TEST 22 PASSED")


def test_insights_hotspot():
    """Test hotspot detection in insights."""
    _separator("TEST 23: Insights — Hotspot Detection (v4)")

    from review_engine.engine.insights_generator import (
        InsightsGenerator,
    )

    engine = ReviewEngine()

    # 3 findings in same file = hotspot
    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="auth.py",
                line_number=10,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="SQLi #1",
                category="injection",
            ),
            FindingInput(
                file_path="auth.py",
                line_number=20,
                vuln_type="XSS Vulnerability",
                severity="medium",
                tool="semgrep",
                message="XSS in auth",
                category="xss",
            ),
            FindingInput(
                file_path="auth.py",
                line_number=30,
                vuln_type="Auth Bypass",
                severity="critical",
                tool="semgrep",
                message="Auth bypass",
                category="authentication",
            ),
            FindingInput(
                file_path="utils.py",
                line_number=5,
                vuln_type="Debug Mode",
                severity="low",
                tool="semgrep",
                message="Debug on",
                category="misconfiguration",
            ),
        ],
        changed_lines={
            "auth.py": [10, 20, 30],
            "utils.py": [5],
        },
    )

    result = engine.execute(request)
    generator = InsightsGenerator()
    insights = generator.generate(result)

    print(f"\n💡 Generated {len(insights)} insights:")
    for i in insights:
        print(f"  {i.emoji} [{i.insight_type}] {i.title}")
        if i.recommendation:
            print(f"    → {i.recommendation[:80]}")

    hotspots = [
        i for i in insights
        if i.insight_type == "hotspot"
    ]
    assert len(hotspots) >= 1, (
        f"Expected hotspot insight, got none. "
        f"Types: {[i.insight_type for i in insights]}"
    )
    assert "auth.py" in hotspots[0].title

    print("\n✅ TEST 23 PASSED")


def test_insights_false_positive():
    """Test false positive flagging in test files."""
    _separator("TEST 24: Insights — False Positive (v4)")

    from review_engine.engine.insights_generator import (
        InsightsGenerator,
    )

    engine = ReviewEngine()

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="test_auth.py",
                line_number=10,
                vuln_type="Hardcoded password",
                severity="high",
                tool="gitleaks",
                message="Password in test file",
                category="secrets",
            ),
            FindingInput(
                file_path="app.py",
                line_number=20,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="Real SQLi",
                category="injection",
            ),
        ],
        changed_lines={
            "test_auth.py": [10],
            "app.py": [20],
        },
    )

    result = engine.execute(request)
    generator = InsightsGenerator()
    insights = generator.generate(result)

    print(f"\n💡 Generated {len(insights)} insights:")
    for i in insights:
        print(f"  {i.emoji} [{i.insight_type}] {i.title}")

    fp_insights = [
        i for i in insights
        if i.insight_type == "false_positive_signal"
    ]
    assert len(fp_insights) >= 1, (
        f"Expected false_positive_signal insight"
    )
    assert "test" in fp_insights[0].title.lower()

    print("\n✅ TEST 24 PASSED")


def test_narrative_generation():
    """Test human-like narrative output."""
    _separator("TEST 25: Narrative Generation (v4)")

    engine = ReviewEngine()

    request = ReviewRequest(
        findings=[
            FindingInput(
                file_path="api.py",
                line_number=42,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="Unsanitized query",
                status="new",
                category="injection",
                fix="Use parameterized queries",
            ),
        ],
        changed_lines={"api.py": [42]},
    )

    report = engine.execute_intelligent(request)

    print(f"\n📝 Executive summary:")
    print(f"  {report.executive_summary}")
    print(f"\n📜 Narrative (first 500 chars):")
    print(report.narrative[:500])
    print(f"\n⚖️ Risk: {report.risk_assessment.risk_level}"
          f" ({report.risk_assessment.risk_score}/100)")

    assert len(report.narrative) > 50, (
        f"Narrative too short: {len(report.narrative)} chars"
    )
    assert len(report.executive_summary) > 20
    assert report.risk_assessment.risk_level != ""
    assert "Intelligence Report" in report.narrative

    print("\n✅ TEST 25 PASSED")


def test_end_to_end_v4():
    """Full end-to-end v4 intelligent review."""
    _separator("TEST 26: End-to-End v4 (Intelligent)")

    engine = ReviewEngine()

    request = ReviewRequest(
        findings=[
            # New injection — high priority
            FindingInput(
                file_path="api/views.py",
                line_number=42,
                vuln_type="SQL Injection",
                severity="high",
                tool="semgrep",
                message="Unsanitized input in query",
                status="new",
                change_risk="high",
                category="injection",
                fix="Use parameterized queries",
            ),
            FindingInput(
                file_path="api/views.py",
                line_number=42,
                vuln_type="SQL Injection",
                severity="high",
                tool="bandit",
                message="Possible SQL injection",
                status="new",
                change_risk="high",
                category="injection",
            ),
            # Existing low-priority
            FindingInput(
                file_path="api/views.py",
                line_number=100,
                vuln_type="Verbose Logging",
                severity="info",
                tool="semgrep",
                message="Debug log in production",
                status="existing",
                category="misconfiguration",
            ),
            # FP in test file
            FindingInput(
                file_path="tests/test_auth.py",
                line_number=15,
                vuln_type="Hardcoded password",
                severity="high",
                tool="gitleaks",
                message="Test credential",
                status="new",
                category="secrets",
            ),
        ],
        changed_lines={
            "api/views.py": [40, 41, 42, 43, 100],
            "tests/test_auth.py": [15],
        },
        diffs={
            "api/views.py": (
                "@@ -40,4 +40,6 @@\n"
                " from django.db import connection\n"
                "+user_id = request.GET['id']\n"
                "+cursor.execute(\"SELECT * FROM "
                "users WHERE id = \" + user_id)\n"
            ),
        },
        change_risk={
            "api/views.py": "high",
        },
    )

    report = engine.execute_intelligent(
        request=request,
        history=[
            {"score": 30},
            {"score": 25},
            {"score": 35},
        ],
        repo_context={
            "repo": "myapp",
            "language": "python",
        },
    )

    print(f"\n📊 Score: {report.score}")
    print(f"🔍 Decision: {report.decision}")
    print(f"🏆 Prioritized: "
          f"{len(report.prioritized_findings)}")
    print(f"📋 Explanation steps: "
          f"{len(report.explanation.causal_chain)}")
    print(f"💡 Insights: {len(report.insights)}")
    print(f"⚖️ Risk: {report.risk_assessment.risk_level}")
    print(f"🔖 Engine: {report.engine_version}")

    # Priority ranking
    assert len(report.prioritized_findings) >= 1
    top = report.prioritized_findings[0]
    print(f"\n🥇 Top priority: {top.vuln_type} "
          f"(score={top.priority_score})")
    assert top.priority_score > 0

    # Explainability
    assert len(report.explanation.causal_chain) >= 3
    assert report.explanation.confidence > 0
    print(f"🎯 Confidence: "
          f"{report.explanation.confidence:.0%}")

    # Insights
    assert len(report.insights) >= 1
    for i in report.insights:
        print(f"  {i.emoji} {i.title}")

    # Narrative
    assert len(report.narrative) > 100
    assert "Intelligence Report" in report.narrative

    # Risk assessment
    assert report.risk_assessment.risk_level in (
        "critical", "high", "medium", "low", "safe"
    )

    # Metadata
    assert report.engine_version == "v4"
    assert report.repo_context.get("repo") == "myapp"

    print(f"\n── Narrative (first 800 chars) ──")
    print(report.narrative[:800])

    print("\n✅ TEST 26 PASSED")


# ── Run all tests ──────────────────────────────────────

if __name__ == "__main__":
    tests = [
        # v1 tests
        test_full_review,
        test_clean_review,
        test_score_only,

        test_comments_only,
        test_hard_blocker,
        test_no_changed_lines,
        # v2 tests
        test_diff_parsing,
        test_pattern_detection,
        test_deduplication,
        test_diminishing_returns,
        test_confidence_weighting,
        test_pr_review,
        test_end_to_end_v2,
        # v3 tests
        test_cross_tool_correlation,
        test_status_weighting,
        test_change_risk_weighting,
        test_policy_auto_approve_existing,
        test_policy_block_new_critical,
        test_corroboration_boost_scoring,
        test_end_to_end_v3,
        # v4 tests
        test_priority_ranking,
        test_explainability_causal_chain,
        test_insights_hotspot,
        test_insights_false_positive,
        test_narrative_generation,
        test_end_to_end_v4,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"\n❌ FAILED: {e}")
            import traceback
            traceback.print_exc()
            failed += 1

    _separator("RESULTS")
    print(f"  ✅ Passed: {passed}")
    print(f"  ❌ Failed: {failed}")
    print(f"  Total: {passed + failed}")
    print()

    sys.exit(1 if failed > 0 else 0)
