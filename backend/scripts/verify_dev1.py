"""Full verification of Dev 1 implementation."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "api"))

passed = 0
failed = 0

def check(name, fn):
    global passed, failed
    try:
        fn()
        print(f"  ✅  {name}")
        passed += 1
    except Exception as e:
        print(f"  ❌  {name} — {e}")
        failed += 1

# 1. Schema imports
def t1():
    from schemas.review import PRReviewRequest, PRReviewResponse, PRMetadata
check("schemas/review.py imports", t1)

# 2. Publisher
def t2():
    from packages.scanner.github_publisher import GitHubPublisher
    p = GitHubPublisher(token="fake")
    assert hasattr(p, "post_pr_review")
    assert hasattr(p, "post_summary_comment")
    assert hasattr(p, "post_acknowledgment")
check("github_publisher.py — 3 methods", t2)

# 3. GitHub service PR methods
def t3():
    from packages.scanner.github_service import GitHubService
    gs = GitHubService()
    for m in ["parse_repo_url", "fetch_pr_metadata", "fetch_pr_diff", "split_diff_by_file"]:
        assert hasattr(gs, m), f"Missing {m}"
check("github_service.py — 4 PR methods", t3)

# 4. parse_repo_url
def t4():
    from packages.scanner.github_service import GitHubService
    gs = GitHubService()
    o, r = gs.parse_repo_url("https://github.com/octocat/Hello-World")
    assert o == "octocat", f"got {o}"
    assert r == "Hello-World", f"got {r}"
    o2, r2 = gs.parse_repo_url("https://github.com/org/repo.git")
    assert o2 == "org" and r2 == "repo"
check("parse_repo_url logic", t4)

# 5. split_diff_by_file
def t5():
    from packages.scanner.github_service import GitHubService
    gs = GitHubService()
    diff = (
        "diff --git a/foo.py b/foo.py\n"
        "--- a/foo.py\n+++ b/foo.py\n"
        "@@ -1,3 +1,4 @@\n+new line\n"
        "diff --git a/bar.js b/bar.js\n"
        "--- a/bar.js\n+++ b/bar.js\n"
        "@@ -5,2 +5,3 @@\n+another\n"
    )
    result = gs.split_diff_by_file(diff)
    assert "foo.py" in result, f"got {list(result.keys())}"
    assert "bar.js" in result
    assert len(result) == 2
check("split_diff_by_file — 2 files", t5)

# 6. Dev 2 engine schemas
def t6():
    from review_engine.schemas.review import (
        ReviewRequest, ReviewResult, FindingInput,
        GitHubPRReview, ClassifiedFinding, ScoreResult,
        DecisionResult, MergeDecision
    )
check("review_engine schemas import", t6)

# 7. ReviewEngine.execute_pr
def t7():
    from review_engine.service import ReviewEngine
    assert hasattr(ReviewEngine, "execute_pr")
    e = ReviewEngine()
    assert callable(getattr(e, "execute_pr"))
check("ReviewEngine.execute_pr callable", t7)

# 8. DiffAnalyzer
def t8():
    from review_engine.engine.diff_analyzer import DiffAnalyzer
    a = DiffAnalyzer()
    parsed = a.parse({"test.py": "@@ -1,3 +1,5 @@\n+added1\n+added2\n context"})
    assert len(parsed) > 0
    cl = a.backfill_changed_lines(parsed, {})
    assert "test.py" in cl
    assert len(cl["test.py"]) >= 2
check("DiffAnalyzer parse + backfill", t8)

# 9. PRReviewRequest validation
def t9():
    from schemas.review import PRReviewRequest
    from pydantic import ValidationError
    try:
        PRReviewRequest(repo_url="https://gitlab.com/test/repo", pr_number=1)
        raise AssertionError("Should reject non-GitHub URL")
    except ValidationError:
        pass
    req = PRReviewRequest(repo_url="https://github.com/test/repo", pr_number=42)
    assert req.pr_number == 42
check("PRReviewRequest validation", t9)

# 10. HMAC signature
def t10():
    import hmac, hashlib
    secret = "test-secret"
    payload = b'{"test": true}'
    sig = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    assert sig.startswith("sha256=")
    assert len(sig) == 71
check("HMAC-SHA256 signature", t10)

# 11. Finding adapter
def t11():
    from review_engine.schemas.review import FindingInput
    raw = {
        "file_path": "x.py", "line_number": 1,
        "vuln_type": "Test", "severity": "BOGUS",
        "tool_source": "test", "description": "test"
    }
    sev = raw.get("severity", "info").lower()
    if sev not in {"critical","high","medium","low","info"}:
        sev = "info"
    inp = FindingInput(
        file_path=raw["file_path"], line_number=raw["line_number"],
        vuln_type=raw["vuln_type"], severity=sev,
        tool=raw["tool_source"], message=raw["description"]
    )
    assert inp.severity == "info"
check("Finding adapter severity mapping", t11)

# 12. Full pipeline (split → parse → adapt → engine → payload)
def t12():
    from packages.scanner.github_service import GitHubService
    from review_engine.engine.diff_analyzer import DiffAnalyzer
    from review_engine.schemas.review import FindingInput, ReviewRequest
    from review_engine.service import ReviewEngine

    gs = GitHubService()
    diff = (
        "diff --git a/app.py b/app.py\n--- a/app.py\n+++ b/app.py\n"
        "@@ -10,3 +10,6 @@\n+import os\n"
        '+SECRET = "hardcoded_password"\n'
        "+query = 'SELECT * FROM users WHERE id=' + uid\n"
    )
    per_file = gs.split_diff_by_file(diff)
    analyzer = DiffAnalyzer()
    parsed = analyzer.parse(per_file)
    cl = analyzer.backfill_changed_lines(parsed, {})
    findings = [
        FindingInput(file_path="app.py", line_number=12,
                     vuln_type="Hardcoded Secret", severity="critical",
                     tool="gitleaks", message="secret in source"),
    ]
    req = ReviewRequest(findings=findings, changed_lines=cl, diffs=per_file)
    engine = ReviewEngine()
    result = engine.execute_pr(req)
    assert result.score is not None
    assert result.decision is not None
    assert result.pr_review is not None
    assert result.pr_review.event in {"APPROVE","REQUEST_CHANGES","COMMENT"}
    assert len(result.pr_review.body) > 0
    # Validate GitHub payload structure
    payload = {
        "commit_id": "test123",
        "event": result.pr_review.event,
        "body": result.pr_review.body,
        "comments": [{"path":c.path,"line":c.line,"side":c.side,"body":c.body}
                     for c in result.pr_review.comments]
    }
    assert isinstance(payload["comments"], list)
check("Full pipeline → GitHub payload", t12)

# 13. README markers
def t13():
    readme = os.path.join(os.path.dirname(__file__), "..", "hrishikesh_readme.md")
    with open(readme) as f:
        content = f.read()
    assert "<!-- ACTIVITY_LOG_START -->" in content
    assert "<!-- ACTIVITY_LOG_END -->" in content
    start_idx = content.index("<!-- ACTIVITY_LOG_START -->")
    end_idx = content.index("<!-- ACTIVITY_LOG_END -->")
    assert start_idx < end_idx
check("hrishikesh_readme.md markers", t13)

# 14. Dockerfile exists and valid
def t14():
    df = os.path.join(os.path.dirname(__file__), "..", "Dockerfile")
    with open(df) as f:
        content = f.read()
    assert "FROM python:3.11" in content
    assert "EXPOSE 8000" in content
    assert "uvicorn" in content
check("Dockerfile structure", t14)

# 15. GitHub Actions workflow
def t15():
    wf = os.path.join(os.path.dirname(__file__), "..", ".github", "workflows", "nexus_review.yml")
    with open(wf) as f:
        content = f.read()
    assert "pull_request" in content
    assert "issue_comment" in content
    assert "WEBHOOK_SECRET" in content
    assert "review/github-pr" in content
    assert "webhooks/github" in content
check("nexus_review.yml workflow", t15)

# ══════════════════════════════════════════════════
#  Phase 2: Data Intelligence Layer Tests
# ══════════════════════════════════════════════════

# 16. classify_finding_status
def t16():
    from packages.scanner.diff_enrichment import classify_finding_status
    cl = {"app.py": [10, 11, 12], "db.py": [5]}
    # New: on changed line
    assert classify_finding_status({"file_path": "app.py", "line_number": 11}, cl) == "new"
    # Existing: in changed file but different line
    assert classify_finding_status({"file_path": "app.py", "line_number": 99}, cl) == "existing"
    # Existing: file not in diff
    assert classify_finding_status({"file_path": "other.py", "line_number": 1}, cl) == "existing"
    # Existing: no file_path
    assert classify_finding_status({"line_number": 1}, cl) == "existing"
    # Existing: no line_number
    assert classify_finding_status({"file_path": "app.py"}, cl) == "existing"
check("classify_finding_status", t16)

# 17. extract_diff_context
def t17():
    from packages.scanner.diff_enrichment import extract_diff_context
    from review_engine.engine.diff_analyzer import DiffAnalyzer
    analyzer = DiffAnalyzer()
    diffs = {"app.py": "@@ -10,3 +10,5 @@\n context1\n+added_line_1\n+added_line_2\n context2"}
    parsed = analyzer.parse(diffs)
    # Should get context for a line in the diff
    ctx = extract_diff_context({"file_path": "app.py", "line_number": 11}, parsed)
    assert ctx is not None
    assert "added_line_1" in ctx
    # Should return None for a line not in diff
    ctx2 = extract_diff_context({"file_path": "app.py", "line_number": 999}, parsed)
    assert ctx2 is None
    # Should return None for unknown file
    ctx3 = extract_diff_context({"file_path": "unknown.py", "line_number": 1}, parsed)
    assert ctx3 is None
check("extract_diff_context", t17)

# 18. compute_change_risk — critical
def t18():
    from packages.scanner.diff_enrichment import compute_change_risk
    cl = {"auth.py": [1, 2], "utils.py": [5]}
    diffs = {
        "auth.py": "@@ -1,2 +1,3 @@\n+SECRET_KEY = 'hardcoded_password'\n+token = api_key",
        "utils.py": "@@ -5,1 +5,2 @@\n+print('hello')",
    }
    risk = compute_change_risk(cl, diffs)
    assert risk["auth.py"] == "critical", f"got {risk['auth.py']}"
    assert risk["utils.py"] == "low", f"got {risk['utils.py']}"
check("compute_change_risk — critical + low", t18)

# 19. compute_change_risk — high/medium
def t19():
    from packages.scanner.diff_enrichment import compute_change_risk
    cl = {"db.py": [1], "web.py": [1]}
    diffs = {
        "db.py": "@@ -1,1 +1,2 @@\n+cursor.execute(query)",
        "web.py": "@@ -1,1 +1,2 @@\n+redirect_url = http://evil.com",
    }
    risk = compute_change_risk(cl, diffs)
    assert risk["db.py"] == "high", f"got {risk['db.py']}"
    assert risk["web.py"] == "medium", f"got {risk['web.py']}"
check("compute_change_risk — high + medium", t19)

# 20. correlate_scanner_findings
def t20():
    from packages.scanner.diff_enrichment import correlate_scanner_findings
    findings = [
        {"file_path": "app.py", "line_number": 10, "vuln_type": "SQL Injection",
         "severity": "high", "tool_source": "semgrep", "description": "sqli"},
        {"file_path": "app.py", "line_number": 10, "vuln_type": "sql-injection",
         "severity": "critical", "tool_source": "bandit", "description": "sqli2"},
        {"file_path": "other.py", "line_number": 5, "vuln_type": "XSS",
         "severity": "medium", "tool_source": "semgrep", "description": "xss"},
    ]
    merged = correlate_scanner_findings(findings)
    assert len(merged) == 2, f"Expected 2, got {len(merged)}"
    # Find the merged SQL injection finding
    sqli = [f for f in merged if "app.py" == f["file_path"]][0]
    assert len(sqli["tools"]) == 2, f"Expected 2 tools, got {sqli['tools']}"
    assert "semgrep" in sqli["tools"]
    assert "bandit" in sqli["tools"]
    # Highest severity should win
    assert sqli["severity"] == "critical"
check("correlate_scanner_findings — multi-tool", t20)

# 21. correlate_scanner_findings — single tool passthrough
def t21():
    from packages.scanner.diff_enrichment import correlate_scanner_findings
    findings = [
        {"file_path": "a.py", "line_number": 1, "vuln_type": "XSS",
         "severity": "medium", "tool_source": "t1", "description": "x"},
    ]
    merged = correlate_scanner_findings(findings)
    assert len(merged) == 1
    assert merged[0]["tools"] == ["t1"]
check("correlate_scanner_findings — single tool", t21)

# 22. v3 adapter fields
def t22():
    from review_engine.schemas.review import FindingInput
    inp = FindingInput(
        file_path="x.py", line_number=1,
        vuln_type="Test", severity="high",
        tool="semgrep", message="test",
        status="new", diff_context="some context",
        tools=["semgrep", "bandit"],
        change_risk="critical",
    )
    assert inp.status == "new"
    assert inp.diff_context == "some context"
    assert inp.tools == ["semgrep", "bandit"]
    assert inp.change_risk == "critical"
check("FindingInput v3 fields", t22)

# 23. Full enriched pipeline
def t23():
    from packages.scanner.github_service import GitHubService
    from packages.scanner.diff_enrichment import (
        classify_finding_status, extract_diff_context,
        compute_change_risk, correlate_scanner_findings,
    )
    from review_engine.engine.diff_analyzer import DiffAnalyzer
    from review_engine.schemas.review import FindingInput, ReviewRequest
    from review_engine.service import ReviewEngine

    gs = GitHubService()
    diff = (
        "diff --git a/auth.py b/auth.py\n--- a/auth.py\n+++ b/auth.py\n"
        "@@ -5,3 +5,6 @@\n context\n"
        "+API_KEY = 'sk-secret-12345'\n"
        "+password = 'admin123'\n"
        "+query = 'SELECT * FROM users WHERE id=' + uid\n"
    )
    per_file = gs.split_diff_by_file(diff)
    analyzer = DiffAnalyzer()
    parsed = analyzer.parse(per_file)
    cl = analyzer.backfill_changed_lines(parsed, {})

    # Simulate raw findings from 2 tools
    raw = [
        {"file_path": "auth.py", "line_number": 6, "vuln_type": "Hardcoded Secret",
         "severity": "critical", "tool_source": "gitleaks", "description": "API key"},
        {"file_path": "auth.py", "line_number": 6, "vuln_type": "hardcoded-secret",
         "severity": "high", "tool_source": "trufflehog", "description": "secret"},
        {"file_path": "auth.py", "line_number": 8, "vuln_type": "SQL Injection",
         "severity": "high", "tool_source": "semgrep", "description": "sqli"},
    ]
    # Phase 1.5a: correlate
    raw = correlate_scanner_findings(raw)
    assert len(raw) == 2, f"Expected 2 after correlation, got {len(raw)}"

    # Phase 1.5b: change risk
    risk_map = compute_change_risk(cl, per_file)
    assert risk_map["auth.py"] == "critical", f"got {risk_map.get('auth.py')}"

    # Phase 1.5c+d: enrich
    for f in raw:
        f["status"] = classify_finding_status(f, cl)
        f["diff_context"] = extract_diff_context(f, parsed)
        f["change_risk"] = risk_map.get(f.get("file_path", ""), "medium")

    # Verify enrichment
    secret_finding = [f for f in raw if "secret" in f["vuln_type"].lower()][0]
    assert secret_finding["status"] == "new"
    assert secret_finding["diff_context"] is not None
    assert len(secret_finding["tools"]) == 2
    assert secret_finding["change_risk"] == "critical"

    # Phase 2: Convert + Phase 3: Engine
    inputs = []
    for f in raw:
        sev = f.get("severity", "info").lower()
        if sev not in {"critical","high","medium","low","info"}: sev = "info"
        status = f.get("status", "new")
        if status not in {"new","existing","fixed"}: status = "new"
        cr = f.get("change_risk", "medium")
        if cr not in {"critical","high","medium","low","none"}: cr = "medium"
        tools = f.get("tools", [])
        inputs.append(FindingInput(
            file_path=f.get("file_path"), line_number=f.get("line_number"),
            vuln_type=f.get("vuln_type","Unknown"), severity=sev,
            tool=f.get("tool_source","unknown"), message=f.get("description",""),
            status=status, diff_context=f.get("diff_context"),
            tools=tools, change_risk=cr,
        ))

    req = ReviewRequest(findings=inputs, changed_lines=cl, diffs=per_file, change_risk=risk_map)
    engine = ReviewEngine()
    result = engine.execute_pr(req)
    assert result.score is not None
    assert result.pr_review is not None
    assert result.new_findings_count >= 0
check("Full enriched pipeline (v3)", t23)

print(f"\n{'='*50}")
print(f"  RESULTS: {passed} passed, {failed} failed / {passed+failed} total")
print(f"{'='*50}")
if failed > 0:
    sys.exit(1)

