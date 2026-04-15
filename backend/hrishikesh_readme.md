# 🛡️ AuditLens — Dev 1 (Hrishikesh Patil)

> **Role**: Backend Developer 1  
> **Scope**: GitHub API · Data Pipeline · Orchestration  
> **Boundary**: NO scoring logic, decision engines, severity mapping, or config YAML files

---

## 📋 My Responsibilities

| # | Workstream | Status | Key Files |
|---|-----------|--------|-----------|
| 1 | **PR Ingestion & Diff Parser** | ✅ Done | `api/api/v1/review.py`, `api/packages/scanner/github_service.py` |
| 2 | **PR Scan Celery Task** | ✅ Done | `api/workers/tasks/sast.py` (`run_pr_scan`) |
| 3 | **GitHub Publisher** | ✅ Done | `api/packages/scanner/github_publisher.py` |
| 4 | **Re-Review Webhook** | ✅ Done | `api/api/v1/webhooks.py` |
| 5 | **DevOps & Infrastructure** | ✅ Done | `Dockerfile`, `.github/workflows/nexus_review.yml` |

---

## 🏗️ Architecture (Dev 1 Scope)

```
GitHub Actions (PR opened / "fixed" comment)
    │
    ▼
POST /api/v1/review/github-pr ─── X-Webhook-Secret auth
    │
    ├── GitHubService.fetch_pr_metadata()
    ├── GitHubService.fetch_pr_diff()
    ├── GitHubService.split_diff_by_file()
    ├── DiffAnalyzer.backfill_changed_lines()  ← Dev 2's module
    └── Celery dispatch → run_pr_scan
                              │
                              ├── Phase 1: Semgrep + Gitleaks + TruffleHog + Bandit + Trivy
                              ├── Phase 2: _convert_to_finding_inputs() → FindingInput[]
                              ├── Phase 3: ReviewEngine.execute_pr()    ← Dev 2's engine
                              └── Phase 4: GitHubPublisher → GitHub PR
```

---

## 🔌 Integration Contract with Dev 2

| Direction | Data | Schema |
|-----------|------|--------|
| **My Pipeline → Dev 2** | `ReviewRequest(findings, changed_lines, diffs)` | `review_engine/schemas/review.py` |
| **Dev 2 → My Publisher** | `ReviewResult.pr_review → GitHubPRReview` | `review_engine/schemas/review.py` |

---

## 📁 Files I Own

### New Files (6)
- `api/api/v1/review.py` — PR review endpoint
- `api/api/v1/webhooks.py` — GitHub webhook listener
- `api/schemas/review.py` — API-layer Pydantic schemas
- `api/packages/scanner/github_publisher.py` — GitHub API transport
- `Dockerfile` — Slim SAST-only container
- `.github/workflows/nexus_review.yml` — CI trigger

### Modified Files (4)
- `api/packages/scanner/github_service.py` — +4 PR methods
- `api/workers/tasks/sast.py` — +`run_pr_scan` task
- `api/main.py` — Router registration
- `api/api/v1/__init__.py` — Module imports

### Test Scripts (4)
- `scripts/test_pipeline_e2e.py` — Offline E2E (5/5 pass)
- `scripts/test_pr_trigger.py` — API endpoint test
- `scripts/test_fixed_webhook.py` — Webhook simulation
- `scripts/check_github_token.py` — Token validator

---

## 🔑 Environment Variables

| Variable | Purpose |
|----------|---------|
| `GITHUB_TOKEN` | GitHub API auth (fetch PR data + post reviews) |
| `WEBHOOK_SECRET` | Shared secret for endpoint & webhook HMAC auth |

---

## 🧬 Phase 2: Data Intelligence Layer

> Enriches raw scanner findings with PR-aware context before handing to Dev 2's v3 engine.

### New Module: `api/packages/scanner/diff_enrichment.py`

| Function | What It Does | Output |
|----------|-------------|--------|
| `classify_finding_status()` | Checks if finding is on a changed line | `"new"` or `"existing"` |
| `extract_diff_context()` | Extracts ±3 lines of code around finding | Context string |
| `compute_change_risk()` | Scans added lines for security keywords | `{"file": "critical\|high\|medium\|low"}` |
| `correlate_scanner_findings()` | Pre-merges identical findings from multiple tools | `tools: ["semgrep", "bandit"]` |

### Pipeline Architecture (Phase 1.5)

```
Phase 1:   SAST Scanners → raw findings[]
Phase 1.5: Data Intelligence (NEW)
  ├── 1.5a: correlate_scanner_findings() → dedup + tools[]
  ├── 1.5b: compute_change_risk()        → per-file risk map
  ├── 1.5c: parse diffs (DiffAnalyzer)   → structured context
  └── 1.5d: enrich each finding          → status + diff_context + change_risk
Phase 2:   _convert_to_finding_inputs()  → FindingInput[] (v3 fields)
Phase 3:   ReviewEngine.execute_pr()     → ReviewResult
Phase 4:   GitHubPublisher               → GitHub PR
```

### v3 Fields Supplied to Dev 2

| Field | Type | Source |
|-------|------|--------|
| `status` | `"new"` \| `"existing"` | `classify_finding_status()` |
| `diff_context` | `string` | `extract_diff_context()` |
| `tools` | `["semgrep", "bandit"]` | `correlate_scanner_findings()` |
| `change_risk` | `"critical"` \| `"high"` \| ... | `compute_change_risk()` |
| `ReviewRequest.change_risk` | `{file: risk}` | `compute_change_risk()` |

---

## ✅ Test Results

```
Dev 1 Verification: 23/23 passed
Dev 2 Engine:       26/26 passed
E2E Pipeline:        5/5 passed
Total:              54/54 green ✅
```

---

## 📝 Activity & Modification Log

> Auto-updated by `sync_dev1.sh` on every push.

| Timestamp (IST) | Commit Message | Files Changed |
|-----------------|----------------|---------------|
<!-- ACTIVITY_LOG_START -->
| 2026-04-15 15:39 IST | add Dev 1 README and auto-sync script | ✏️`.cursorrules` ✏️`.gitignore` ✏️`README.md` ✏️`alembic.ini` ✏️`env.py` ✏️`001_create_users.py` ✏️`002_create_all_tables.py` ✏️`003_performance_indexes.py` ✏️`004_scheduled_templates_apikeys.py` ✏️`005_add_risk_breakdown.py` +114 more |
<!-- ACTIVITY_LOG_END -->

---

*Last updated by Hrishikesh Patil — Backend Dev 1*
