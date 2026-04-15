#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────
#  sync_dev1.sh — Auto-commit & push with activity logging
#  Author: Hrishikesh Patil (Backend Dev 1)
#
#  Usage:
#    chmod +x sync_dev1.sh
#    ./sync_dev1.sh "fixed diff parser bug"
#    ./sync_dev1.sh "added webhook HMAC validation"
#
#  What it does:
#    1. Grabs timestamp + modified files list
#    2. Injects a new row into hrishikesh_readme.md
#    3. Stages all changes (including updated README)
#    4. Commits with "[Dev 1 Auto-Sync] <message>"
#    5. Pushes to origin/main
# ─────────────────────────────────────────────────────────

set -euo pipefail

# ── Colors ─────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ── Config ─────────────────────────────────────────────
README_FILE="hrishikesh_readme.md"
BRANCH="main"
MARKER_START="<!-- ACTIVITY_LOG_START -->"
MAX_FILES_IN_LOG=10  # Show at most N files in the log row

# ── Helpers ────────────────────────────────────────────
info()    { echo -e "${BLUE}ℹ ${NC}$1"; }
success() { echo -e "${GREEN}✅${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠️ ${NC}$1"; }
error()   { echo -e "${RED}❌${NC} $1"; exit 1; }
step()    { echo -e "\n${CYAN}${BOLD}[$1/5]${NC} ${BOLD}$2${NC}"; }

# ── Banner ─────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ${CYAN}🛡️  AuditLens — Dev 1 Auto-Sync${NC}             ${BOLD}║${NC}"
echo -e "${BOLD}║  ${NC}Hrishikesh Patil · Backend Dev 1${BOLD}            ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""

# ── Validate input ─────────────────────────────────────
if [ $# -eq 0 ]; then
    error "Missing commit message!\n   Usage: ./sync_dev1.sh \"your commit message\""
fi

COMMIT_MSG="$*"
info "Commit message: ${BOLD}${COMMIT_MSG}${NC}"

# ── Validate we're in a git repo ───────────────────────
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    error "Not inside a git repository!"
fi

# ── Ensure git identity is set ─────────────────────────
if [ -z "$(git config user.name 2>/dev/null)" ]; then
    warn "Git user.name not set, configuring..."
    git config user.name "Hrishikesh Patil"
fi
if [ -z "$(git config user.email 2>/dev/null)" ]; then
    warn "Git user.email not set, configuring..."
    git config user.email "hrishikeshnerkar956@gmail.com"
fi

# ── Check README exists ────────────────────────────────
if [ ! -f "$README_FILE" ]; then
    error "${README_FILE} not found! Run this from the repo root."
fi

# ══════════════════════════════════════════════════════
#  STEP 1: Gather data
# ══════════════════════════════════════════════════════
step 1 "Gathering modification data..."

# Timestamp in IST
TIMESTAMP=$(TZ='Asia/Kolkata' date '+%Y-%m-%d %H:%M IST')
info "Timestamp: ${TIMESTAMP}"

# Get modified/added/deleted files (short format)
CHANGED_FILES=$(git status --short 2>/dev/null || echo "")
if [ -z "$CHANGED_FILES" ]; then
    warn "No changes detected by git status"
    FILE_COUNT=0
    CHANGED_FILES_DISPLAY="(no staged changes)"
else
    FILE_COUNT=$(echo "$CHANGED_FILES" | wc -l | tr -d ' ')
    # Format: compact display with max N files
    CHANGED_FILES_DISPLAY=$(echo "$CHANGED_FILES" \
        | head -n "$MAX_FILES_IN_LOG" \
        | awk '{
            status = substr($0, 1, 2);
            gsub(/^ +| +$/, "", status);
            file = $2;
            n = split(file, parts, "/");
            basename = parts[n];
            if (status ~ /M/)        prefix = "✏️";
            else if (status ~ /A/)   prefix = "🆕";
            else if (status ~ /D/)   prefix = "🗑️";
            else if (status ~ /\?/)  prefix = "🆕";
            else                     prefix = "📄";
            printf "%s`%s` ", prefix, basename;
        }')
    # Append overflow indicator
    if [ "$FILE_COUNT" -gt "$MAX_FILES_IN_LOG" ]; then
        OVERFLOW=$((FILE_COUNT - MAX_FILES_IN_LOG))
        CHANGED_FILES_DISPLAY="${CHANGED_FILES_DISPLAY}+${OVERFLOW} more"
    fi
fi

info "Files changed: ${FILE_COUNT}"

# ══════════════════════════════════════════════════════
#  STEP 2: Inject log entry into README
# ══════════════════════════════════════════════════════
step 2 "Updating ${README_FILE}..."

# Escape pipe characters for markdown table
SAFE_MSG=$(echo "$COMMIT_MSG" | sed 's/|/∣/g')
SAFE_FILES=$(echo "$CHANGED_FILES_DISPLAY" | sed 's/|/∣/g')

NEW_ROW="| ${TIMESTAMP} | ${SAFE_MSG} | ${SAFE_FILES} |"

# Check if markers exist
if ! grep -q "$MARKER_START" "$README_FILE"; then
    error "Marker '${MARKER_START}' not found in ${README_FILE}!"
fi

# Inject the new row right after ACTIVITY_LOG_START marker
TEMP_FILE=$(mktemp)
awk -v marker="$MARKER_START" -v newrow="$NEW_ROW" '
    {
        print $0
        if (index($0, marker) > 0) {
            print newrow
        }
    }
' "$README_FILE" > "$TEMP_FILE"

mv "$TEMP_FILE" "$README_FILE"

success "Activity log updated"
echo -e "   ${CYAN}${NEW_ROW}${NC}"

# ══════════════════════════════════════════════════════
#  STEP 3: Stage all changes
# ══════════════════════════════════════════════════════
step 3 "Staging all changes..."

git add .
STAGED_COUNT=$(git diff --cached --name-only | wc -l | tr -d ' ')
success "Staged ${STAGED_COUNT} file(s)"

# ══════════════════════════════════════════════════════
#  STEP 4: Commit
# ══════════════════════════════════════════════════════
step 4 "Committing..."

FULL_MSG="[Dev 1 Auto-Sync] ${COMMIT_MSG}"
git commit -m "$FULL_MSG"
success "Committed: ${BOLD}${FULL_MSG}${NC}"

# ══════════════════════════════════════════════════════
#  STEP 5: Push
# ══════════════════════════════════════════════════════
step 5 "Pushing to origin/${BRANCH}..."

if git push origin "$BRANCH"; then
    success "Pushed to origin/${BRANCH}"
else
    error "Push failed! Check your network or auth."
fi

# ── Summary ────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║  ${GREEN}✅ Sync Complete!${NC}                           ${BOLD}║${NC}"
echo -e "${BOLD}╠══════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}║${NC}  📝 ${COMMIT_MSG}"
echo -e "${BOLD}║${NC}  🕐 ${TIMESTAMP}"
echo -e "${BOLD}║${NC}  📦 ${STAGED_COUNT} file(s) pushed"
echo -e "${BOLD}║${NC}  🌿 Branch: ${BRANCH}"
echo -e "${BOLD}╚══════════════════════════════════════════════╝${NC}"
echo ""
