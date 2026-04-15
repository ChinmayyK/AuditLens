#!/usr/bin/env bash
set -euo pipefail

# ── Aesthetic Config (Futuristic Palette) ────────────────
RED='\033[38;5;196m'
GREEN='\033[38;5;82m'
BLUE='\033[38;5;39m'
PURPLE='\033[38;5;99m'
CYAN='\033[38;5;51m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Banner ───────────────────────────────────────────
echo -e "${RED}${BOLD}"
echo "    ⚡ SHIELDSENTINEL DECOMMISSION CORE ⚡"
echo -e "    ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "    ${PURPLE}Initiating Shutdown Sequence...${NC}\n"

# ── Helpers ──────────────────────────────────────────
step_label() { echo -e "  ${CYAN}${BOLD}$1${NC}"; }
success_msg() { echo -e "  ${GREEN}${BOLD}✔${NC} $1"; }
error_msg() { echo -e "  ${RED}${BOLD}✘${NC} $1"; exit 1; }

# ── Dependency Validation ────────────────────────────
check_docker() {
    if ! command -v docker &> /dev/null; then
        error_msg "Docker command not found."
    fi
    if ! docker info > /dev/null 2>&1; then
        echo -e "  ${RED}${BOLD}✘ DOCKER DAEMON UNREACHABLE${NC}"
        if [[ "$(uname)" == "Darwin" ]]; then
            echo -e "  ${YELLOW}Tip: Restart Docker Desktop and ensure it's fully started.${NC}"
        fi
        exit 1
    fi
}
check_docker

# ── Lifecycle Management ──────────────────────────────
COMPOSE_DIR="$(dirname "$0")/compose"
ENV_FILE="../.env"

if [ ! -d "$COMPOSE_DIR" ]; then
    error_msg "Compose directory not found at $COMPOSE_DIR"
fi

cd "$COMPOSE_DIR"

step_label "DECOMMISSIONING SERVICES"
if docker compose --env-file "$ENV_FILE" down --remove-orphans; then
    success_msg "All neural nodes offline."
    echo -e "\n  ${GREEN}${BOLD}✨ SYSTEM SECURED AND STOPPED SUCCESSFULLY ✨${NC}"
    echo -e "  ${DIM}ShieldSentinel Intelligence Layer is now OFF-LINE.${NC}\n"
else
    error_msg "Failed to decommission services."
fi
