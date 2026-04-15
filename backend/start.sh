#!/usr/bin/env bash
set -euo pipefail

# ── Dynamic Environment Detection ─────────────────────
# Ensure Docker is in PATH, especially on macOS
if [[ "$(uname)" == "Darwin" ]]; then
    DOCKER_BIN_PATCH="/Applications/Docker.app/Contents/Resources/bin"
    if [ -d "$DOCKER_BIN_PATCH" ] && [[ ":$PATH:" != *":$DOCKER_BIN_PATCH:"* ]]; then
        export PATH="$PATH:$DOCKER_BIN_PATCH"
    fi
    # Also add standard local bin
    if [[ ":$PATH:" != *":/usr/local/bin:"* ]]; then
        export PATH="$PATH:/usr/local/bin"
    fi
fi

# ── Aesthetic Config (Futuristic Palette) ────────────────
RED='\033[38;5;196m'
GREEN='\033[38;5;82m'
YELLOW='\033[38;5;226m'
BLUE='\033[38;5;39m'
MAGENTA='\033[38;5;171m'
CYAN='\033[38;5;51m'
PURPLE='\033[38;5;99m'
ORANGE='\033[38;5;208m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Banner ───────────────────────────────────────────
print_banner() {
    # Only clear if we are in an interactive terminal
    if [ -t 1 ] && [ "${TERM:-}" != "dumb" ]; then
        clear
    fi
    echo -e "${CYAN}${BOLD}"
    echo "    ⚡ SHIELDSENTINEL INTELLIGENCE CORE ⚡"
    echo -e "    ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "    ${PURPLE}Neural Link Established... OS: $(uname -s)${NC}\n"
}

# ── Helpers ──────────────────────────────────────────
status_msg() { echo -e "  ${BLUE}${BOLD}➤${NC} ${DIM}[$1]${NC}"; }
step_label() { echo -e "  ${CYAN}${BOLD}$1${NC}"; }
success_msg() { echo -e "  ${GREEN}${BOLD}✔${NC} $1"; }
warn_msg() { echo -e "  ${YELLOW}${BOLD}⚠${NC} $1"; }
error_msg() { echo -e "  ${RED}${BOLD}✘${NC} $1"; exit 1; }

# ── Dependency Validation ────────────────────────────
check_docker() {
    status_msg "Checking Docker status..."
    if ! command -v docker &> /dev/null; then
        echo -e "  ${RED}${BOLD}✘ DOCKER NOT INSTALLED${NC}"
        echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${ORANGE}Neural Link Failure: Docker command is missing from PATH.${NC}"
        echo -e "  ${CYAN}Instruction: Please install Docker Desktop and try again.${NC}\n"
        exit 1
    fi

    # Check daemon availability
    if ! docker info > /dev/null 2>&1; then
        echo -e "  ${RED}${BOLD}✘ DOCKER DAEMON UNREACHABLE${NC}"
        echo -e "  ${DIM}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        echo -e "  ${ORANGE}Neural Link Failure: Local client cannot connect to the daemon.${NC}"
        
        if [[ "$(uname)" == "Darwin" ]]; then
            echo -e "  ${YELLOW}Troubleshooting for macOS:${NC}"
            echo -e "  1. Open ${BOLD}Docker Desktop${NC} manually."
            echo -e "  2. Go to ${BOLD}Settings > Resources${NC} and ensure at least 8GB RAM is allocated."
            echo -e "  3. Check ${BOLD}Settings > Advanced${NC} - 'Allow the default Docker socket to be used'."
            echo -e "  4. Restart Docker Desktop if it is already running but unresponsive."
        fi
        echo -e "\n  ${CYAN}Instruction: Start the Docker engine and try again.${NC}\n"
        exit 1
    fi
}

# ── Signal Handling ──────────────────────────────────
handle_interrupt() {
    echo -e "\n\n  ${ORANGE}${BOLD}⚡ INTERRUPT DETECTED${NC}"
    step_label "INITIATING EMERGENCY DECOMMISSION..."
    
    # Simple animation
    echo -n "  "
    for i in {1..10}; do
        printf "${RED}⚡${NC}"
        sleep 0.1
    done
    echo ""

    docker compose --env-file $ENV_FILE down --remove-orphans > /dev/null 2>&1
    success_msg "ShieldSentinel Core Purged. All systems offline."
    echo -e "  ${DIM}Neural link severed safely.${NC}\n"
    exit 0
}

trap handle_interrupt SIGINT

# ── Lifecycle Management ──────────────────────────────
CMD="${1:-"up"}"
COMPOSE_DIR="$(dirname "$0")/compose"
ENV_FILE="../.env"

cd "$COMPOSE_DIR"

# Check .env
if [ ! -f "$ENV_FILE" ]; then
    warn_msg ".env not found in backend/. Creating from template..."
    if [ -f "../.env.example" ]; then
        cp ../.env.example $ENV_FILE
    else
        error_msg "Could not find .env.example. Please create .env manually."
    fi
fi

case "$CMD" in
    "stop"|"down")
        print_banner
        check_docker
        step_label "DECOMMISSIONING SERVICES"
        docker compose --env-file $ENV_FILE down --remove-orphans
        success_msg "All neural nodes offline."
        exit 0
        ;;
    "restart")
        print_banner
        check_docker
        step_label "PHASE 1: PURGING ACTIVE NODES"
        docker compose --env-file $ENV_FILE down --remove-orphans
        step_label "PHASE 2: RE-INITIALIZING..."
        # Navigate back up and run the script again
        cd ..
        ./start.sh up
        exit 0
        ;;
    "logs")
        check_docker
        trap - SIGINT # Disable the shutdown trap for logs; just exit the log view
        docker compose --env-file $ENV_FILE logs -f
        exit 0
        ;;
    "up"|"start"|"")
        print_banner
        check_docker
        
        # 1. Purge existing (requested: stoping allservice when restated again)
        step_label "CLEANUP: Removing stray containers..."
        docker compose --env-file $ENV_FILE down --remove-orphans > /dev/null 2>&1
        
        # 2. Pull with retry logic
        step_label "SYNC: Refreshing neural nodes (Updating images)..."
        MAX_RETRIES=3
        RETRY_COUNT=0
        PULL_SUCCESS=false

        while [ $RETRY_COUNT -lt $MAX_RETRIES ]; do
            # Final attempt is verbose to help debugging
            if [ $RETRY_COUNT -eq $((MAX_RETRIES - 1)) ]; then
                if docker compose --env-file $ENV_FILE pull; then
                    PULL_SUCCESS=true
                    success_msg "Registry synchronized."
                    break
                fi
            else
                if docker compose --env-file $ENV_FILE pull -q; then
                    PULL_SUCCESS=true
                    success_msg "Registry synchronized."
                    break
                else
                    RETRY_COUNT=$((RETRY_COUNT + 1))
                    warn_msg "Registry sync attempt $RETRY_COUNT failed. Retrying in 5 seconds..."
                    sleep 5
                fi
            fi
        done

        if [ "$PULL_SUCCESS" = false ]; then
            warn_msg "Registry sync failed after $MAX_RETRIES attempts. Checking local cache..."
            # Try to start anyway, as images might already exist locally
        fi
        
        # 3. Launch
        step_label "BOOT: Initializing ShieldSentinel Node..."
        if ! docker compose --env-file $ENV_FILE up -d; then
            error_msg "Failed to boot ShieldSentinel. Check Docker logs and your internet connection."
        fi
        
        # 4. Progress Simulation (Enhanced)
        echo -n "  "
        for i in {1..20}; do
            COLOR=$(( 39 + i ))
            printf "\e[38;5;%dm▓\e[0m" "$COLOR"
            sleep 0.1
        done
        echo -e " ${GREEN}100%%${NC}"

        # 5. Health Monitoring
        step_label "DIAGNOSTICS: Verifying System Integrity..."
        sleep 2 # Give it a moment
        
        HEALTH_REPORT=$(docker compose --env-file $ENV_FILE ps --format "{{.Name}}: {{.Status}}")
        UNHEALTHY_COUNT=$(echo "$HEALTH_REPORT" | grep -Ei "unhealthy|exited|restarting" | grep -v "^$" || true | wc -l | tr -d ' ')
        
        # 6. Final Summary
        echo -e "\n  ${BOLD}INTERFACE ACCESS:${NC}"
        echo -e "  ${DIM}────────────────────────────────────────${NC}"
        echo -e "  🌐 ${BOLD}${CYAN}Frontend:${NC}     ${BOLD}http://localhost:9998${NC}"
        echo -e "  🚀 ${BOLD}API Engine:${NC}   http://localhost:9997/api/v1/docs"
        echo -e "  🌸 ${BOLD}Worker UI:${NC}    http://localhost:9999"
        echo -e "  🔌 ${BOLD}Gateway:${NC}      http://localhost:99"
        echo -e "  ${DIM}────────────────────────────────────────${NC}"

        if [ "$UNHEALTHY_COUNT" -gt 0 ]; then
            echo -e "\n  ${RED}${BOLD}STATUS: STARTED WITH ERRORS ($UNHEALTHY_COUNT unhealthy nodes)${NC}"
            echo -e "  ${DIM}$HEALTH_REPORT${NC}"
        else
            echo -e "\n  ${GREEN}${BOLD}STATUS: FULLY OPERATIONAL (All nodes healthy)${NC}"
            echo -e "\n  ${GREEN}${BOLD}✨ ALL WORKING AND STARTED SUCCESSFULLY ✨${NC}"
            echo -e "  ${DIM}ShieldSentinel Intelligence Layer is now fully ON-LINE and operational.${NC}\n"
        fi
        ;;
    *)
        error_msg "Unknown directive: $CMD. Usage: ./start.sh [up/stop/restart/logs]"
        ;;
esac
