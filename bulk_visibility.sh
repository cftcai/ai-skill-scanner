#!/usr/bin/env bash
# bulk_visibility.sh
# Advanced script to change GitHub repository visibility from private to public in bulk.
# Features: dependency checks, auth verification, dry-run, per-repo error handling,
# logging, confirmation prompt, visibility pre-check, and colored output.
#
# Requirements:
#   - GitHub CLI (gh) v2.0+
#   - Authenticated with: gh auth login --scopes repo
#
# Usage:
#   ./bulk_visibility.sh --dry-run
#   ./bulk_visibility.sh --yes
#   ./bulk_visibility.sh --owner cftcai --repos "ai-skill-scanner,ai-skill-signatures"

set -euo pipefail

# Configuration
OWNER="${OWNER:-cftcai}"
REPO_LIST="${REPOS:-ai-skill-scanner,ai-skill-signatures}"
LOG_FILE="visibility_change_$(date +%Y%m%d_%H%M%S).log"
DRY_RUN=false
AUTO_CONFIRM=false

# Colors for output (portable)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log() {
    echo -e "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log "${RED}ERROR: $1${NC}"
    exit 1
}

usage() {
    cat << EOF
Usage: $0 [options]

Options:
  --owner OWNER          GitHub owner (default: cftcai)
  --repos "r1,r2,r3"     Comma separated list of repositories
  --dry-run              Show what would be done without changes
  --yes                  Skip confirmation prompt
  -h, --help             Show this help

Examples:
  $0 --dry-run
  $0 --yes --repos "ai-skill-scanner,ai-skill-signatures"
EOF
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --owner) OWNER="$2"; shift 2 ;;
        --repos) REPO_LIST="$2"; shift 2 ;;
        --dry-run) DRY_RUN=true; shift ;;
        --yes) AUTO_CONFIRM=true; shift ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Convert comma list to array
IFS=',' read -ra REPOS <<< "$REPO_LIST"

echo "=== GitHub Bulk Visibility Changer ==="
echo "Owner: $OWNER"
echo "Repositories: ${REPOS[*]}"
echo "Dry run: $DRY_RUN"
echo "Log file: $LOG_FILE"
echo

# Pre-flight checks
command -v gh >/dev/null 2>&1 || error_exit "GitHub CLI (gh) is not installed. Install from https://cli.github.com"

if ! gh auth status >/dev/null 2>&1; then
    error_exit "Not authenticated with gh. Run: gh auth login --scopes repo"
fi

# Verify token has repo scope (basic check via API call)
if ! gh api user --jq '.login' >/dev/null 2>&1; then
    error_exit "GitHub token lacks required permissions. Re-authenticate with repo scope."
fi

log "Pre-flight checks passed. Starting processing for ${#REPOS[@]} repositories."

# Confirmation unless auto or dry-run
if ! $AUTO_CONFIRM && ! $DRY_RUN; then
    read -p "Proceed with visibility changes for ${#REPOS[@]} repos? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        log "Operation cancelled by user."
        exit 0
    fi
fi

SUCCESS_COUNT=0
FAIL_COUNT=0

for repo in "${REPOS[@]}"; do
    repo="${repo// /}"  # trim whitespace
    full_name="${OWNER}/${repo}"
    
    log "Processing ${full_name}..."
    
    # Check if repo exists and get current visibility
    if ! current_vis=$(gh repo view "$full_name" --json visibility -q '.visibility' 2>/dev/null); then
        log "${YELLOW}WARNING: Repository ${full_name} not found or no access. Skipping.${NC}"
        ((FAIL_COUNT++))
        continue
    fi
    
    if [[ "$current_vis" == "public" ]]; then
        log "${GREEN}Already public. Skipping.${NC}"
        ((SUCCESS_COUNT++))
        continue
    fi
    
    if $DRY_RUN; then
        log "${YELLOW}[DRY RUN] Would change ${full_name} from ${current_vis} to public${NC}"
        ((SUCCESS_COUNT++))
        continue
    fi
    
    # Perform the change with error handling
    if gh repo edit "$full_name" --visibility public 2>&1 | tee -a "$LOG_FILE"; then
        log "${GREEN}Successfully changed ${full_name} to public.${NC}"
        ((SUCCESS_COUNT++))
    else
        log "${RED}Failed to change visibility for ${full_name}.${NC}"
        ((FAIL_COUNT++))
    fi
done

log "=== Summary ==="
log "Successful: ${SUCCESS_COUNT}"
log "Failed: ${FAIL_COUNT}"
log "Total processed: ${#REPOS[@]}"
log "Log saved to: ${LOG_FILE}"

if [[ $FAIL_COUNT -gt 0 ]]; then
    exit 1
fi

exit 0
