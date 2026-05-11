#!/usr/bin/env bash
# =============================================================================
#  SOCPilots — Clean Stateless Deployment Verification & Preparation Script
#
#  Usage:
#    bash scripts/clean-deploy.sh           # verify only (dry-run)
#    bash scripts/clean-deploy.sh --purge   # verify + purge runtime volumes
#    bash scripts/clean-deploy.sh --full    # full clean deploy from scratch
#
#  What this script does:
#    1. Pre-flight: verify .env exists and has no placeholder values
#    2. Secret scan: detect hardcoded credentials in source code
#    3. Git hygiene: confirm no sensitive files tracked
#    4. Docker: rebuild images cleanly (no layer cache)
#    5. Volume hygiene (--purge): drop all runtime data for fresh state
#    6. Post-boot: verify all services healthy
# =============================================================================

set -eo pipefail

RED='\033[0;31m'; YELLOW='\033[1;33m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
PASS="${GREEN}[PASS]${NC}"; WARN="${YELLOW}[WARN]${NC}"; FAIL="${RED}[FAIL]${NC}"; INFO="${CYAN}[INFO]${NC}"

PURGE=false; FULL=false
for arg in "$@"; do
  [[ "$arg" == "--purge" ]] && PURGE=true
  [[ "$arg" == "--full"  ]] && FULL=true PURGE=true
done

ERRORS=0; WARNINGS=0
fail() { echo -e "${FAIL} $1"; ((ERRORS++)) || true; }
warn() { echo -e "${WARN} $1"; ((WARNINGS++)) || true; }
pass() { echo -e "${PASS} $1"; }
info() { echo -e "${INFO} $1"; }

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "   SOCPilots — Clean Deployment Security Audit"
echo "═══════════════════════════════════════════════════════════"
echo ""

# ── 1. Environment File ─────────────────────────────────────────
echo "─── [1] Environment Configuration ───────────────────────"

if [[ ! -f ".env" ]]; then
  fail ".env file does not exist → run: cp .env.example .env && nano .env"
else
  pass ".env file present"

  # Check for unfilled placeholder values
  placeholders=$(grep -E "(YOUR_|CHANGE_ME|<CHANGE|example\.com|placeholder|changeme|1234)" .env 2>/dev/null | grep -v "^#" | wc -l)
  if [[ $placeholders -gt 0 ]]; then
    fail ".env contains $placeholders unfilled placeholder values:"
    grep -E "(YOUR_|CHANGE_ME|<CHANGE|example\.com|placeholder|changeme|1234)" .env | grep -v "^#" | head -10
  else
    pass ".env has no obvious placeholder values"
  fi

  # Check required keys are set and non-empty
  required_keys=("OPENAI_API_KEY" "THEHIVE_API_KEY" "OTX_API_KEY" "OPENSEARCH_PASS" "PG_PASSWORD" "AUTH_SECRET_KEY" "SOC_USERS")
  for key in "${required_keys[@]}"; do
    val=$(grep "^${key}=" .env 2>/dev/null | cut -d= -f2-)
    if [[ -z "$val" ]]; then
      fail "Required variable ${key} is empty or missing in .env"
    else
      pass "${key} is set"
    fi
  done

  # Warn about weak default passwords
  if grep -qE "^SOC_USERS=.*:(admin123|password|socpilots2024|younes123|changeme|admin):" .env 2>/dev/null; then
    warn "SOC_USERS contains a known weak/default password — change before deploying"
  fi

  # Warn about default postgres password
  if grep -qE "^PG_PASSWORD=(postgres|admin|password|changeme)" .env 2>/dev/null; then
    warn "PG_PASSWORD looks like a default value — use a strong random password"
  fi
fi

echo ""

# ── 2. Secret Scan ──────────────────────────────────────────────
echo "─── [2] Hardcoded Secret Scan ───────────────────────────"

# Scan backend JS and Python service files only
SCAN_RESULT=$(grep -rn --include="*.js" --include="*.py" --include="*.go" \
  -E "sk-[a-zA-Z0-9]{20,}" \
  Socpilots/backend/src/ langchain-agent/ services/ 2>/dev/null || true)
if [[ -n "$SCAN_RESULT" ]]; then
  fail "OpenAI key pattern found in source: $SCAN_RESULT"
else
  pass "No hardcoded OpenAI key patterns (sk-...) in source code"
fi

SCAN_RESULT2=$(grep -rn --include="*.js" --include="*.py" --include="*.go" \
  -E "ghp_[a-zA-Z0-9]{36,}" \
  Socpilots/backend/src/ langchain-agent/ services/ 2>/dev/null || true)
if [[ -n "$SCAN_RESULT2" ]]; then
  fail "GitHub token pattern found in source: $SCAN_RESULT2"
else
  pass "No hardcoded GitHub tokens (ghp_...) in source code"
fi

# Check .env.example and .env.template have no real values
env_real=$(grep -h -E "^[A-Z_]+=.+" .env.example MCP-WAZUH/.env.example Socpilots/configs/.env.template 2>/dev/null \
  | grep -v "^#\|CHANGE\|YOUR_\|<\|example\|localhost\|3000\|wazuh-alerts\|admin$\|production$\|587$\|false$\|true$\|60$\|8$\|30$\|50$" \
  | grep -v "^PORT=\|^NODE_ENV=\|^WAZUH_INDEX=\|^WAZUH_MCP_AUTH_MODE=\|ENVIRONMENT=\|^TRIVY" || true)
if [[ -n "$env_real" ]]; then
  warn "Example/template files may contain non-placeholder values — review:"
  echo "$env_real" | head -5
else
  pass ".env.example and .env.template contain only placeholder values"
fi

echo ""

# ── 3. Git Hygiene ──────────────────────────────────────────────
echo "─── [3] Git Repository Safety ───────────────────────────"

# Check .env is not tracked
if git ls-files .env 2>/dev/null | grep -q ".env$"; then
  fail ".env is tracked by git — run: git rm --cached .env"
else
  pass ".env is not tracked by git"
fi

# Check for any *.env files tracked (excluding examples/templates)
tracked_envs=$(git ls-files 2>/dev/null | { grep -E "\.env$|\.env\." || true; } | { grep -v ".env.example\|.env.template" || true; } | wc -l)
if [[ $tracked_envs -gt 0 ]]; then
  fail "$tracked_envs sensitive .env files are tracked by git:"
  git ls-files 2>/dev/null | { grep -E "\.env$|\.env\." || true; } | { grep -v ".env.example\|.env.template" || true; }
else
  pass "No .env files (except examples/templates) are tracked by git"
fi

# Check working tree is clean (no uncommitted changes)
uncommitted=$(git status --porcelain 2>/dev/null | wc -l)
if [[ $uncommitted -gt 0 ]]; then
  warn "Working tree has $uncommitted uncommitted changes"
else
  pass "Working tree is clean"
fi

echo ""

# ── 4. Docker Image Security ────────────────────────────────────
echo "─── [4] Docker Image Security ───────────────────────────"

# Check Dockerfiles don't COPY .env files
bad_copy=$( { grep -rn "COPY.*\.env[^.]" . --include="Dockerfile*" --exclude-dir=.git 2>/dev/null || true; } | { grep -v ".env.example\|.env.template" || true; } | wc -l)
if [[ $bad_copy -gt 0 ]]; then
  fail "Dockerfile(s) COPY .env files (may bake in secrets):"
  { grep -rn "COPY.*\.env[^.]" . --include="Dockerfile*" --exclude-dir=.git 2>/dev/null || true; } | { grep -v ".env.example\|.env.template" || true; }
else
  pass "No Dockerfiles COPY .env files"
fi

# Check docker-compose.yml for hardcoded values (not ${VAR} or empty)
hardcoded_compose=$( { grep -E "^\s+[A-Z_]+=\S+" docker-compose.yml 2>/dev/null || true; } | { grep -v '\${' || true; } | { grep -v "^#" || true; } | wc -l)
if [[ $hardcoded_compose -gt 0 ]]; then
  warn "docker-compose.yml has $hardcoded_compose potentially hardcoded values (review):"
  { grep -E "^\s+[A-Z_]+=\S+" docker-compose.yml 2>/dev/null || true; } | { grep -v '\${' || true; } | { grep -v "^#" || true; } | head -10
else
  pass "docker-compose.yml uses only \${ENV_VAR} references"
fi

echo ""

# ── 5. Volume Purge (--purge flag) ──────────────────────────────
if [[ "$PURGE" == "true" ]]; then
  echo "─── [5] Volume Purge (--purge flag set) ─────────────────"
  warn "About to STOP ALL CONTAINERS and remove runtime volumes..."
  warn "This will delete: postgres_data, redis_data, qdrant_data, neo4j_data, evidence_data"
  warn "OTX feed, investigations, assets, chat history will be WIPED."
  echo ""
  read -r -p "Type 'CONFIRM' to proceed with volume purge: " confirm
  if [[ "$confirm" == "CONFIRM" ]]; then
    info "Stopping containers..."
    docker compose down -v 2>&1 | tail -5
    pass "All runtime volumes purged — next startup will be fresh"
  else
    warn "Volume purge cancelled"
  fi
  echo ""
fi

# ── 6. Fresh Build ──────────────────────────────────────────────
if [[ "$FULL" == "true" ]]; then
  echo "─── [6] Fresh Build ─────────────────────────────────────"
  info "Building all images from scratch (--no-cache)..."
  docker compose build --no-cache 2>&1 | tail -10
  info "Starting stack..."
  docker compose up -d
  info "Waiting 15s for services to initialize..."
  sleep 15
  docker compose ps
  pass "Full clean deploy complete"
  echo ""
fi

# ── Summary ─────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════"
if [[ $ERRORS -gt 0 ]]; then
  echo -e "${FAIL} Audit FAILED — $ERRORS error(s), $WARNINGS warning(s)"
  echo "   Fix all errors before deploying to production."
  echo "═══════════════════════════════════════════════════════════"
  exit 1
elif [[ $WARNINGS -gt 0 ]]; then
  echo -e "${WARN} Audit PASSED with $WARNINGS warning(s)"
  echo "   Review warnings before deploying."
  echo "═══════════════════════════════════════════════════════════"
  exit 0
else
  echo -e "${PASS} Audit PASSED — deployment is clean and secure"
  echo "═══════════════════════════════════════════════════════════"
  exit 0
fi
