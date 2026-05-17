#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
# deploy-workflows.sh — SOCPilots n8n deployment pipeline
#
# Usage:
#   ./automation/deploy-workflows.sh              # Full deploy
#   ./automation/deploy-workflows.sh --validate   # Check env + JSON only
#   ./automation/deploy-workflows.sh --creds-only # Credentials only
#   ./automation/deploy-workflows.sh --dry-run    # Show what would happen
#
# Requirements:
#   - .env at project root with all required variables
#   - Docker + docker compose installed
#   - python3 + cryptography package (pip install cryptography)
# ═══════════════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WF_DIR="$PROJECT_ROOT/Socpilots/workflows"
DB="/var/lib/docker/volumes/socpilots-dev_n8n_data/_data/database.sqlite"
N8N_CONTAINER="dev-n8n"
MODE="full"

for arg in "$@"; do
  case "$arg" in
    --validate)   MODE="validate"   ;;
    --creds-only) MODE="creds"      ;;
    --dry-run)    MODE="dry"        ;;
  esac
done

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'; CYN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GRN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YLW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*" >&2; }
die()   { fail "$*"; exit 1; }

ERRORS=0

# ════════════════════════════════════════════════════════════════════
# 1. LOAD ENVIRONMENT
# ════════════════════════════════════════════════════════════════════
ENV_FILE="$PROJECT_ROOT/.env"
[[ -f "$ENV_FILE" ]] || die "Missing .env at $PROJECT_ROOT — copy .env.example and fill in values"
set -a; source "$ENV_FILE"; set +a
info "Loaded $ENV_FILE"

# ════════════════════════════════════════════════════════════════════
# 2. VALIDATE
# ════════════════════════════════════════════════════════════════════
echo ""
info "══ PHASE 1: VALIDATE ══════════════════════════════════════════"

# Required env vars
REQUIRED=(
  N8N_USER N8N_PASSWORD
  OPENAI_API_KEY MCP_API_KEY
  VIRUSTOTAL_API_KEY ABUSEIPDB_API_KEY
  THEHIVE_URL THEHIVE_API_KEY
  WAZUH_HOST WAZUH_USER WAZUH_PASS
)
missing=()
for var in "${REQUIRED[@]}"; do
  [[ -z "${!var:-}" ]] && missing+=("$var")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  for m in "${missing[@]}"; do fail "Missing: $m"; done
  die "Set missing variables in .env before deploying"
fi
ok "All required env vars present"

# Workflow JSON files — valid JSON + proper UUIDs
UUID_RE='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
for f in "$WF_DIR"/*.json; do
  [[ -f "$f" ]] || continue
  name=$(basename "$f")

  # Valid JSON
  python3 -c "import json,sys; json.load(open('$f'))" 2>/dev/null \
    || { fail "Invalid JSON: $name"; ((ERRORS++)); continue; }

  # All node IDs are UUIDs
  bad=$(python3 -c "
import json,re,sys
data=json.load(open('$f'))
uuid_re=re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',re.I)
bad=[n['id'] for n in data.get('nodes',[]) if not uuid_re.match(n.get('id',''))]
print(' '.join(bad))
  " 2>/dev/null)
  [[ -n "$bad" ]] && { fail "Non-UUID node IDs in $name: $bad"; ((ERRORS++)); continue; }

  ok "$name — valid"
done

# No hardcoded secrets in JSONs
for f in "$WF_DIR"/*.json; do
  [[ -f "$f" ]] || continue
  name=$(basename "$f")
  # Check for raw API key patterns (40+ char hex strings) outside of env expressions
  if python3 -c "
import json,re
data=open('$f').read()
# Find header values that look like raw API keys (not env expressions)
raw_keys = re.findall(r'\"value\":\s*\"([0-9a-f]{32,})\"', data)
if raw_keys:
    print('FOUND')
    sys.exit(0)
import sys; sys.exit(1)
  " 2>/dev/null; then
    warn "Possible hardcoded secret in $name — verify before deploying to prod"
  fi
done

[[ "$ERRORS" -gt 0 ]] && die "Validation failed with $ERRORS error(s)"
ok "All validation checks passed"

[[ "$MODE" == "validate" ]] && { info "Validate-only mode — done"; exit 0; }
[[ "$MODE" == "dry" ]]      && { info "Dry-run mode — would deploy 3 workflows + 2 credentials"; exit 0; }

# ════════════════════════════════════════════════════════════════════
# 3. ENSURE STACK IS RUNNING
# ════════════════════════════════════════════════════════════════════
echo ""
info "══ PHASE 2: STACK STATUS ══════════════════════════════════════"
cd "$PROJECT_ROOT"

running=$(docker ps --filter "name=$N8N_CONTAINER" --filter "status=running" --format "{{.Names}}" 2>/dev/null)
if [[ -z "$running" ]]; then
  info "Starting full stack..."
  docker compose up -d --build
  info "Waiting 30s for services to be ready..."
  sleep 30
fi
ok "Stack is running"

# ════════════════════════════════════════════════════════════════════
# 4. BOOTSTRAP (credentials + workflows via SQLite)
# ════════════════════════════════════════════════════════════════════
echo ""
info "══ PHASE 3: BOOTSTRAP ═════════════════════════════════════════"

# Stop n8n for safe SQLite writes
info "Stopping n8n for DB update..."
docker stop "$N8N_CONTAINER" >/dev/null

# Run the Python bootstrap
if [[ "$MODE" == "creds" ]]; then
  BOOTSTRAP_MODE="credentials"
else
  BOOTSTRAP_MODE="bootstrap"
fi

python3 "$SCRIPT_DIR/n8n_bootstrap.py" "$BOOTSTRAP_MODE" --container "$N8N_CONTAINER" \
  || { docker start "$N8N_CONTAINER" >/dev/null; die "Bootstrap failed"; }

# Fix permissions after SQLite writes
chown 1000:1000 "$DB"
chmod 600 "$DB"

# Restart n8n
info "Starting n8n..."
docker start "$N8N_CONTAINER" >/dev/null

# ════════════════════════════════════════════════════════════════════
# 5. WAIT FOR ACTIVATION
# ════════════════════════════════════════════════════════════════════
echo ""
info "══ PHASE 4: ACTIVATE ══════════════════════════════════════════"
info "Waiting for n8n to activate workflows..."

activated=false
for i in $(seq 1 24); do
  sleep 5
  logs=$(docker logs "$N8N_CONTAINER" 2>&1 | tail -40)

  main_ok=$(echo "$logs" | grep -c 'Activated workflow.*WEBAPP-PRD' || true)
  inv_ok=$(echo "$logs"  | grep -c 'Activated workflow.*Investigation' || true)
  enr_ok=$(echo "$logs"  | grep -c 'Activated workflow.*Enrichment' || true)

  if [[ "$main_ok" -ge 1 && "$inv_ok" -ge 1 && "$enr_ok" -ge 1 ]]; then
    activated=true
    break
  fi

  info "  Waiting... (${i}/24, $((i*5))s elapsed)"
done

if [[ "$activated" != "true" ]]; then
  warn "Activation log not detected — checking DB state directly..."
  active_count=$(sqlite3 "$DB" "SELECT COUNT(*) FROM workflow_entity WHERE active=1;" 2>/dev/null || echo 0)
  [[ "$active_count" -lt 3 ]] && die "Only $active_count/3 workflows active in DB"
  warn "Workflows active in DB but log confirmation missing — continuing..."
fi

ok "Workflows activated"

# ════════════════════════════════════════════════════════════════════
# 6. VERIFY
# ════════════════════════════════════════════════════════════════════
echo ""
info "══ PHASE 5: VERIFY ════════════════════════════════════════════"
sleep 3

# DB state
echo ""
info "Workflow state in DB:"
sqlite3 "$DB" \
  "SELECT name, active, substr(versionId,1,8), substr(activeVersionId,1,8) FROM workflow_entity ORDER BY name;" \
  | while IFS='|' read -r name active vid avid; do
      if [[ "$active" == "1" && "$vid" == "$avid" ]]; then
        ok "  $name — active, versionId=$vid..."
      else
        fail "  $name — active=$active, versionId/activeVersionId mismatch"
        ((ERRORS++))
      fi
    done

# Webhook response
echo ""
info "Webhook endpoint checks:"
for path in socpilots socpilots-investigation; do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://localhost:5678/webhook/$path" \
    -H "Content-Type: application/json" \
    -d '{"message":"ping"}' --max-time 10 2>/dev/null || echo "000")
  if [[ "$code" == "200" ]]; then
    ok "  /webhook/$path → HTTP $code"
  else
    fail "  /webhook/$path → HTTP $code (expected 200)"
    ((ERRORS++))
  fi
done

# Enrichment MCP endpoint
code=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost:5678/webhook/enricment" --max-time 5 2>/dev/null || echo "000")
if [[ "$code" != "404" ]]; then
  ok "  /webhook/enricment → HTTP $code (MCP trigger registered)"
else
  fail "  /webhook/enricment → HTTP 404 (not registered)"
  ((ERRORS++))
fi

# Summary
echo ""
if [[ "$ERRORS" -eq 0 ]]; then
  echo -e "${GRN}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${GRN}  DEPLOY COMPLETE — all workflows active and verified  ✓${NC}"
  echo -e "${GRN}═══════════════════════════════════════════════════════════${NC}"
  echo ""
  echo "  Webapp:          http://${SERVER_IP:-localhost}"
  echo "  n8n editor:      http://${SERVER_IP:-localhost}:5678"
  echo "  Main webhook:    POST http://localhost:5678/webhook/socpilots"
  echo "  Investigation:   POST http://localhost:5678/webhook/socpilots-investigation"
else
  echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
  echo -e "${RED}  DEPLOY FINISHED WITH $ERRORS ERROR(S) — review output above${NC}"
  echo -e "${RED}═══════════════════════════════════════════════════════════${NC}"
  exit 1
fi
