#!/usr/bin/env bash
# deploy-workflows.sh — Deploy and activate SOCPilots n8n workflows
# Usage: ./automation/deploy-workflows.sh [--dry-run] [--validate-only]
# Requires: running n8n container, .env at project root
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKFLOWS_DIR="$PROJECT_ROOT/Socpilots-webapp/workflows"
DRY_RUN=false
VALIDATE_ONLY=false

for arg in "$@"; do
  case "$arg" in
    --dry-run)       DRY_RUN=true ;;
    --validate-only) VALIDATE_ONLY=true ;;
  esac
done

# ── Colours ─────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }
die()   { error "$*"; exit 1; }

# ── Load .env ───────────────────────────────────────────────────────
ENV_FILE="$PROJECT_ROOT/.env"
[[ -f "$ENV_FILE" ]] || die ".env not found at $ENV_FILE"
set -a; source "$ENV_FILE"; set +a

# ── Required env vars ────────────────────────────────────────────────
REQUIRED_VARS=(
  N8N_USER N8N_PASSWORD
  MCP_WAZUH_HOST MCP_WAZUH_PORT
  MCP_THEHIVE_HOST MCP_THEHIVE_PORT
  N8N_INTERNAL_HOST N8N_INTERNAL_PORT
  VIRUSTOTAL_API_KEY ABUSEIPDB_API_KEY
)

# ── Workflow definitions: id, file, webhook_path ─────────────────────
declare -A WF_FILES=(
  [jXI278MucaooQW1l]="SOCPilots_Main.json"
  [67z9w0HklVCA5Y5E]="SOCPilots_Investigation.json"
  [BbuBpP3hOjKJmmqI]="SOCPilots_Enrichment.json"
)
declare -A WF_PATHS=(
  [jXI278MucaooQW1l]="socpilots"
  [67z9w0HklVCA5Y5E]="socpilots-investigation"
  [BbuBpP3hOjKJmmqI]="enricment"
)

N8N_BASE="${N8N_BASE_URL:-http://localhost:5678}"
N8N_AUTH="$N8N_USER:$N8N_PASSWORD"
ERRORS=0

# ════════════════════════════════════════════════════════════════════
# 1. VALIDATION
# ════════════════════════════════════════════════════════════════════
echo ""
info "=== PHASE 1: VALIDATION ==="

# 1a. Required env vars
missing=()
for var in "${REQUIRED_VARS[@]}"; do
  [[ -z "${!var:-}" ]] && missing+=("$var")
done
if [[ ${#missing[@]} -gt 0 ]]; then
  error "Missing required env vars: ${missing[*]}"
  die "Set these in .env before deploying."
fi
ok "All required env vars present"

# 1b. Workflow JSON files exist and are valid JSON
for wf_id in "${!WF_FILES[@]}"; do
  file="$WORKFLOWS_DIR/${WF_FILES[$wf_id]}"
  [[ -f "$file" ]] || { error "Missing workflow file: $file"; ((ERRORS++)); continue; }
  python3 -c "import json,sys; json.load(open('$file'))" 2>/dev/null \
    || { error "Invalid JSON: $file"; ((ERRORS++)); continue; }
  ok "$(basename "$file") — valid JSON"
done

# 1c. Check workflow JSONs have proper UUID node IDs
for wf_id in "${!WF_FILES[@]}"; do
  file="$WORKFLOWS_DIR/${WF_FILES[$wf_id]}"
  [[ -f "$file" ]] || continue
  bad_ids=$(python3 - <<'EOF'
import json, re, sys
data = json.load(open(sys.argv[1]))
uuid_re = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.I)
bad = [n['id'] for n in data.get('nodes', []) if not uuid_re.match(n.get('id', ''))]
print('\n'.join(bad))
EOF
    "$file")
  if [[ -n "$bad_ids" ]]; then
    error "Non-UUID node IDs in ${WF_FILES[$wf_id]}: $bad_ids"
    ((ERRORS++))
  else
    ok "$(basename "$file") — all node IDs are valid UUIDs"
  fi
done

# 1d. Check env var expressions present (not hardcoded URLs)
for wf_id in "${!WF_FILES[@]}"; do
  file="$WORKFLOWS_DIR/${WF_FILES[$wf_id]}"
  [[ -f "$file" ]] || continue
  for pattern in "mcp-wazuh:[0-9]" "thehive-mcp:[0-9]" "n8n:[0-9].*mcp" \
                 "x-apikey.*802f4ac4" "x-apikey.*0880243c"; do
    if grep -qE "$pattern" "$file" 2>/dev/null; then
      warn "Possible hardcoded value matching '$pattern' in ${WF_FILES[$wf_id]}"
      ((ERRORS++))
    fi
  done
done

# 1e. Check $env expressions reference allowlisted vars
ALLOWLIST="MCP_WAZUH_HOST MCP_WAZUH_PORT MCP_THEHIVE_HOST MCP_THEHIVE_PORT N8N_INTERNAL_HOST N8N_INTERNAL_PORT VIRUSTOTAL_API_KEY ABUSEIPDB_API_KEY"
for wf_id in "${!WF_FILES[@]}"; do
  file="$WORKFLOWS_DIR/${WF_FILES[$wf_id]}"
  [[ -f "$file" ]] || continue
  used_vars=$(grep -oE '\$env\.[A-Z_]+' "$file" | sed 's/\$env\.//' | sort -u || true)
  for var in $used_vars; do
    if ! echo "$ALLOWLIST" | grep -qw "$var"; then
      warn "$var used in ${WF_FILES[$wf_id]} but not in N8N_SECURITY_ALLOWED_EXTERNAL_ENV_VARS"
    fi
  done
done

# 1f. Check n8n container is running (skip if validate-only)
if [[ "$VALIDATE_ONLY" == "false" ]]; then
  if ! docker ps --filter "name=socpilots-n8n" --filter "status=running" --format "{{.Names}}" \
       | grep -q "socpilots-n8n"; then
    die "n8n container 'socpilots-n8n' is not running. Start the stack first."
  fi
  ok "n8n container is running"

  # 1g. Check n8n API is reachable
  if ! curl -sf -u "$N8N_AUTH" "$N8N_BASE/api/v1/workflows?limit=1" -o /dev/null; then
    die "n8n API not reachable at $N8N_BASE — check credentials and port"
  fi
  ok "n8n API reachable"
fi

if [[ "$ERRORS" -gt 0 ]]; then
  die "Validation failed with $ERRORS error(s). Fix above issues before deploying."
fi
ok "All validation checks passed"

[[ "$VALIDATE_ONLY" == "true" ]] && { info "Validate-only mode — exiting."; exit 0; }
[[ "$DRY_RUN" == "true" ]]       && { info "Dry-run mode — skipping deploy."; exit 0; }

# ════════════════════════════════════════════════════════════════════
# 2. DEPLOY
# ════════════════════════════════════════════════════════════════════
echo ""
info "=== PHASE 2: DEPLOY ==="

n8n_api() {
  local method="$1" path="$2"; shift 2
  curl -sf -u "$N8N_AUTH" -X "$method" \
    -H "Content-Type: application/json" \
    "$N8N_BASE/api/v1$path" "$@"
}

for wf_id in "${!WF_FILES[@]}"; do
  file="$WORKFLOWS_DIR/${WF_FILES[$wf_id]}"
  wf_name=$(python3 -c "import json; print(json.load(open('$file'))['name'])")
  info "Deploying: $wf_name ($wf_id)"

  # Check if workflow already exists
  existing=$(n8n_api GET "/workflows/$wf_id" 2>/dev/null || echo "")

  if [[ -n "$existing" ]] && echo "$existing" | python3 -c "import json,sys; d=json.load(sys.stdin); exit(0 if 'id' in d else 1)" 2>/dev/null; then
    # Update existing
    result=$(n8n_api PUT "/workflows/$wf_id" --data-binary "@$file")
    ok "Updated: $wf_name"
  else
    # Create new (preserve ID via POST with id field)
    result=$(n8n_api POST "/workflows" --data-binary "@$file")
    created_id=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('id',''))" 2>/dev/null || echo "")
    if [[ "$created_id" != "$wf_id" ]]; then
      warn "Created with ID $created_id instead of $wf_id — updating DB ID"
      # Rename via SQLite if IDs differ (edge case)
      DB="/var/lib/docker/volumes/socpilots_n8n_data/_data/database.sqlite"
      if [[ -f "$DB" ]]; then
        docker stop socpilots-n8n >/dev/null
        sqlite3 "$DB" "UPDATE workflow_entity SET id='$wf_id' WHERE id='$created_id';" \
                      "UPDATE shared_workflow SET workflowId='$wf_id' WHERE workflowId='$created_id';" \
                      "PRAGMA wal_checkpoint(TRUNCATE);"
        docker start socpilots-n8n >/dev/null
        sleep 5
      fi
    fi
    ok "Created: $wf_name"
  fi
done

# ════════════════════════════════════════════════════════════════════
# 3. ACTIVATE
# ════════════════════════════════════════════════════════════════════
echo ""
info "=== PHASE 3: ACTIVATE ==="

for wf_id in "${!WF_FILES[@]}"; do
  wf_name="${WF_FILES[$wf_id]%.json}"
  info "Activating: $wf_name"
  result=$(n8n_api POST "/workflows/$wf_id/activate" 2>/dev/null || echo '{"error":"failed"}')
  if echo "$result" | grep -q '"active":true'; then
    ok "Active: $wf_name"
  else
    # Fallback: set activeVersionId directly in SQLite
    warn "API activation failed for $wf_id — falling back to SQLite"
    DB="/var/lib/docker/volumes/socpilots_n8n_data/_data/database.sqlite"
    if [[ -f "$DB" ]]; then
      docker stop socpilots-n8n >/dev/null
      sqlite3 "$DB" \
        "UPDATE workflow_entity SET active=1, activeVersionId=versionId WHERE id='$wf_id';" \
        "PRAGMA wal_checkpoint(TRUNCATE);"
      docker start socpilots-n8n >/dev/null
      sleep 5
      ok "Activated via SQLite: $wf_name"
    else
      error "Cannot activate $wf_name — SQLite DB not found"
      ((ERRORS++))
    fi
  fi
done

# ════════════════════════════════════════════════════════════════════
# 4. VERIFY
# ════════════════════════════════════════════════════════════════════
echo ""
info "=== PHASE 4: VERIFY ==="
sleep 3

for wf_id in "${!WF_FILES[@]}"; do
  wf_name="${WF_FILES[$wf_id]%.json}"
  state=$(n8n_api GET "/workflows/$wf_id" 2>/dev/null \
    | python3 -c "import json,sys; d=json.load(sys.stdin); print('active' if d.get('active') else 'INACTIVE')" 2>/dev/null || echo "UNREACHABLE")
  if [[ "$state" == "active" ]]; then
    ok "$wf_name — active"
  else
    error "$wf_name — $state"
    ((ERRORS++))
  fi
done

# Verify webhook paths
for wf_id in "${!WF_PATHS[@]}"; do
  path="${WF_PATHS[$wf_id]}"
  wf_name="${WF_FILES[$wf_id]%.json}"
  # Only test POST webhooks (not MCP trigger)
  [[ "$path" == "enricment" ]] && continue
  http_code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "http://localhost:5678/webhook/$path" \
    -H "Content-Type: application/json" \
    -d '{"message":"ping"}' \
    --max-time 10 2>/dev/null || echo "000")
  # 200 = response, 500 = agent error (still registered), 404 = not registered
  if [[ "$http_code" == "404" ]]; then
    error "Webhook not registered: /webhook/$path ($wf_name)"
    ((ERRORS++))
  else
    ok "Webhook registered: /webhook/$path → HTTP $http_code"
  fi
done

echo ""
if [[ "$ERRORS" -eq 0 ]]; then
  ok "=== DEPLOY COMPLETE — all workflows active and webhooks registered ==="
else
  error "=== DEPLOY FINISHED WITH $ERRORS ERROR(S) — review output above ==="
  exit 1
fi
