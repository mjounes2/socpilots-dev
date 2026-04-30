#!/bin/bash
# ================================================================
# SOC PILOTS — Connection Test Script
# Run BEFORE deploying to verify all services are reachable
# Usage: ./test-connections.sh
# ================================================================

GREEN='\033[0;32m' RED='\033[0;31m' YELLOW='\033[1;33m' CYAN='\033[0;36m' NC='\033[0m'
ok() { echo -e "  ${GREEN}✅ $1${NC}"; }
fail() { echo -e "  ${RED}❌ $1${NC}"; }
warn() { echo -e "  ${YELLOW}⚠️  $1${NC}"; }
info() { echo -e "  ${CYAN}ℹ️  $1${NC}"; }

# Load .env
if [ -f ".env" ]; then
  export $(grep -v '^#' .env | grep -v '^$' | xargs)
  echo "Loaded .env file"
else
  echo "No .env found — using environment variables"
fi

echo ""
echo "╔══════════════════════════════════════════╗"
echo "║   SOC Pilots — Connection Tests          ║"
echo "╚══════════════════════════════════════════╝"
echo ""

PASS=0
FAIL=0

# ── Test 1: OpenSearch ─────────────────────────────────────────
echo -e "${CYAN}[1] Wazuh OpenSearch${NC}"
info "URL: ${OPENSEARCH_URL}"
info "User: ${OPENSEARCH_USER}"

HTTP_CODE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" \
  -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
  "${OPENSEARCH_URL}/_cluster/health" 2>/dev/null)

if [ "$HTTP_CODE" = "200" ]; then
  HEALTH=$(curl -sk --max-time 8 -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
    "${OPENSEARCH_URL}/_cluster/health" 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('status','?'))" 2>/dev/null)
  ok "OpenSearch reachable — cluster status: ${HEALTH}"
  ((PASS++))

  # Test wazuh-alerts index
  IDX_CODE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" \
    -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
    "${OPENSEARCH_URL}/${WAZUH_INDEX:-wazuh-alerts-*}/_count" 2>/dev/null)
  if [ "$IDX_CODE" = "200" ]; then
    COUNT=$(curl -sk --max-time 8 \
      -u "${OPENSEARCH_USER}:${OPENSEARCH_PASS}" \
      "${OPENSEARCH_URL}/${WAZUH_INDEX:-wazuh-alerts-*}/_count" 2>/dev/null | \
      python3 -c "import sys,json; print(json.load(sys.stdin).get('count',0))" 2>/dev/null)
    ok "wazuh-alerts-* index found — ${COUNT} documents"
    ((PASS++))
  else
    fail "wazuh-alerts-* index not found (HTTP ${IDX_CODE})"
    warn "Check: WAZUH_INDEX in .env"
    ((FAIL++))
  fi
else
  fail "OpenSearch unreachable (HTTP ${HTTP_CODE:-TIMEOUT})"
  warn "Fix: ufw allow 9200 on Wazuh server"
  warn "Fix: Check OPENSEARCH_URL, OPENSEARCH_USER, OPENSEARCH_PASS"
  ((FAIL++))
fi

echo ""

# ── Test 2: TheHive ────────────────────────────────────────────
echo -e "${CYAN}[2] TheHive${NC}"
info "URL: ${THEHIVE_URL}"

HTTP_CODE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
  "${THEHIVE_URL}/api/v1/status" 2>/dev/null)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "204" ]; then
  ok "TheHive reachable"
  ((PASS++))

  # Test case list
  CASE_CODE=$(curl -sk --max-time 8 -o /dev/null -w "%{http_code}" \
    -X POST \
    -H "Authorization: Bearer ${THEHIVE_API_KEY}" \
    -H "Content-Type: application/json" \
    -d '{"query":[{"_name":"listCase"},{"_name":"page","from":0,"to":1}]}' \
    "${THEHIVE_URL}/api/v1/query" 2>/dev/null)
  if [ "$CASE_CODE" = "200" ]; then
    ok "TheHive API key valid — cases accessible"
    ((PASS++))
  else
    fail "TheHive API key invalid or insufficient permissions (HTTP ${CASE_CODE})"
    warn "Fix: Create a new API key in TheHive → Settings → API Keys"
    ((FAIL++))
  fi
else
  fail "TheHive unreachable (HTTP ${HTTP_CODE:-TIMEOUT})"
  warn "Fix: Check THEHIVE_URL in .env"
  warn "Fix: Ensure TheHive is running and port is accessible"
  ((FAIL++))
fi

echo ""

# ── Test 3: n8n Webhook ────────────────────────────────────────
echo -e "${CYAN}[3] n8n Webhook${NC}"
info "URL: ${N8N_WEBHOOK_URL}"

HTTP_CODE=$(curl -s --max-time 10 -o /dev/null -w "%{http_code}" \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"action":"chat","message":"ping","session_id":"health-check"}' \
  "${N8N_WEBHOOK_URL}" 2>/dev/null)

if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "201" ]; then
  ok "n8n webhook reachable and responding"
  ((PASS++))
elif [ "$HTTP_CODE" = "404" ]; then
  fail "n8n webhook path not found (HTTP 404)"
  warn "Fix: Check webhook path in N8N_WEBHOOK_URL"
  warn "Fix: Make sure the n8n workflow is Active (Published)"
  ((FAIL++))
elif [ -z "$HTTP_CODE" ] || [ "$HTTP_CODE" = "000" ]; then
  fail "n8n connection timeout"
  warn "Fix: ufw allow 5678 on n8n server"
  warn "Fix: Check N8N_WEBHOOK_URL in .env"
  ((FAIL++))
else
  fail "n8n returned HTTP ${HTTP_CODE}"
  warn "Fix: Check n8n workflow configuration"
  ((FAIL++))
fi

echo ""

# ── Summary ────────────────────────────────────────────────────
echo "══════════════════════════════════════════"
echo "  RESULTS: ${PASS} passed, ${FAIL} failed"
echo "══════════════════════════════════════════"

if [ "$FAIL" = "0" ]; then
  echo -e "${GREEN}"
  echo "  ✅ All connections OK!"
  echo "  Ready to deploy SOC Pilots."
  echo -e "${NC}"
  exit 0
else
  echo -e "${RED}"
  echo "  ❌ ${FAIL} connection(s) failed."
  echo "  Fix the issues above before deploying."
  echo -e "${NC}"
  exit 1
fi
