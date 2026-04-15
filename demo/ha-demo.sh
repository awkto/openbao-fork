#!/usr/bin/env bash
# OpenBao Enterprise HA Demo Script
# Run from any machine with curl and SSH access to the cluster nodes.
#
# Usage: ./ha-demo.sh
#
# Cluster: baoha-{1,2,3}.dnsif.ca (voters) + baoha-dr-1.dnsif.ca (DR non-voter)
set -euo pipefail

# --- Configuration ---
LEADER="baoha-1.dnsif.ca"
STANDBY="baoha-2.dnsif.ca"
DR_NODE="baoha-dr-1.dnsif.ca"
TOKEN="${BAO_TOKEN:-}"
UNSEAL_KEY="${BAO_UNSEAL_KEY:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CA_CERT="${BAO_CACERT:-${SCRIPT_DIR}/tls/ca-cert.pem}"
CURL="curl -s --cacert $CA_CERT"
SCHEME="https"

RED='\033[0;31m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
NC='\033[0m'

pause() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
    echo ""
}

header() {
    echo ""
    echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════════${NC}"
    echo ""
}

run() {
    echo -e "${GREEN}\$ $1${NC}"
    eval "$1"
}

if [ -z "$TOKEN" ] || [ -z "$UNSEAL_KEY" ]; then
    echo -e "${RED}Set BAO_TOKEN and BAO_UNSEAL_KEY before running.${NC}"
    echo "  export BAO_TOKEN=s.xxxxx"
    echo "  export BAO_UNSEAL_KEY=xxxxx"
    exit 1
fi

# ──────────────────────────────────────────────────
header "1. CLUSTER TOPOLOGY"
echo "OpenBao 4-node Raft cluster with horizontal read scalability."
echo ""
echo "  baoha-1  (voter)     baoha-2  (voter)     baoha-3  (voter)"
echo "     |                    |                    |"
echo "     +--------------------+--------------------+"
echo "                          |"
echo "                   baoha-dr-1  (non-voter / DR replica)"
echo ""
echo "All standby nodes serve reads locally. Writes forward to leader."
pause

run "$CURL -H 'X-Vault-Token: $TOKEN' ${SCHEME}://$LEADER:8200/v1/sys/ha-status | python3 -m json.tool"
pause

# ──────────────────────────────────────────────────
header "2. WRITE A SECRET — capture X-Bao-Index"
echo "When the active node processes a write, it returns the Raft applied"
echo "index in the X-Bao-Index response header."
pause

run "$CURL -D /dev/stderr -H 'X-Vault-Token: $TOKEN' -X POST -d '{\"data\":{\"password\":\"s3cret\",\"env\":\"production\"}}' ${SCHEME}://$LEADER:8200/v1/secret/data/demo-secret 2>&1 | grep -E 'X-Bao-Index|HTTP'"
echo ""
echo -e "${YELLOW}Notice the X-Bao-Index header in the response.${NC}"
pause

# Get the actual index value
BAO_IDX=$($CURL -D- -H "X-Vault-Token: $TOKEN" ${SCHEME}://$LEADER:8200/v1/secret/data/demo-secret 2>&1 | grep -i X-Bao-Index | awk '{print $2}' | tr -d '\r')
echo -e "Captured index: ${GREEN}$BAO_IDX${NC}"
pause

# ──────────────────────────────────────────────────
header "3. CONSISTENT READ FROM STANDBY"
echo "A client sends X-Bao-Require-Index to tell the standby: don't serve"
echo "this read until your local Raft index reaches this value."
echo ""
echo "This eliminates stale reads / 404s after mount creation."
pause

run "$CURL -H 'X-Vault-Token: $TOKEN' -H 'X-Bao-Require-Index: $BAO_IDX' ${SCHEME}://$STANDBY:8200/v1/secret/data/demo-secret | python3 -m json.tool"
echo ""
echo -e "${GREEN}Read served from standby with guaranteed consistency.${NC}"
pause

# ──────────────────────────────────────────────────
header "4. CLUSTER HEALTH MONITORING"
echo "The enhanced sys/ha-status endpoint shows:"
echo "  - Per-node Raft applied index and replication lag"
echo "  - Cluster health from autopilot (voters, non-voters, failure tolerance)"
pause

run "$CURL -H 'X-Vault-Token: $TOKEN' ${SCHEME}://$LEADER:8200/v1/sys/ha-status | python3 -c \"
import sys, json
d = json.load(sys.stdin)
ch = d.get('cluster_health', {})
print(f'  Healthy:           {ch.get(\"healthy\")}')
print(f'  Failure tolerance: {ch.get(\"failure_tolerance\")}')
print(f'  Leader:            {ch.get(\"leader\")}')
print(f'  Voters:            {ch.get(\"voters\")}')
print(f'  Non-voters:        {ch.get(\"non_voters\")}')
print(f'  Replication lag:   {ch.get(\"replication_lag\")}')
\""
pause

# ──────────────────────────────────────────────────
header "5. LEADER FAILOVER"
echo "Killing the current leader. Raft will elect a new one in ~3 seconds."
pause

CURRENT_LEADER=$($CURL -H "X-Vault-Token: $TOKEN" ${SCHEME}://$LEADER:8200/v1/sys/leader | python3 -c "import sys,json; print(json.load(sys.stdin).get('leader_address',''))" 2>/dev/null || echo "${SCHEME}://$LEADER:8200")
echo -e "Current leader: ${RED}$CURRENT_LEADER${NC}"
echo ""

run "ssh altanc@$LEADER 'sudo systemctl stop bao'"
echo ""
echo "Leader stopped. Waiting for re-election..."
sleep 8

# Find the new leader
for host in $STANDBY baoha-3.dnsif.ca; do
    MODE=$(ssh altanc@$host "BAO_ADDR=https://127.0.0.1:8200 BAO_CACERT=/opt/bao/tls/ca-cert.pem bao status 2>&1 | grep 'HA Mode'" | awk '{print $NF}')
    if [ "$MODE" = "active" ]; then
        NEW_LEADER=$host
        break
    fi
done
echo -e "New leader: ${GREEN}$NEW_LEADER${NC}"
echo ""

echo "Verifying data survived failover:"
run "$CURL -H 'X-Vault-Token: $TOKEN' ${SCHEME}://$NEW_LEADER:8200/v1/secret/data/demo-secret | python3 -c \"import sys,json; print(json.dumps(json.load(sys.stdin)['data']['data'], indent=2))\""
pause

# Bring the old leader back
echo "Bringing old leader back as standby..."
ssh altanc@$LEADER "sudo systemctl start bao" 2>/dev/null
sleep 3
ssh altanc@$LEADER "BAO_ADDR=https://127.0.0.1:8200 BAO_CACERT=/opt/bao/tls/ca-cert.pem bao operator unseal $UNSEAL_KEY" > /dev/null 2>&1
echo -e "${GREEN}Old leader rejoined as standby.${NC}"
pause

# ──────────────────────────────────────────────────
header "6. DR NODE STATUS"
echo "The non-voter node replicates all data but doesn't participate in"
echo "leader elections. It's a disaster recovery standby."
pause

run "$CURL -H 'X-Vault-Token: $TOKEN' ${SCHEME}://$DR_NODE:8200/v1/sys/storage/raft/dr-failover | python3 -m json.tool"
pause

# ──────────────────────────────────────────────────
header "DEMO COMPLETE"
echo "Features demonstrated:"
echo "  1. Read-after-write consistency (X-Bao-Index headers)"
echo "  2. Enhanced cluster health monitoring"
echo "  3. Automatic leader failover (~3s)"
echo "  4. Data survives failover"
echo "  5. DR non-voter node ready for disaster recovery"
echo ""
echo "Not shown (destructive): DR failover — kill all voters, promote"
echo "non-voter to leader with: POST /v1/sys/storage/raft/dr-failover"
echo ""
echo -e "${GREEN}Thank you!${NC}"
