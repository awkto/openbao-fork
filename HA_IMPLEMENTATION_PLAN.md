# OpenBao Enterprise HA Implementation Plan

## Demo/Roadshow Reference Implementation

This document describes the HA enhancements built in this fork as a
proof-of-concept for enterprise-grade High Availability in OpenBao.
These changes are designed to align with upstream architectural direction
(flat-cluster model, no perf replication) and address the top gaps
blocking bank/enterprise adoption.

---

## Test Environment

| Node | Hostname | IP | Role |
|------|----------|----|------|
| 1 | baoha-1.dnsif.ca | 10.33.11.205 | Raft Voter (initial leader) |
| 2 | baoha-2.dnsif.ca | 10.33.11.206 | Raft Voter |
| 3 | baoha-3.dnsif.ca | 10.33.11.207 | Raft Voter |
| 4 | baoha-dr-1.dnsif.ca | 10.33.11.208 | Raft Non-Voter (DR) |

---

## Feature 1: Read-After-Write Consistency (Issue #2546)

### Problem
Standby nodes with horizontal read scalability return stale data (404s)
after write operations like mount creation. The cache invalidation is
push-based and asynchronous — there is a window where a client writing
to the active node and immediately reading from a standby will get stale
results.

### Solution: WAL Index Header Protocol

**Active node (on every write response):**
- Add `X-Bao-Index: <raft_applied_index>` header to all write responses
- The index represents the Raft applied index at the time of the write

**Standby node (on every read request):**
- Check for `X-Bao-Require-Index: <index>` header in incoming requests
- If present, wait (with timeout) until local applied index >= requested index
- If timeout (configurable, default 5s), forward the request to the active node
- Add `X-Bao-Index: <local_applied_index>` to read responses for client tracking

**Client behavior:**
- Clients capture `X-Bao-Index` from write responses
- Send it as `X-Bao-Require-Index` on subsequent reads
- Load balancers/proxies can pass these headers through transparently

### Files Modified
- `http/handler.go` — Add index headers to responses, parse require-index
- `vault/ha.go` — Add WaitForIndex() method on Core
- `vault/raft.go` — Expose WaitForAppliedIndex() on RaftBackend
- `physical/raft/raft.go` — Implement index waiting with notification channel
- `sdk/helper/consts/consts.go` — Define header constants

### Key Design Decisions
- Timeout-based: don't block forever; forward to active as fallback
- Opt-in: only activates when client sends the header
- Compatible: clients without the header see no behavior change

---

## Feature 2: Enhanced HA Health Monitoring

### Problem
The current `sys/ha-status` endpoint returns minimal information.
Enterprise users need: replication lag, per-node health scores,
invalidation backlog, cluster topology with voter/non-voter roles.

### Solution: Extended HA Status API

**New fields in `sys/ha-status` response:**

```json
{
  "nodes": [...],
  "cluster_health": {
    "healthy": true,
    "failure_tolerance": 1,
    "leader": "node-id",
    "voters": ["id1", "id2", "id3"],
    "non_voters": ["id4"],
    "replication_lag_ms": {
      "node-id-2": 12,
      "node-id-3": 8,
      "node-id-4": 45
    }
  }
}
```

**Per-node enhancements to HAStatusNode:**
- `raft_applied_index` — current applied index
- `raft_committed_index` — current committed index
- `replication_lag` — index delta from leader
- `role` — "voter" or "non-voter"
- `healthy` — autopilot health assessment
- `last_contact_ms` — ms since last successful contact

### Files Modified
- `vault/logical_system.go` — Extend handleHAStatus, HAStatusNode struct
- `vault/ha.go` — Extend getHAMembers to include raft state
- `vault/logical_system_paths.go` — Update response schema

---

## Feature 3: Automated DR Failover

### Problem
When all voter nodes are lost, the cluster cannot achieve quorum and
non-voter nodes sit idle. Recovery requires manual intervention (peer
recovery, snapshot restore). Enterprise deployments need automated
failover to DR non-voters.

### Solution: DR Watchdog on Non-Voter Nodes

**Mechanism:**
1. Non-voter nodes run a DR watchdog goroutine
2. Watchdog monitors leader connectivity via heartbeat timeout
3. If no leader contact for `dr_failover_threshold` (default: 30s):
   - Verify all known voters are unreachable
   - Enter DR failover candidate state
   - If this node has the highest applied index among reachable non-voters:
     - Execute Raft peer recovery (reconfigure cluster with self as voter)
     - Promote self to voter and become leader
4. New `sys/ha-status` shows DR failover state

**Configuration:**
```hcl
ha_storage "raft" {
  # ...
  autopilot {
    dr_failover_enabled   = true
    dr_failover_threshold = "30s"
  }
}
```

**Safety:**
- Only triggers when ALL voters are confirmed unreachable
- Uses Raft applied index to pick the most up-to-date non-voter
- Logs extensively for audit trail
- Can be disabled (default: disabled)

### Files Modified
- `vault/ha.go` — Add DR watchdog goroutine, started for non-voter standby nodes
- `physical/raft/raft.go` — Add RecoverCluster method for single-node recovery
- `physical/raft/raft_autopilot.go` — Add DR failover config fields
- `command/server/config.go` — Parse dr_failover config

---

## Feature 4: Version-Gated Leader Election (PR #2865)

### Problem
During rolling upgrades, an older-version node can win leadership,
potentially breaking newer nodes that depend on new features. This
prevents zero-downtime upgrades.

### Solution: Minimum Version Check in Leadership Acquisition

**Mechanism:**
1. Before a node attempts to acquire the HA lock, it checks the cluster's
   minimum expected version (stored in Raft metadata)
2. If the node's version is below the minimum, it defers leadership
3. The minimum version advances as nodes report their versions via Echo

### Files Modified
- `vault/ha.go` — Add version check before lock acquisition
- `physical/raft/raft_autopilot.go` — Track and enforce minimum version
- `vault/version_store.go` — Add cluster minimum version management

---

## Build & Deploy

### Build Command
```bash
export PATH=/usr/local/go/bin:$PATH
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -tags "openbao" \
  -o bin/bao .
```

### Deploy to Each Node
```bash
scp bin/bao altanc@baoha-X.dnsif.ca:/tmp/bao
ssh altanc@baoha-X.dnsif.ca 'sudo mv /tmp/bao /usr/local/bin/bao && sudo chmod +x /usr/local/bin/bao'
```

### Node Configuration (baoha-1 example)
```hcl
storage "raft" {
  path    = "/opt/bao/data"
  node_id = "baoha-1"

  retry_join {
    leader_api_addr = "http://baoha-2.dnsif.ca:8200"
  }
  retry_join {
    leader_api_addr = "http://baoha-3.dnsif.ca:8200"
  }
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true
}

api_addr     = "http://baoha-1.dnsif.ca:8200"
cluster_addr = "https://baoha-1.dnsif.ca:8201"
disable_mlock = true
```
