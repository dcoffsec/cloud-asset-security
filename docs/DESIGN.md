# Design Decisions & Tradeoffs

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        AWS Account                               │
│                                                                   │
│  CloudTrail ──► EventBridge ──► Discovery Lambda                 │
│                                       │                           │
│                                  SQS FIFO Queue                  │
│                                       │                           │
│                              Scanner Lambda (×N)                 │
│                              ┌────────┴────────┐                 │
│                         Enrichment        Security Checks         │
│                         DNS/HTTP/TLS/Ports Headers/TLS/Endpoints  │
│                                       │                           │
│                              LLM Review (Claude)                 │
│                                       │                           │
│                           S3 Report  +  Slack Alert              │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Design Decisions

### 1. CloudTrail + EventBridge over polling

**Decision:** Use EventBridge rules that react to CloudTrail `CreateLoadBalancer`, `RunInstances`, `ChangeResourceRecordSets` etc., rather than periodically polling the AWS API.

**Why:**
- Zero latency — scan starts within seconds of resource creation
- No polling cost — EventBridge is ~$1/million events
- No state management for "what did I already see"
- Scales to any number of accounts via AWS Organizations EventBridge bus

**Tradeoff:** CloudTrail events can take 5–15 minutes to appear in CloudWatch Logs. For near-real-time needs, use CloudTrail Data Events (higher cost) or hook directly into resource creation via SCPs/Service Control Policies.

**Alternative considered:** AWS Config rules + Config recorder. Rejected because Config has higher per-resource cost and doesn't capture the full creation event payload (owner, tags) as cleanly.

---

### 2. Ephemeral Lambda workers over persistent services

**Decision:** Each scan runs as a short-lived Lambda invocation (max 4 minutes), not in a persistent ECS service or EC2 instance.

**Isolation benefits:**
- Each scan gets a fresh memory space — no cross-contamination of findings between assets
- Lambda execution role is tightly scoped (only S3 write + Secrets Manager read)
- Compromised scan code can't pivot to scan internal resources across invocations
- No persistent filesystem — malicious content discovered during scanning can't persist

**Cleanup strategy:**
- Lambda: zero cleanup needed — execution environment is discarded automatically
- Kubernetes Jobs: `ttlSecondsAfterFinished: 600` auto-deletes Job + Pod 10 minutes after completion
- SQLite DB: stored on ephemeral `/tmp` in Lambda, or on a mounted volume in K8s with lifecycle policies
- Reports: written to S3 with 365-day expiry lifecycle rule

**Cost at 10,000 assets/day:**
- Lambda (512MB, 240s avg): 10,000 × 0.000016667 GB-s × 240s × $0.0000166667 ≈ **$6.67/day**
- SQS: 10,000 × $0.0000004 ≈ **$0.004/day**
- EventBridge: ~$0.01/day
- Total compute: **~$7/day** for 10,000 scans

**Kubernetes alternative:** Use K8s Jobs with `restartPolicy: Never` and `ttlSecondsAfterFinished`. Better for scans requiring >15 minutes or needing persistent tooling (nmap, testssl.sh). Higher baseline cost but more control.

---

### 3. SQLite for asset registry (with DynamoDB migration path)

**Decision:** Use SQLite for local/single-node deployments. The `AssetRegistry` class abstracts storage behind a clean interface.

**Why SQLite first:**
- Zero infrastructure — works in Lambda `/tmp`, local dev, and Docker
- ACID compliant — no lost asset registrations
- 50,000 assets fits comfortably in a single SQLite file

**Migration to DynamoDB at scale:**
Replace `AssetRegistry` with a DynamoDB implementation. The key access patterns map cleanly:

| SQLite query | DynamoDB equivalent |
|-------------|---------------------|
| `WHERE scan_status = 'pending'` | GSI on `scan_status` + `discovered_at` |
| `WHERE hostname = ?` | GSI on `hostname` for deduplication |
| `WHERE asset_id = ?` | Primary key lookup |

DynamoDB also enables atomic `UpdateItem` with `ConditionExpression` to implement work-claiming (scanner claims an asset by changing `pending → claimed` atomically, preventing duplicate scans in multi-worker deployments).

**Cost crossover:** SQLite is free. DynamoDB costs ~$0.25/million reads. At 10,000 assets/day with 5 reads/write cycle per asset = ~$0.01/day. DynamoDB becomes worthwhile when you need multi-region or >10 concurrent workers.

---

### 4. LLM with deterministic fallback

**Decision:** Claude generates the security review, but if the API key is missing or the call fails, a deterministic review is generated from the structured findings.

**Why this matters:**
- Pipeline never stalls waiting for LLM — if Anthropic has an outage, scans still complete
- Deterministic output is fully testable (no API calls in unit tests)
- LLM adds value on top of structured findings — it doesn't replace them

**Prompt design choices:**
- JSON-only output with explicit schema — reliable parsing, no markdown fences to strip
- Asset context (owner, environment, type) in the prompt — LLM can calibrate risk (Redis on prod ALB vs dev box)
- Findings truncated to 300 chars each — stays within context window for large finding sets
- System prompt instructs "specific and technical" actions — avoids vague "improve security posture" output

**Model selection:** `claude-opus-4-5` for quality. Can switch to `claude-haiku-4-5` at 10x lower cost for high-volume deployments where LLM review is less critical.

**Cost per scan:** ~1,500 input tokens + ~500 output tokens = 2,000 tokens ≈ $0.015 on Opus, $0.0005 on Haiku.

---

### 5. Targeted port scanning over full nmap sweeps

**Decision:** Probe only a curated list of 14 high-risk ports rather than running a full 65,535-port scan.

**Why:**
- Full scans take 2–5 minutes and generate noise in target IDS/SIEM
- Security-relevant finding set is well-known: databases, admin panels, caches
- Faster scans = lower Lambda cost and better scaling
- Targeted scans are more attributable as legitimate security reviews

**Tradeoff:** May miss unusual services on non-standard ports (e.g. a database on port 5555). Acceptable because:
1. The asset already has security group rules — unusual ports need explicit allowance
2. Risk of unknown ports is lower than known-vulnerable services on standard ports
3. Engineering teams can add ports to `PORT_SCAN_TARGETS` config

**For production:** Run as a known IP (NAT Gateway with Elastic IP) so targets can verify the scan source. Document the scanner IP in runbooks.

---

### 6. Sensitive path probing list design

**Decision:** Use a hardcoded, curated list of ~30 paths rather than a tool like `gobuster` or `ffuf` with a large wordlist.

**Why:**
- Large wordlists (SecLists has 220k paths) generate thousands of 404s, trigger WAFs, and slow scans
- The highest-value findings come from a small, well-known set: `.env`, `/.git/config`, `/admin`, Swagger, actuator
- Curated list is auditable and reviewable by the security team
- False positive rate is low — these paths mean the same thing everywhere

**Coverage tradeoff:** Won't find custom admin paths like `/mgmt-console-v2`. Acceptable at this stage — the goal is catching the 90% case, not replacing a full pentest.

---

### 7. Single-account vs multi-account

**Current design:** Single AWS account.

**Multi-account extension (Organizations):**
1. Create a central EventBridge event bus in a Security account
2. In each member account, add EventBridge rule to forward resource-creation events to the central bus
3. Discovery Lambda in the Security account receives events from all member accounts
4. Scanner Lambda assumes cross-account roles (via STS `AssumeRole`) to fetch resource tags/metadata

This requires:
- `sts:AssumeRole` permission on scanner role
- Cross-account role in each member account with read-only EC2/ELB/Route53 permissions
- `account_id` field on `Asset` model (already present) to route role assumption

---

## Security Considerations for the Scanner Itself

The scanner is security-critical infrastructure. Key protections:

1. **Least-privilege IAM** — Discovery Lambda only writes to SQS. Scanner Lambda only reads from SQS, writes to S3, reads one secret. No `*` permissions.

2. **Network isolation** — Scanner Lambda runs in a VPC with a NAT Gateway. Outbound traffic to scanned assets goes via a known Elastic IP. Inbound: none.

3. **Secret management** — API keys in Secrets Manager, not Lambda environment variables (which appear in CloudWatch Logs).

4. **No user-controlled input in scan commands** — hostname is extracted from CloudTrail event, not passed as a string to shell commands. No subprocess/shell injection risk.

5. **Read-only scan** — All probes are passive (HTTP GET, TCP connect, TLS handshake). No exploitation, no writes to target systems.

6. **Scan attribution** — Scanner identifies itself via User-Agent: `CloudSecurityScanner/1.0 (internal-security-review)`. Teams can see scanner traffic in their logs and know it's legitimate.

---

## What This Is Not

- **Not a replacement for pentesting** — catches misconfigurations, not business logic flaws
- **Not a WAF** — detects missing WAF, doesn't provide one
- **Not a DAST tool** — doesn't fuzz inputs or test for SQLi/XSS/etc.
- **Not agent-based** — won't catch server-side misconfigs invisible from the network

The right mental model: this is automated security hygiene at scale, catching the "low-hanging fruit" that fills pentest reports and breach post-mortems. It frees human security engineers to focus on harder problems.
