# Cloud Asset Security Review

> Automatically discover newly created internet-facing AWS assets and perform AI-assisted security reviews.

```
New Asset Created (CloudTrail Event)
          ↓
  Asset Discovery (EventBridge)
          ↓
  Metadata Collection (DNS · HTTP · TLS · Ports)
          ↓
  Security Checks (Headers · TLS · Endpoints · Ports · DNS)
          ↓
  LLM-Based Review (Claude — risk synthesis + prioritisation)
          ↓
  Findings & Report (JSON + Markdown + Slack alert)
```

## Features

- **Zero-config discovery** via CloudTrail + EventBridge — no agents, no polling
- **5 security check suites**: HTTP headers, TLS/SSL, sensitive endpoint probing, port exposure, DNS/subdomain takeover
- **AI-powered synthesis** using Claude to prioritise findings and generate attack scenarios
- **Ephemeral execution** — each scan runs in an isolated Lambda / Kubernetes Job, auto-cleaned after completion
- **Structured JSON + Markdown reports** with CWE references, evidence, and remediation steps
- **Slack alerting** for CRITICAL/HIGH findings
- **Local demo mode** — runs without any AWS credentials

---

## Quick Start (Local — No AWS Required)

### 1. Clone and install

```bash
git clone https://github.com/your-org/cloud-asset-security-review
cd cloud-asset-security-review
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY
```

### 3. Run a scan

```bash
# Scan any public hostname
python -m src.main scan --target example.com --json

# Demo mode (mock AWS assets, no credentials needed)
python -m src.main demo --target example.com

# Docker (no Python setup needed)
docker compose run --rm demo TARGET=example.com
```

Reports are written to `/tmp/reports/` by default.

---

## Installation

### Prerequisites

| Requirement | Version |
|------------|---------|
| Python | 3.12+ |
| pip | 23+ |
| Docker | 24+ (optional) |
| AWS CLI | 2.x (for AWS deployment) |

### Python

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### Docker

```bash
docker build -t cloud-asset-scanner .
docker run --env-file .env cloud-asset-scanner python -m src.main scan --target example.com --json
```

---

## Configuration

All configuration is via environment variables. Copy `.env.example` to `.env`:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ANTHROPIC_API_KEY` | Yes* | — | Claude API key for LLM review |
| `AWS_REGION` | No | `us-east-1` | AWS region |
| `AWS_ACCOUNT_ID` | No | — | AWS account ID |
| `MOCK_AWS` | No | `false` | Use mock data (no AWS creds needed) |
| `MOCK_TARGET` | No | `example.com` | Hostname for mock mode |
| `DB_PATH` | No | `/tmp/asset_registry.db` | SQLite database path |
| `REPORTS_OUTPUT_DIR` | No | `/tmp/reports` | Report output directory |
| `SLACK_WEBHOOK_URL` | No | — | Slack webhook for alerts |
| `ALERT_ON_RISK_LEVELS` | No | `CRITICAL,HIGH` | Risk levels that trigger alerts |
| `SCAN_TIMEOUT_S` | No | `30` | Per-request timeout (seconds) |
| `PORT_SCAN_TARGETS` | No | See config.py | Comma-separated ports to probe |
| `LLM_MODEL` | No | `claude-opus-4-5` | Anthropic model to use |

*If `ANTHROPIC_API_KEY` is not set, a deterministic fallback review is generated from the structured findings — the pipeline always produces output.

---

## CLI Usage

```bash
# Scan a single target
python -m src.main scan --target api.example.com

# Scan with metadata and write reports
python -m src.main scan \
  --target api.example.com \
  --asset-type alb \
  --owner platform-team \
  --env production \
  --json

# Demo mode with mock AWS assets
python -m src.main demo --target example.com

# Process pending assets from registry (worker mode)
python -m src.main worker --once

# Continuous worker (poll every 10s)
python -m src.main worker

# Registry statistics
python -m src.main stats
```

---

## AWS Deployment

### Prerequisites

1. Enable CloudTrail in your AWS account (must be writing to CloudWatch Logs)
2. Build and push the Docker image to ECR:

```bash
# Build and push
aws ecr create-repository --repository-name cloud-asset-scanner
docker build -t cloud-asset-scanner .
docker tag cloud-asset-scanner:latest \
  123456789012.dkr.ecr.us-east-1.amazonaws.com/cloud-asset-scanner:latest
aws ecr get-login-password | docker login --username AWS \
  --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/cloud-asset-scanner:latest
```

3. Deploy CloudFormation stack:

```bash
aws cloudformation deploy \
  --template-file cloudformation/template.yaml \
  --stack-name cloud-asset-security-review \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    AnthropicApiKey=sk-ant-your-key-here \
    ScannerImageUri=123456789012.dkr.ecr.us-east-1.amazonaws.com/cloud-asset-scanner:latest \
    Environment=production \
    SlackWebhookUrl=https://hooks.slack.com/services/xxx
```

### What gets deployed

```
EventBridge Rules (4)          — detect EC2, ALB, API GW, Route53 creation
    ↓
Discovery Lambda               — parses event, registers asset, enqueues scan
    ↓
SQS FIFO Queue                 — buffers scan jobs (DLQ for failures)
    ↓
Scanner Lambda (concurrency=10) — full scan pipeline per asset
    ↓
S3 Bucket                      — stores JSON + Markdown reports
    ↓
Slack / CloudWatch             — alerts and monitoring
```

### Kubernetes deployment

```bash
# Create namespace and secrets
kubectl apply -f kubernetes/scan-job.yaml

# Launch a scan job for an asset
ASSET_ID=abc-123 envsubst < kubernetes/scan-job.yaml | kubectl apply -f -

# Watch the job
kubectl logs -n security-scanning -l asset-id=abc-123 -f

# Jobs auto-delete after 10 minutes (ttlSecondsAfterFinished: 600)
```

---

## Running Tests

```bash
# All tests
pytest tests/ -v

# With coverage
pytest tests/ -v --cov=src --cov-report=term-missing

# Single module
pytest tests/test_security_checks.py::TestHeaderChecks -v
```

All 29 tests pass. No external services required.

---

## Project Structure

```
cloud-asset-security-review/
├── src/
│   ├── models.py                    # Core data models
│   ├── config.py                    # Environment-based config
│   ├── main.py                      # CLI entry point
│   ├── discovery/
│   │   ├── cloudtrail_monitor.py    # CloudTrail event parsing + mock mode
│   │   └── asset_registry.py        # SQLite asset store
│   ├── enrichment/
│   │   ├── __init__.py              # EnrichmentPipeline orchestrator
│   │   ├── http_enricher.py         # DNS + HTTP + tech fingerprinting
│   │   ├── tls_enricher.py          # TLS certificate analysis
│   │   └── port_scanner.py          # TCP port probing
│   ├── security_checks/
│   │   ├── __init__.py              # run_all_checks orchestrator
│   │   ├── header_checks.py         # HTTP security headers
│   │   ├── tls_checks.py            # TLS/SSL validation
│   │   ├── endpoint_checks.py       # Sensitive path probing
│   │   ├── port_checks.py           # Network exposure
│   │   └── dns_checks.py            # Subdomain takeover + DNS hygiene
│   ├── llm_review/
│   │   └── reviewer.py              # Claude integration + fallback
│   ├── orchestration/
│   │   ├── scan_orchestrator.py     # Full pipeline runner
│   │   └── lambda_handler.py        # AWS Lambda entry points
│   └── reporting/
│       ├── report_generator.py      # JSON + Markdown reports
│       └── slack_notifier.py        # Slack webhook alerts
├── tests/
│   └── test_security_checks.py      # 29 unit tests
├── sample_output/
│   ├── report_api_acme_payments_com.json
│   └── report_api_acme_payments_com.md
├── kubernetes/
│   └── scan-job.yaml                # Ephemeral K8s Job spec
├── cloudformation/
│   └── template.yaml                # Full AWS deployment
├── docs/
│   └── DESIGN.md                    # Architecture decisions + tradeoffs
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── .env.example
└── README.md
```

---

## Security Checks Reference

| Check ID Prefix | Category | Count |
|----------------|----------|-------|
| `HDR-` | HTTP Security Headers | 12 checks |
| `TLS-` | TLS/SSL Configuration | 7 checks |
| `ENDPOINT-` | Sensitive Path Exposure | 30+ paths |
| `PORT-` | Network Port Exposure | 14 ports |
| `DNS-` | DNS / Subdomain Takeover | 5 checks |
| `GOVERNANCE-` | Asset Tagging / Ownership | 2 checks |

### HTTP Headers checked
HSTS · CSP · X-Frame-Options · X-Content-Type-Options · Referrer-Policy · Permissions-Policy · CORS · X-Powered-By · Server version disclosure

### Sensitive paths probed
`/.env` · `/.git/config` · `/admin` · `/swagger-ui` · `/actuator/env` · `/actuator/heapdump` · `/phpmyadmin` · `/wp-admin` · `/.env` · `/graphiql` · `/console` · `/config.json` · and 20+ more

### High-risk ports checked
Redis (6379) · MongoDB (27017) · Elasticsearch (9200) · MySQL (3306) · PostgreSQL (5432) · RDP (3389) · Telnet (23) · Memcached (11211) · Jupyter (8888) · and more

---

## Sample Output

See [`sample_output/`](sample_output/) for a full example report against a mock production payments API with 16 findings (3 CRITICAL, 4 HIGH).

---

## Scalability

The system is designed for 10,000+ assets/day:

| Component | Scale strategy |
|-----------|---------------|
| Discovery | EventBridge is serverless — handles any event volume |
| Queue | SQS FIFO scales to ~3,000 msg/s |
| Scan workers | Lambda concurrency limit = cost/parallelism knob |
| Storage | Swap SQLite → DynamoDB for multi-node |
| Reports | S3 with lifecycle policies — zero ops |

See [`docs/DESIGN.md`](docs/DESIGN.md) for detailed tradeoff analysis.

---

## License

MIT
