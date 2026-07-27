# Certificate Expiry Monitor (CEM)

A robust, extensible Python application for monitoring TLS, URL, and local certificate expiration with automated alert management, notification channels (Console, Webhook, SMTP Email), and multiple export formats (Table, JSON, Prometheus).

## Features

- **Multiple Certificate Sources**:
  - **TLS Endpoints**: Direct hostname/IP and port inspection (`host:port` / `[ipv6]:port`).
  - **URL Targets**: Direct HTTPS URL endpoint inspection (`https://example.com/health`).
  - **Local Files**: PEM & DER files, directories, and glob patterns (`./certs/*.pem`).
- **Notification Channels**:
  - **Console**: Human-readable stderr alert logs.
  - **Webhook**: POST JSON alert payloads to Slack, Teams, or custom webhook endpoints.
  - **Email (SMTP)**: Send formatted alert emails via SMTP (STARTTLS / SSL authentication).
- **Flexible Alert State Management**:
  - Alert suppression and acknowledgment per target.
  - Tier-based escalation (WARNING -> HIGH -> CRITICAL -> EXPIRED).
- **Multiple Output Formats**: Table view, structured JSON, and Prometheus metric exporters.

## Quick Start

### Installation

```bash
# Create and activate virtual environment
python -m venv .venv

# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1

# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Usage Examples

#### 1. Check TLS Targets
```bash
python -m checker --domain youtube.com:443 --domain api.example.com:8443
```

#### 2. Check URL Targets
```bash
python -m checker --url https://example.com/v1/health --url https://api.mysite.org
```

#### 3. Check Local Certificate Files
```bash
python -m checker --file ./certificates/*.pem --file /etc/ssl/certs/
```

#### 4. Run with Configuration File
```bash
python -m checker --config example_config.yaml
```

## Configuration Format (`example_config.yaml`)

Environment variables in `${VARIABLE_NAME}` syntax are expanded automatically:

```yaml
settings:
  timeout: 10
  concurrency: 8
  state_file: ".certificate-monitor-state.json"

thresholds:
  warning_days: 30
  high_days: 15
  critical_days: 5

targets:
  - type: tls
    host: example.com
    port: 443

  - type: url
    url: "https://api.example.com/v1/health"

  - type: file
    path: "./certificates/*.pem"

notifications:
  console:
    enabled: true

  webhook:
    enabled: false
    url: "${CERT_WEBHOOK_URL}"

  email:
    enabled: true
    smtp_host: "smtp.example.com"
    smtp_port: 587
    username: "${SMTP_USER}"
    password: "${SMTP_PASS}"
    use_tls: true
    starttls: true
    from_addr: "alerts@example.com"
    to_addrs:
      - "admin@example.com"
      - "devops@example.com"
    subject_prefix: "[Cert Alert]"
```

## Output Formats

- **Table** (default): `python -m checker --domain example.com:443`
- **JSON**: `python -m checker --domain example.com:443 --format json`
- **Prometheus Metrics**: `python -m checker --domain example.com:443 --format prometheus`

## Suppression & Acknowledgement

```bash
# Suppress alerts for a target
python -m checker suppress --target https://example.com/v1/health --reason "Maintenance window"

# Unsuppress alerts
python -m checker unsuppress --target https://example.com/v1/health
```

## Running Tests

```bash
python -m pytest
```
