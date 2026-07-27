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
  - Tier-based escalation (30, 14, 7, 3, 1 days & Expired).
  - Resets state automatically when certificates are renewed.
- **Multiple Modes**: Single Check, Periodic Background Monitor, and HTTP REST API server.
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

---

## How to Check URLs

### 1. Check URLs directly from Terminal
```bash
# Check a single URL
python -m checker --url https://example.com

# Check multiple URLs
python -m checker --url https://example.com --url https://api.example.com:8443 --url https://google.com
```

### 2. Check URLs using Configuration File
```bash
python -m checker --config example_config.yaml
```

### 3. Change Output Format
```bash
# Human-readable table (default)
python -m checker --url https://example.com

# JSON output
python -m checker --url https://example.com --format json

# Prometheus metrics output
python -m checker --url https://example.com --format prometheus
```

### 4. Periodic Scheduled Background Monitoring
```bash
# Periodically check URLs every 6 hours (21600 seconds)
python -m checker monitor --interval 21600
```

### 5. Run HTTP REST API Server
```bash
# Start API server on port 8000
python -m checker serve --port 8000

# POST /api/monitors to register a new URL target
curl -X POST http://127.0.0.1:8000/api/monitors -H "Content-Type: application/json" -d '{"url": "https://example.com"}'

# GET /api/monitors to view target statuses
curl http://127.0.0.1:8000/api/monitors
```

---

## Email Alerts & Environment Configuration (`.env`)

Email alerts can be configured using environment variables in a `.env` file or directly in `example_config.yaml`:

### `.env` File Example
```env
# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com

# Alert Recipients (comma-separated for multiple)
ALERT_RECIPIENT=admin@example.com,devops@example.com

# Configurable Alert Thresholds (in days)
ALERT_THRESHOLDS=30,14,7,3,1

# Monitoring Interval (in seconds)
CHECK_INTERVAL=21600
```

### YAML Configuration Example (`example_config.yaml`)
```yaml
settings:
  timeout: 10
  concurrency: 8
  state_file: ".certificate-monitor-state.json"
  check_interval: 21600

thresholds:
  warning_days: 30
  high_days: 15
  critical_days: 5

targets:
  - type: url
    url: "https://example.com"
  - type: url
    url: "https://api.example.com"
  - type: tls
    host: example.com
    port: 443
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
    smtp_host: "${SMTP_HOST}"
    smtp_port: 587
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
    from_addr: "${SMTP_FROM}"
    to_addrs:
      - "${ALERT_RECIPIENT}"
```

---

## Suppression & Acknowledgement

```bash
# Suppress alerts for a specific URL
python -m checker suppress --target https://example.com --reason "Planned maintenance"

# Unsuppress alerts for a target
python -m checker unsuppress --target https://example.com
```

---

## Running Tests

```bash
python -m pytest
```
