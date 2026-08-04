# Certificate Expiry Monitor (CEM)

A robust, extensible Python application for monitoring TLS, URL, and local certificate expiration with automated alert management and multiple notification channels (Console, Webhook, SMTP Email, **SendGrid API**).

## Features

- **Multiple Certificate Sources**:
  - **TLS Endpoints**: Direct hostname/IP and port inspection (`host:port` / `[ipv6]:port`).
  - **URL Targets**: Direct HTTPS URL endpoint inspection (`https://example.com/health`).
  - **Local Files**: PEM & DER files, directories, and glob patterns (`./certs/*.pem`).
- **Notification Channels**:
  - **Console**: Human-readable stderr alert logs.
  - **Webhook**: POST JSON alert payloads to Slack, Teams, or custom webhook endpoints.
  - **Email (SMTP)**: Send formatted alert emails via SMTP (STARTTLS / SSL authentication).
  - **Email (SendGrid API)**: Send alerts via SendGrid REST API over **HTTPS (port 443)** — bypasses ISPs that block SMTP ports.
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

# On Windows:
.venv\Scripts\activate

# On Windows (if PowerShell blocks scripts):
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1

# On Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### One-Click Launcher (Windows)

Double-click `launch_cem.bat` to open an interactive menu:

```
1) Quick check (default targets)
2) Check custom URL
3) Continuous monitor mode
4) Start API server
5) Dry-run (no email sent)
0) Exit
```

---

## Docker

Run CEM as a container — no Python installation needed.

### Prerequisites

- Docker with Docker Compose (Compose v2.24+ supports optional `.env` files)

### Build the image

```bash
docker build -t cem .
```

### One-off check

Mount your `config.yaml` (read-only) and keep alert state in a named volume:

```bash
docker run --rm \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  -v cem-state:/app/data \
  cem check --config /app/config.yaml --state-file /app/data/certificate-monitor-state.json
```

No config file? Targets can be passed directly:

```bash
docker run --rm cem --url https://example.com --format json
```

### Continuous background monitor

```bash
docker run -d --restart unless-stopped --name cem-monitor \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  -v cem-state:/app/data \
  cem monitor --config /app/config.yaml --state-file /app/data/certificate-monitor-state.json
```

### HTTP REST API server

The API server must bind `0.0.0.0` inside the container to be reachable from your host:

```bash
docker run -d --restart unless-stopped --name cem-api \
  -p 8000:8000 \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  cem serve --config /app/config.yaml --host 0.0.0.0 --port 8000

curl http://localhost:8000/api/monitors
```

### Docker Compose (recommended)

Compose wires up config mounting, state persistence, and port mapping for you. It runs out of the box using the project's `example_config.yaml` — no setup required. To use your own configuration, either edit `example_config.yaml` or point the `CONFIG_FILE` variable at your file, e.g. `CONFIG_FILE=config.yaml docker compose run --rm cem`. Then:

```bash
# One-off check (uses example_config.yaml by default; the first run builds the image)
docker compose run --rm cem

# Continuous monitor (background)
docker compose --profile monitor up -d

# REST API server on http://localhost:8000 (background)
docker compose --profile api up -d

# View API logs
docker compose --profile api logs -f

# Stop everything
docker compose --profile cli --profile monitor --profile api down
```

> **Note:** the example config enables the webhook and SendGrid notification channels, which need credentials in your `.env` file (see [Email Alerts & Environment Configuration](#email-alerts--environment-configuration-1)). Without them the check still prints its results, but it reports a notification-setup error and exits non-zero. For a quick smoke test with no credentials at all, pass targets directly:

```bash
docker compose run --rm cem check --url https://example.com
```

### Passing secrets & env vars

Secrets and settings are read from your `.env` file automatically (see [Email Alerts & Environment Configuration](#email-alerts--environment-configuration-1)). With Compose, place `.env` next to `docker-compose.yml`. With plain `docker run`, pass them explicitly:

```bash
docker run --rm \
  -e SENDGRID_API_KEY=SG.xxx \
  -e SENDGRID_FROM=alerts@example.com \
  -e ALERT_RECIPIENT=admin@example.com \
  -e CHECK_INTERVAL=21600 \
  cem --url https://example.com
```

### Notes

- The container runs as an **unprivileged user** (`cem`), not root.
- `/app/data` is the designated persistent volume: keep the JSON state file there (as in the commands above) so alert suppression survives container restarts.
- To monitor local certificate files, mount them read-only and reference the container path, e.g. `-v "$(pwd)/certs:/certs:ro" cem --file /certs/*.pem`.

---

## How to Check URLs

### 1. Check URLs directly from Terminal

```bash
# Check a single URL
python -m checker --url https://example.com

# Check multiple URLs
python -m checker --url https://example.com --url https://api.example.com:8443
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

# Run a single monitor loop (for testing)
python -m checker monitor --interval 3600 --once
```

### 5. Run HTTP REST API Server

```bash
# Start API server on port 8000
python -m checker serve --port 8000

# In another terminal, register a new URL target
curl -X POST http://127.0.0.1:8000/api/monitors ^
  -H "Content-Type: application/json" ^
  -d "{\"url\": \"https://example.com\"}"

# View all monitored targets
curl http://127.0.0.1:8000/api/monitors
```

---

## Email Alerts & Environment Configuration (`.env`)

Copy `.env.example` to `.env` and fill in your credentials:

```bash
copy .env.example .env
```

### Option 1: SendGrid API (Recommended — Bypasses SMTP blocking)

SendGrid uses **HTTPS (port 443)** to send emails, so it works even when your ISP blocks SMTP ports. It also works with any email address (Gmail, Outlook, etc.) as the sender.

```env
# SendGrid API Configuration
SENDGRID_API_KEY=SG.your_sendgrid_api_key_here   # From SendGrid dashboard
SENDGRID_FROM=blacksaphire.ke@gmail.com           # Must be verified in SendGrid
SENDGRID_RECIPIENT=admin@example.com              # Where alerts go
```

**Setup steps:**
1. Create a free account at [signup.sendgrid.com](https://signup.sendgrid.com)
2. Go to **Settings → API Keys → Create API Key** (Full Access)
3. Go to **Settings → Sender Authentication → Single Sender Verification** and verify your sender email
4. Add the values to your `.env` file

### Option 2: SMTP Email (Traditional)

```env
# SMTP Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
SMTP_FROM=your-email@gmail.com

# Alert Recipients (comma-separated for multiple)
ALERT_RECIPIENT=admin@example.com
```

> **Note:** Many residential ISPs block SMTP ports (587, 465). If emails don't arrive, use the **SendGrid API** option above instead.

### Optional: Custom Thresholds & Interval

```env
# Configurable Alert Thresholds (in days, comma-separated)
ALERT_THRESHOLDS=30,14,7,3,1

# Monitoring Interval (in seconds, default 21600 = 6 hours)
CHECK_INTERVAL=21600
```

---

## Configuration File (`example_config.yaml`)

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
    enabled: false
    smtp_host: "${SMTP_HOST}"
    smtp_port: 587
    username: "${SMTP_USERNAME}"
    password: "${SMTP_PASSWORD}"
    from_addr: "${SMTP_FROM}"
    to_addrs:
      - "${ALERT_RECIPIENT}"

  sendgrid:
    enabled: true
    api_key: "${SENDGRID_API_KEY}"
    from_addr: "${SENDGRID_FROM}"
    to_addrs:
      - "${SENDGRID_RECIPIENT}"
```

> Environment variables (`${VAR}`) are loaded from your `.env` file automatically. If a variable is unset, it defaults to an empty string and the corresponding notifier will be skipped gracefully.

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

All 54+ tests should pass.
