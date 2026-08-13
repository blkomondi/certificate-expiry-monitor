#!/bin/bash
# Deploy the CEM 24/7 monitor on a Sidian server.
# Run as root on 192.168.200.13 (or .14). Requires Docker on the server.
set -e

REGISTRY=192.168.200.13:32000
IMAGE=$REGISTRY/cem:20260813
NAME=cem-monitor

echo "==> [1/4] Writing /opt/cem/config.yaml"
mkdir -p /opt/cem
cat > /opt/cem/config.yaml <<'EOF'
settings:
  timeout: 10
  concurrency: 8
  state_file: "/app/data/certificate-monitor-state.json"
  check_interval: 21600

thresholds:
  warning_days: 30
  high_days: 15
  critical_days: 5

targets:
  - type: url
    url: "https://ecollectv2.sidianbank.co.ke/"
  - type: url
    url: "https://ecollectuat.sidianbank.co.ke/"
  - type: url
    url: "https://ecollectdev.sidianbank.co.ke/"
  - type: url
    url: "https://keycloakdev.sidianbank.co.ke/"

notifications:
  console:
    enabled: true
  webhook:
    enabled: true
    url: "http://192.168.200.13:9090/cem-alert"
  email:
    enabled: true
    smtp_host: "192.168.200.177"
    smtp_port: 25
    username: ""
    password: ""
    use_tls: false
    starttls: false
    ssl: false
    from_addr: "ecollect@sidianbank.co.ke"
    to_addrs:
      - "rktoroitich@sidianbank.co.ke"
  sendgrid:
    enabled: false
    api_key: ""
    from_addr: ""
    to_addrs:
      - "rktoroitich@sidianbank.co.ke"
EOF

echo "==> [2/4] Pulling image $IMAGE"
docker pull "$IMAGE"

echo "==> [3/4] Starting container '$NAME' (restart: unless-stopped)"
docker rm -f "$NAME" 2>/dev/null || true
docker run -d --restart unless-stopped --name "$NAME" \
  -v /opt/cem/config.yaml:/app/config.yaml:ro \
  -v cem-state:/app/data \
  "$IMAGE" \
  monitor --config /app/config.yaml --state-file /app/data/certificate-monitor-state.json

echo "==> [4/4] Verifying"
sleep 8
docker ps | grep "$NAME"
echo "--- recent logs ---"
docker logs "$NAME" --tail 20
echo "--- state file ---"
docker exec "$NAME" cat /app/data/certificate-monitor-state.json 2>/dev/null || true

echo
echo "DONE. Monitor checks every 6 hours; alerts go to rktoroitich@sidianbank.co.ke."
