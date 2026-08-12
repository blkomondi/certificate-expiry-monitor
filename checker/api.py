"""HTTP REST API server for monitor registration and status inspection."""

from __future__ import annotations

import json
from datetime import UTC
from http.server import BaseHTTPRequestHandler, HTTPServer

from .config import AppConfig, TargetSpec
from .service import run_checks


def _iso8601(dt: object) -> str | None:
    if dt is None:
        return None
    return dt.astimezone(UTC).isoformat().replace("+00:00", "Z")  # type: ignore[union-attr]


class MonitorApiHandler(BaseHTTPRequestHandler):
    config: AppConfig
    dynamic_targets: list[TargetSpec] = []

    def _send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        # Suppress standard HTTP request logging to keep output clean
        pass

    def do_GET(self) -> None:
        if self.path in ("/api/monitors", "/api/monitors/"):
            all_targets = list(self.config.targets) + self.dynamic_targets
            results = run_checks(
                all_targets,
                timeout=self.config.settings.timeout,
                concurrency=self.config.settings.concurrency,
                thresholds=self.config.thresholds,
            )
            response_data = [
                {
                    "url": r.target,
                    "hostname": r.hostname,
                    "port": r.port,
                    "expiresAt": _iso8601(r.expires_at),
                    "daysRemaining": r.days_remaining,
                    "status": r.status,
                    "reasonCode": r.error_reason.value if r.error_reason else None,
                }
                for r in results
            ]
            self._send_json(200, response_data)
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path in ("/api/monitors", "/api/monitors/"):
            try:
                length = int(self.headers.get("Content-Length", 0))
                raw_data = self.rfile.read(length)
                payload = json.loads(raw_data.decode("utf-8"))
                url = payload.get("url")
                if not url or not isinstance(url, str):
                    self._send_json(400, {"error": "missing 'url' field"})
                    return
                spec = TargetSpec("url", url)
                if spec not in self.dynamic_targets:
                    self.dynamic_targets.append(spec)
                self._send_json(201, {"message": f"added monitor target: {url}", "url": url})
            except Exception as exc:
                self._send_json(400, {"error": f"invalid request: {exc}"})
        else:
            self._send_json(404, {"error": "not found"})


def create_api_server(config: AppConfig, host: str = "127.0.0.1", port: int = 8000) -> HTTPServer:
    handler_cls = type("ConfiguredMonitorApiHandler", (MonitorApiHandler,), {"config": config, "dynamic_targets": []})
    return HTTPServer((host, port), handler_cls)
