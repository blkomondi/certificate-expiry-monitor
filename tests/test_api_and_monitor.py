from __future__ import annotations

import json
import threading
from urllib.request import Request, urlopen

from checker.api import create_api_server
from checker.cli import main, _run_monitor_loop
from checker.config import AppConfig, Settings, TargetSpec
from checker.state import JsonStateStore


def test_api_server_get_and_post(tmp_path, now, monkeypatch) -> None:
    import checker.service as service
    monkeypatch.setattr(service, "utc_now", lambda: now)

    cert_path = tmp_path / "test_cert.pem"
    from tests.conftest import make_certificate
    cert_path.write_bytes(make_certificate(now, days=15))

    config = AppConfig(
        settings=Settings(state_file=tmp_path / "state.json"),
        targets=(TargetSpec("file", str(cert_path)),),
    )

    server = create_api_server(config, host="127.0.0.1", port=8989)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # GET /api/monitors
        with urlopen("http://127.0.0.1:8989/api/monitors", timeout=5) as response:
            assert response.status == 200
            data = json.loads(response.read().decode("utf-8"))
            assert len(data) == 1
            assert data[0]["daysRemaining"] == 15
            assert data[0]["status"] == "EXPIRING_SOON"
            assert data[0]["reasonCode"] is None

        # POST /api/monitors
        req = Request(
            "http://127.0.0.1:8989/api/monitors",
            data=json.dumps({"url": "https://example.invalid"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=5) as response:
            assert response.status == 201
            res_data = json.loads(response.read().decode("utf-8"))
            assert res_data["url"] == "https://example.invalid"
    finally:
        server.shutdown()
        server.server_close()


def test_run_monitor_loop_once(tmp_path) -> None:
    state_file = tmp_path / "state.json"
    store = JsonStateStore(state_file)
    config = AppConfig(settings=Settings(state_file=state_file))
    code = _run_monitor_loop(config, store, interval=1, once=True)
    assert code == 0


def test_serve_accepts_host_flag(monkeypatch) -> None:
    import checker.cli as cli_module

    captured: dict[str, object] = {}

    class FakeServer:
        def serve_forever(self) -> None:
            raise KeyboardInterrupt

        def server_close(self) -> None:
            pass

    def fake_create_api_server(config, host="127.0.0.1", port=8000):
        captured["host"] = host
        captured["port"] = port
        return FakeServer()

    monkeypatch.setattr(cli_module, "create_api_server", fake_create_api_server)
    code = cli_module.main(["serve", "--host", "0.0.0.0", "--port", "9000"])
    assert code == 0
    assert captured == {"host": "0.0.0.0", "port": 9000}
