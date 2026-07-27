from __future__ import annotations

import json
from datetime import UTC, datetime

from checker.cli import main
from tests.conftest import make_certificate


def test_cli_json_and_prometheus_output(tmp_path, now, capsys) -> None:
    certificate = tmp_path / "cert.pem"
    certificate.write_bytes(make_certificate(datetime.now(UTC), days=90))
    state = tmp_path / "state.json"
    code = main(["--file", str(certificate), "--format", "json", "--state-file", str(state), "--quiet"])
    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out)[0]["status"] == "OK"
    code = main(["--file", str(certificate), "--format", "prometheus", "--state-file", str(state), "--quiet"])
    assert code == 0
    assert "certificate_days_remaining" in capsys.readouterr().out


def test_cli_suppress_and_unsuppress(tmp_path, capsys) -> None:
    state = tmp_path / "state.json"
    assert main(["suppress", "--target", "api.test:443", "--state-file", str(state)]) == 0
    assert main(["unsuppress", "--target", "api.test:443", "--state-file", str(state)]) == 0
    assert "removed suppression" in capsys.readouterr().out
