from __future__ import annotations

import json
from io import StringIO

from checker.evaluation import evaluate_certificate
from checker.models import Thresholds
from checker.notification.console import ConsoleNotifier
from checker.notification.webhook import WebhookNotifier
from checker.parsing import parse_certificate_bytes
from checker.service import dispatch_alerts
from checker.state import AlertState
from tests.conftest import FakeClock, FakeNotifier, make_certificate


def _warning(now):
    info = parse_certificate_bytes(make_certificate(now, days=30), target="api.test:443", source="test")
    return evaluate_certificate(info, Thresholds(), FakeClock(now))


def test_console_notifier_is_readable(now) -> None:
    stream = StringIO()
    ConsoleNotifier(stream).notify(_warning(now))
    assert "[WARNING] api.test:443 expires in 30 days" in stream.getvalue()


def test_dispatch_prevents_duplicate_and_force_bypasses(now) -> None:
    result = _warning(now)
    state = AlertState()
    notifier = FakeNotifier()
    dispatch_alerts([result], state=state, notifiers=[notifier], now=now)
    dispatch_alerts([result], state=state, notifiers=[notifier], now=now)
    assert len(notifier.notifications) == 1
    dispatch_alerts([result], state=state, notifiers=[notifier], now=now, force=True)
    assert len(notifier.notifications) == 2


def test_dry_run_does_not_send_or_write_state(now) -> None:
    result = _warning(now)
    state = AlertState()
    notifier = FakeNotifier()
    dispatch_alerts([result], state=state, notifiers=[notifier], now=now, dry_run=True)
    assert notifier.notifications == []
    assert state.alerted == {}


def test_webhook_payload(monkeypatch, now) -> None:
    captured: dict[str, object] = {}

    class Response:
        status = 204

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def fake_open(request, timeout):
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        return Response()

    import checker.notification.webhook as webhook

    monkeypatch.setattr(webhook, "urlopen", fake_open)
    WebhookNotifier("https://example.invalid/hook").notify(_warning(now))
    assert captured["payload"]["severity"] == "WARNING"
