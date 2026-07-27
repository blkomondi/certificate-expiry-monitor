"""Tests for SendGrid notification channel."""

from __future__ import annotations

import pytest

from checker.evaluation import evaluate_certificate
from checker.models import Thresholds
from checker.notification.sendgrid import SendGridNotifier, _build_alert_content
from checker.parsing import parse_certificate_bytes
from tests.conftest import FakeClock, make_certificate


def _warning_result(now):
    info = parse_certificate_bytes(make_certificate(now, days=14), target="https://example.com", source="url")
    return evaluate_certificate(info, Thresholds(), FakeClock(now))


def _expired_result(now):
    info = parse_certificate_bytes(make_certificate(now, days=-5), target="https://example.com", source="url")
    return evaluate_certificate(info, Thresholds(), FakeClock(now))


def test_build_alert_content_warning(now) -> None:
    result = _warning_result(now)
    subject, body = _build_alert_content(result)

    assert "Certificate Expiry Alert" in subject
    assert "example.com" in subject
    # Terminal table output included
    assert "TARGET" in body
    assert "STATUS" in body
    assert "DAYS" in body
    assert "EXPIRES" in body
    assert "CHAIN" in body
    # Detail fields
    assert "URL: https://example.com" in body
    assert "Hostname: example.com" in body
    assert "Port: 443" in body
    assert "Remaining: 14 days" in body
    assert "Status: EXPIRING_SOON" in body


def test_build_alert_content_expired(now) -> None:
    result = _expired_result(now)
    subject, body = _build_alert_content(result)

    assert "URGENT" in subject
    assert "Certificate Expired" in subject
    assert "This certificate has expired!" in body
    assert "Status: EXPIRED" in body
    # Terminal table output includes negative days
    assert "-5" in body


def test_build_alert_content_subject_prefix(now) -> None:
    result = _warning_result(now)
    notifier = SendGridNotifier(
        api_key="SG.test_key",
        from_addr="alerts@example.test",
        to_addrs=("admin@example.test",),
        subject_prefix="[CEM]",
    )

    subject, body = _build_alert_content(result)
    expected_subject = f"[CEM] {subject}"
    assert notifier.subject_prefix
    assert expected_subject.startswith("[CEM]")


def test_sendgrid_notifier_sends_successfully(monkeypatch, now) -> None:
    sent_messages: list[dict[str, object]] = []

    class FakeResponse:
        status_code = 202

    class FakeSendGridClient:
        def __init__(self, api_key: str):
            self.api_key = api_key

        def send(self, message):
            sent_messages.append({
                "api_key": self.api_key,
                "message": message,
            })
            return FakeResponse()

    import checker.notification.sendgrid as sendgrid_module
    monkeypatch.setattr(sendgrid_module, "SendGridAPIClient", FakeSendGridClient)

    notifier = SendGridNotifier(
        api_key="SG.test_key_123",
        from_addr="alerts@example.test",
        to_addrs=("admin@example.test", "dev@example.test"),
    )

    result = _warning_result(now)
    notifier.notify(result)

    assert len(sent_messages) == 1
    msg_data = sent_messages[0]
    assert msg_data["api_key"] == "SG.test_key_123"
    message = msg_data["message"]
    assert message.from_email.email == "alerts@example.test"
    # Recipients are stored as dicts in personalizations via the sendgrid Mail helper
    tos = message.personalizations[0].tos if message.personalizations else []
    to_emails = [t["email"] for t in tos]
    assert "admin@example.test" in to_emails
    assert "dev@example.test" in to_emails
    assert "URL: https://example.com" in message.contents[0].content


def test_sendgrid_notifier_empty_recipients_skips(monkeypatch, now) -> None:
    sent_messages: list[dict[str, object]] = []

    class FakeSendGridClient:
        def __init__(self, api_key: str):
            pass

        def send(self, message):
            sent_messages.append(message)
            return type("Resp", (), {"status_code": 202})()

    import checker.notification.sendgrid as sendgrid_module
    monkeypatch.setattr(sendgrid_module, "SendGridAPIClient", FakeSendGridClient)

    notifier = SendGridNotifier(
        api_key="SG.test_key",
        from_addr="alerts@example.test",
        to_addrs=(),
    )

    notifier.notify(_warning_result(now))
    assert len(sent_messages) == 0


def test_sendgrid_notifier_http_error(monkeypatch, now) -> None:
    class FakeResponse:
        status_code = 401

    class FakeSendGridClient:
        def __init__(self, api_key: str):
            pass

        def send(self, message):
            return FakeResponse()

    import checker.notification.sendgrid as sendgrid_module
    monkeypatch.setattr(sendgrid_module, "SendGridAPIClient", FakeSendGridClient)

    notifier = SendGridNotifier(
        api_key="SG.invalid_key",
        from_addr="alerts@example.test",
        to_addrs=("admin@example.test",),
    )

    with pytest.raises(OSError, match="SendGrid API returned HTTP 401"):
        notifier.notify(_warning_result(now))


def test_sendgrid_notifier_expired_alert(monkeypatch, now) -> None:
    sent_messages: list[dict[str, object]] = []

    class FakeResponse:
        status_code = 202

    class FakeSendGridClient:
        def __init__(self, api_key: str):
            pass

        def send(self, message):
            sent_messages.append(message)
            return FakeResponse()

    import checker.notification.sendgrid as sendgrid_module
    monkeypatch.setattr(sendgrid_module, "SendGridAPIClient", FakeSendGridClient)

    notifier = SendGridNotifier(
        api_key="SG.test_key",
        from_addr="alerts@example.test",
        to_addrs=("admin@example.test",),
    )

    result = _expired_result(now)
    notifier.notify(result)

    assert len(sent_messages) == 1
    msg = sent_messages[0]
    assert "URGENT" in str(msg.subject)
    assert "expired" in msg.contents[0].content.lower()
