from __future__ import annotations

import email
import pytest

from checker.evaluation import error_result, evaluate_certificate
from checker.models import ErrorReason, Thresholds
from checker.notification.email import EmailNotifier
from checker.parsing import parse_certificate_bytes
from tests.conftest import FakeClock, make_certificate


def _warning_result(now):
    info = parse_certificate_bytes(make_certificate(now, days=14), target="https://example.com", source="url")
    return evaluate_certificate(info, Thresholds(), FakeClock(now))


def _expired_result(now):
    info = parse_certificate_bytes(make_certificate(now, days=-5), target="https://example.com", source="url")
    return evaluate_certificate(info, Thresholds(), FakeClock(now))


def test_email_notifier_starttls_and_content(monkeypatch, now) -> None:
    sent_messages: list[dict[str, object]] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float):
            self.host = host
            self.port = port
            self.timeout = timeout
            self.started_tls = False
            self.logged_in = False

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self, *, context=None):
            self.started_tls = True

        def login(self, user, password):
            self.logged_in = True

        def sendmail(self, from_addr, to_addrs, msg_str):
            sent_messages.append({
                "from": from_addr,
                "to": to_addrs,
                "msg": msg_str,
                "started_tls": self.started_tls,
                "logged_in": self.logged_in,
            })

    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    notifier = EmailNotifier(
        smtp_host="smtp.example.test",
        smtp_port=587,
        username="user@example.test",
        password="secretpassword",
        from_addr="alerts@example.test",
        to_addrs=("admin@example.test", "dev@example.test"),
    )

    result = _warning_result(now)
    notifier.notify(result)

    assert len(sent_messages) == 1
    msg_data = sent_messages[0]
    assert msg_data["from"] == "alerts@example.test"
    assert msg_data["to"] == ["admin@example.test", "dev@example.test"]
    assert msg_data["started_tls"] is True
    assert msg_data["logged_in"] is True

    parsed_msg = email.message_from_string(str(msg_data["msg"]))
    assert parsed_msg["Subject"] == "TLS Certificate Expiry Alert: example.com"
    payload_text = parsed_msg.get_payload(decode=True).decode("utf-8")
    # Terminal table output included
    assert "TARGET" in payload_text
    assert "STATUS" in payload_text
    assert "DAYS" in payload_text
    assert "EXPIRES" in payload_text
    assert "CHAIN" in payload_text
    # Detail fields
    assert "URL: https://example.com" in payload_text
    assert "Hostname: example.com" in payload_text
    assert "Port: 443" in payload_text
    assert "Remaining: 14 days" in payload_text
    assert "Status: EXPIRING_SOON" in payload_text



def test_email_notifier_urgent_expired(monkeypatch, now) -> None:
    sent_messages: list[dict[str, object]] = []

    class FakeSMTPSSL:
        def __init__(self, host: str, port: int, *, timeout: float, context=None):
            self.host = host
            self.port = port
            self.timeout = timeout

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def login(self, user, password):
            pass

        def sendmail(self, from_addr, to_addrs, msg_str):
            sent_messages.append({"from": from_addr, "to": to_addrs, "msg": msg_str})

    import smtplib
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTPSSL)

    notifier = EmailNotifier(
        smtp_host="smtp.example.test",
        smtp_port=465,
        ssl=True,
        from_addr="alerts@example.test",
        to_addrs=("admin@example.test",),
    )

    notifier.notify(_expired_result(now))
    assert len(sent_messages) == 1
    parsed_msg = email.message_from_string(str(sent_messages[0]["msg"]))
    assert "URGENT: TLS Certificate Expired: example.com" in parsed_msg["Subject"]
    payload_text = parsed_msg.get_payload(decode=True).decode("utf-8")
    assert "Status: EXPIRED" in payload_text
    assert "This certificate has expired!" in payload_text


def test_email_notifier_error_uses_accurate_copy(monkeypatch) -> None:
    sent_messages: list[dict[str, object]] = []

    class FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def starttls(self, *, context=None):
            pass

        def login(self, user, password):
            pass

        def sendmail(self, from_addr, to_addrs, msg_str):
            sent_messages.append({"msg": msg_str})

    import smtplib

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)

    notifier = EmailNotifier(
        smtp_host="smtp.example.test",
        use_tls=False,
        starttls=False,
        from_addr="alerts@example.test",
        to_addrs=("admin@example.test",),
    )

    result = error_result(
        "https://example.com",
        ErrorReason.TLS_HANDSHAKE_RESET,
        "TLS handshake was reset by the server; the server may be blocking automated (non-browser) TLS clients",
    )
    notifier.notify(result)

    assert len(sent_messages) == 1
    parsed_msg = email.message_from_string(str(sent_messages[0]["msg"]))
    assert "TLS Certificate Monitoring Error: example.com" in parsed_msg["Subject"]
    payload_text = parsed_msg.get_payload(decode=True).decode("utf-8")
    assert "TLS Certificate Monitoring Error" in payload_text
    assert "The certificate could not be checked" in payload_text
    assert "blocking automated" in payload_text
    assert "Status: TLS_ERROR" in payload_text
    assert "approaching its expiry date" not in payload_text


def test_email_notifier_smtp_failure(monkeypatch, now) -> None:
    class FailingSMTP:
        def __init__(self, host: str, port: int, timeout: float):
            pass

        def __enter__(self):
            raise OSError("SMTP connection failed")

        def __exit__(self, *args):
            return False

    import smtplib
    monkeypatch.setattr(smtplib, "SMTP", FailingSMTP)

    notifier = EmailNotifier(
        smtp_host="smtp.failing.test",
        from_addr="alerts@example.test",
        to_addrs=("admin@example.test",),
    )

    with pytest.raises(OSError, match="SMTP connection failed"):
        notifier.notify(_warning_result(now))
