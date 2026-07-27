from __future__ import annotations

import email
import pytest

from checker.evaluation import evaluate_certificate
from checker.models import Thresholds
from checker.notification.email import EmailNotifier
from checker.parsing import parse_certificate_bytes
from tests.conftest import FakeClock, make_certificate


def _warning_result(now):
    info = parse_certificate_bytes(make_certificate(now, days=25), target="https://example.com/api", source="url")
    return evaluate_certificate(info, Thresholds(), FakeClock(now))


def test_email_notifier_starttls(monkeypatch, now) -> None:
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

        def starttls(self):
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
        subject_prefix="[Custom Alert]",
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
    assert parsed_msg["Subject"] == "[Custom Alert] [WARNING] Target: https://example.com/api"
    payload_text = parsed_msg.get_payload(decode=True).decode("utf-8")
    assert "Days Remaining: 25" in payload_text
    assert "Target: https://example.com/api" in payload_text


def test_email_notifier_ssl(monkeypatch, now) -> None:
    sent_messages: list[dict[str, object]] = []

    class FakeSMTPSSL:
        def __init__(self, host: str, port: int, timeout: float):
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

    notifier.notify(_warning_result(now))
    assert len(sent_messages) == 1
