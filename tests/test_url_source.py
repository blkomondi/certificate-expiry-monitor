from __future__ import annotations

import pytest

from checker.evaluation import evaluate_certificate
from checker.models import CertInfo, ErrorReason, Thresholds
from checker.parsing import parse_certificate_bytes
from checker.service import dispatch_alerts, run_checks
from checker.config import TargetSpec
from checker.sources.url import URLCertificateSource, parse_url_target
from checker.state import AlertState
from tests.conftest import FakeClock, FakeNotifier, make_certificate


def test_parse_url_target_valid_cases() -> None:
    assert parse_url_target("https://example.com/api/v1") == ("example.com", 443)
    assert parse_url_target("https://example.com:8443/health") == ("example.com", 8443)
    assert parse_url_target("example.com/health") == ("example.com", 443)
    assert parse_url_target("https://[2001:db8::1]:8443/status") == ("2001:db8::1", 8443)


def test_parse_url_target_invalid_cases() -> None:
    with pytest.raises(ValueError, match="HTTP scheme does not use SSL/TLS encryption"):
        parse_url_target("http://example.com")

    with pytest.raises(ValueError, match="unsupported URL scheme"):
        parse_url_target("ftp://example.com")

    with pytest.raises(ValueError, match="URL contains no valid hostname"):
        parse_url_target("https://")


def test_url_source_retargeting_and_sni(now) -> None:
    cert_bytes = make_certificate(now, days=60)
    info = parse_certificate_bytes(cert_bytes, target="example.com:8443", source="tls", chain_valid=False)

    captured_target = []

    class FakeTLSSource:
        def check(self, target: str, *, timeout: float):
            captured_target.append(target)
            return [info]

    url_source = URLCertificateSource(tls_source=FakeTLSSource())  # type: ignore[arg-type]
    outcomes = url_source.check("https://example.com:8443/api/v1", timeout=10.0)

    assert captured_target == ["example.com:8443"]
    assert len(outcomes) == 1
    result_info = outcomes[0]
    assert isinstance(result_info, CertInfo)
    assert result_info.target == "https://example.com:8443/api/v1"
    assert result_info.hostname == "example.com"
    assert result_info.port == 8443
    assert result_info.source == "url"
    assert result_info.chain_valid is False  # Self-signed/invalid chain still inspectable


def test_multiple_url_checks_concurrency(now) -> None:
    cert1 = make_certificate(now, days=20)
    cert2 = make_certificate(now, days=5)

    info1 = parse_certificate_bytes(cert1, target="https://one.example.com", source="url")
    info2 = parse_certificate_bytes(cert2, target="https://two.example.com", source="url")

    class MockURLSource:
        def check(self, target: str, *, timeout: float):
            if "one.example.com" in target:
                return [info1]
            return [info2]

    targets = [
        TargetSpec("url", "https://one.example.com"),
        TargetSpec("url", "https://two.example.com"),
    ]

    results = run_checks(
        targets,
        timeout=5.0,
        concurrency=2,
        thresholds=Thresholds(),
        now=lambda: now,
        sources={"url": MockURLSource()},  # type: ignore[arg-type]
    )

    assert len(results) == 2
    assert results[0].target == "https://one.example.com"
    assert results[0].status == "EXPIRING_SOON"
    assert results[1].target == "https://two.example.com"
    assert results[1].status == "EXPIRING_SOON"


def test_certificate_renewal_resets_alert_state(now) -> None:
    cert_old = make_certificate(now, days=10)
    cert_new = make_certificate(now, days=90)

    res_old = evaluate_certificate(
        parse_certificate_bytes(cert_old, target="https://example.com", source="url"),
        Thresholds(),
        FakeClock(now),
    )
    res_new = evaluate_certificate(
        parse_certificate_bytes(cert_new, target="https://example.com", source="url"),
        Thresholds(),
        FakeClock(now),
    )

    state = AlertState()
    notifier = FakeNotifier()

    # Old cert fires alert
    dispatch_alerts([res_old], state=state, notifiers=[notifier], now=now)
    assert len(notifier.notifications) == 1

    # Same old cert does not fire duplicate alert
    dispatch_alerts([res_old], state=state, notifiers=[notifier], now=now)
    assert len(notifier.notifications) == 1

    # Renewed cert (different fingerprint & expiry) triggers new alert cycle when it eventually expires
    res_renewed_expiring = evaluate_certificate(
        parse_certificate_bytes(cert_new, target="https://example.com", source="url"),
        Thresholds(warning_days=100),
        FakeClock(now),
    )
    dispatch_alerts([res_renewed_expiring], state=state, notifiers=[notifier], now=now)
    assert len(notifier.notifications) == 2
