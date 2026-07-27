from __future__ import annotations

import pytest

from checker.models import CertInfo, ErrorReason
from checker.sources.url import URLCertificateSource, parse_url_target
from tests.conftest import make_certificate
from checker.parsing import parse_certificate_bytes


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


def test_url_source_retargeting(now) -> None:
    cert_bytes = make_certificate(now, days=60)
    info = parse_certificate_bytes(cert_bytes, target="example.com:443", source="tls")

    class FakeTLSSource:
        def check(self, target: str, *, timeout: float):
            return [info]

    url_source = URLCertificateSource(tls_source=FakeTLSSource())  # type: ignore[arg-type]
    outcomes = url_source.check("https://example.com/api/v1", timeout=10.0)

    assert len(outcomes) == 1
    result_info = outcomes[0]
    assert isinstance(result_info, CertInfo)
    assert result_info.target == "https://example.com/api/v1"
    assert result_info.source == "url"


def test_url_source_invalid_url_handling() -> None:
    url_source = URLCertificateSource()
    outcomes = url_source.check("http://example.com", timeout=10.0)
    assert len(outcomes) == 1
    assert outcomes[0].error_reason is ErrorReason.UNKNOWN
    assert "HTTP scheme" in outcomes[0].message
