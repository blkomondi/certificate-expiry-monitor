from __future__ import annotations

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from checker.parsing import parse_certificate_bytes
from tests.conftest import make_certificate


def test_extracts_certificate_metadata(now) -> None:
    info = parse_certificate_bytes(make_certificate(now), target="example:443", source="tls", chain_valid=False)
    assert info.subject_cn == "monitor.test"
    assert "monitor.test" in info.san
    assert info.fingerprint and len(info.fingerprint) == 64
    assert info.key_size == 2048
    assert info.chain_valid is False
    assert info.not_after.tzinfo is not None


def test_handles_absent_cn_and_san(now) -> None:
    info = parse_certificate_bytes(make_certificate(now, common_name=None, san=False), target="test", source="file")
    assert info.subject_cn is None
    assert info.san == ()


def test_der_is_supported(now) -> None:
    pem = make_certificate(now)
    certificate = x509.load_pem_x509_certificate(pem)
    der = certificate.public_bytes(serialization.Encoding.DER)
    assert parse_certificate_bytes(der, target="test", source="file").serial
