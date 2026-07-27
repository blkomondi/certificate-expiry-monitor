from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from checker.models import CheckResult


@dataclass
class FakeClock:
    value: datetime

    def __call__(self) -> datetime:
        return self.value


@dataclass
class FakeNotifier:
    notifications: list[CheckResult]

    def __init__(self) -> None:
        self.notifications = []

    def notify(self, result: CheckResult) -> None:
        self.notifications.append(result)


@pytest.fixture
def now() -> datetime:
    return datetime(2032, 1, 1, 12, 0, tzinfo=UTC)


def make_certificate(
    now: datetime,
    *,
    days: int = 45,
    not_before_offset: timedelta = timedelta(days=-1),
    common_name: str | None = "monitor.test",
    san: bool = True,
) -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attributes = [x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Certificate Monitor Tests")]
    if common_name:
        attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    subject = issuer = x509.Name(attributes)
    not_before = now + not_before_offset
    not_after = now + timedelta(days=days)
    if not_before >= not_after:
        not_before = not_after - timedelta(days=1)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName("monitor.test")]), critical=False)
    certificate = builder.sign(key, hashes.SHA256())
    return certificate.public_bytes(serialization.Encoding.PEM)


@pytest.fixture
def certificate_bytes(now: datetime) -> bytes:
    return make_certificate(now)
