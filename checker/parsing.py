"""Certificate decoding and metadata extraction, independent of transport."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .models import CertInfo


class CertificateParseError(ValueError):
    """The supplied bytes were expected to be a certificate but were not."""


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _certificate_datetime(certificate: x509.Certificate, name: str) -> datetime:
    aware_name = f"{name}_utc"
    aware_value = getattr(certificate, aware_name, None)
    return _as_utc(aware_value if aware_value is not None else getattr(certificate, name))


def _common_name(certificate: x509.Certificate) -> str | None:
    values = certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return values[0].value if values else None


def _sans(certificate: x509.Certificate) -> tuple[str, ...]:
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return ()
    return tuple(str(getattr(value, "value", value)) for value in extension.value)


def _key_size(certificate: x509.Certificate) -> int | None:
    size = getattr(certificate.public_key(), "key_size", None)
    return size if isinstance(size, int) else None


def _signature_algorithm(certificate: x509.Certificate) -> str | None:
    algorithm = certificate.signature_hash_algorithm
    return algorithm.name if algorithm is not None else None


def parse_certificate_bytes(
    data: bytes,
    *,
    target: str,
    source: str,
    chain_valid: bool | None = None,
) -> CertInfo:
    """Parse one PEM or DER X.509 certificate and return normalized metadata."""

    try:
        if b"-----BEGIN CERTIFICATE-----" in data:
            certificate = x509.load_pem_x509_certificate(data)
        else:
            certificate = x509.load_der_x509_certificate(data)
    except ValueError as exc:
        raise CertificateParseError("certificate data is not valid PEM or DER") from exc

    return CertInfo(
        target=target,
        source=source,
        fingerprint=certificate.fingerprint(hashes.SHA256()).hex(),
        not_before=_certificate_datetime(certificate, "not_valid_before"),
        not_after=_certificate_datetime(certificate, "not_valid_after"),
        subject=certificate.subject.rfc4514_string(),
        subject_cn=_common_name(certificate),
        san=_sans(certificate),
        issuer=certificate.issuer.rfc4514_string(),
        serial=format(certificate.serial_number, "x"),
        signature_algorithm=_signature_algorithm(certificate),
        key_size=_key_size(certificate),
        chain_valid=chain_valid,
    )


def parse_certificate_file(path: Path, *, target: str | None = None) -> CertInfo:
    """Read and parse a certificate file, propagating ordinary read errors."""

    display = target or str(path)
    return parse_certificate_bytes(path.read_bytes(), target=display, source="file")
