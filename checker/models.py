"""Typed domain objects shared by all layers of the monitor."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class Severity(str, Enum):
    """The certificate health tiers, ordered from least to most severe."""

    OK = "OK"
    WARNING = "WARNING"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    EXPIRED = "EXPIRED"
    ERROR = "ERROR"


class ErrorReason(str, Enum):
    """Stable reason codes suitable for automation."""

    DNS_FAILURE = "DNS_FAILURE"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    TIMEOUT = "TIMEOUT"
    TLS_HANDSHAKE_FAILURE = "TLS_HANDSHAKE_FAILURE"
    UNPARSEABLE_FILE = "UNPARSEABLE_FILE"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    CERTIFICATE_RETRIEVAL_FAILURE = "CERTIFICATE_RETRIEVAL_FAILURE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class Thresholds:
    """Centralized expiry thresholds measured in whole days."""

    warning_days: int = 30
    high_days: int = 15
    critical_days: int = 5

    def __post_init__(self) -> None:
        if not (0 <= self.critical_days <= self.high_days <= self.warning_days):
            raise ValueError("thresholds must satisfy 0 <= critical <= high <= warning")


@dataclass(frozen=True, slots=True)
class CertInfo:
    """Metadata extracted from one leaf certificate.

    Time-dependent fields are populated by the pure evaluation layer rather
    than by parsers or certificate sources.
    """

    target: str
    source: str
    fingerprint: str
    not_before: datetime
    not_after: datetime
    subject: str
    subject_cn: str | None
    san: tuple[str, ...]
    issuer: str
    serial: str
    signature_algorithm: str | None
    key_size: int | None
    chain_valid: bool | None
    days_remaining: int | None = None
    not_yet_valid: bool = False


@dataclass(frozen=True, slots=True)
class CheckResult:
    """One target's final outcome, including successful and failed checks."""

    target: str
    severity: Severity
    certificate: CertInfo | None
    error_reason: ErrorReason | None
    message: str

    @property
    def days_remaining(self) -> int | None:
        return self.certificate.days_remaining if self.certificate else None

    @property
    def expires_at(self) -> datetime | None:
        return self.certificate.not_after if self.certificate else None


@dataclass(frozen=True, slots=True)
class Notification:
    """A decision to communicate a result through one or more notifiers."""

    result: CheckResult
    forced: bool = False
