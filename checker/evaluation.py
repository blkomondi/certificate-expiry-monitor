"""Pure, deterministic certificate evaluation."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Callable

from .models import CertInfo, CheckResult, ErrorReason, Severity, Thresholds


def utc_now() -> datetime:
    """Return an aware current UTC timestamp for I/O orchestration only."""

    return datetime.now(UTC)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("certificate datetimes must be timezone-aware")
    return value.astimezone(UTC)


def calculate_days_remaining(not_after: datetime, now: datetime) -> int:
    """Return floor((not_after - now) / one day), including negative values."""

    return ( _utc(not_after) - _utc(now) ) // timedelta(days=1)


def severity_for_days(days_remaining: int, thresholds: Thresholds) -> Severity:
    """Map an exact whole-day remaining value to a configured tier."""

    if days_remaining < 0:
        return Severity.EXPIRED
    if days_remaining <= thresholds.critical_days:
        return Severity.CRITICAL
    if days_remaining <= thresholds.high_days:
        return Severity.HIGH
    if days_remaining <= thresholds.warning_days:
        return Severity.WARNING
    return Severity.OK


def evaluate_certificate(
    certificate: CertInfo,
    thresholds: Thresholds,
    now: Callable[[], datetime] = utc_now,
) -> CheckResult:
    """Evaluate a parsed certificate without I/O, state access, or side effects."""

    current = _utc(now())
    not_before = _utc(certificate.not_before)
    days = calculate_days_remaining(certificate.not_after, current)
    future = not_before > current
    evaluated = replace(certificate, days_remaining=days, not_yet_valid=future)

    if future:
        return CheckResult(
            target=certificate.target,
            severity=Severity.CRITICAL,
            certificate=evaluated,
            error_reason=None,
            message="certificate is not yet valid",
        )
    severity = severity_for_days(days, thresholds)
    if severity is Severity.EXPIRED:
        message = f"certificate expired {-days} day(s) ago"
    else:
        message = f"certificate expires in {days} day(s)"
    return CheckResult(certificate.target, severity, evaluated, None, message)


def error_result(target: str, reason: ErrorReason, message: str) -> CheckResult:
    """Build a first-class per-target error outcome."""

    return CheckResult(target, Severity.ERROR, None, reason, message)
