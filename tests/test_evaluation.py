from __future__ import annotations

from datetime import UTC, datetime, timedelta, timezone

import pytest

from checker.evaluation import calculate_days_remaining, evaluate_certificate, severity_for_days
from checker.models import Severity, Thresholds
from checker.parsing import parse_certificate_bytes
from tests.conftest import FakeClock, make_certificate


@pytest.mark.parametrize(
    ("days", "expected"),
    [(45, Severity.OK), (30, Severity.WARNING), (15, Severity.HIGH), (5, Severity.CRITICAL), (1, Severity.CRITICAL), (-1, Severity.EXPIRED)],
)
def test_boundaries_are_exact(now: datetime, days: int, expected: Severity) -> None:
    info = parse_certificate_bytes(make_certificate(now, days=days), target="test", source="test")
    result = evaluate_certificate(info, Thresholds(), FakeClock(now))
    assert result.days_remaining == days
    assert result.severity is expected


def test_fractional_negative_days_are_floored() -> None:
    now = datetime(2032, 1, 2, tzinfo=UTC)
    assert calculate_days_remaining(now - timedelta(seconds=1), now) == -1
    assert calculate_days_remaining(now + timedelta(hours=23, minutes=59), now) == 0


def test_timezone_aware_conversion(now: datetime) -> None:
    plus_three = timezone(timedelta(hours=3))
    assert calculate_days_remaining((now + timedelta(days=30)).astimezone(plus_three), now) == 30


def test_naive_datetime_is_rejected(now: datetime) -> None:
    with pytest.raises(ValueError):
        calculate_days_remaining(now.replace(tzinfo=None), now)


def test_not_yet_valid_is_critical(now: datetime) -> None:
    info = parse_certificate_bytes(
        make_certificate(now, days=45, not_before_offset=timedelta(days=1)), target="test", source="test"
    )
    result = evaluate_certificate(info, Thresholds(), FakeClock(now))
    assert result.severity is Severity.CRITICAL
    assert result.certificate is not None and result.certificate.not_yet_valid


def test_thresholds_are_configurable() -> None:
    thresholds = Thresholds(warning_days=20, high_days=10, critical_days=2)
    assert severity_for_days(20, thresholds) is Severity.WARNING
    assert severity_for_days(10, thresholds) is Severity.HIGH
    assert severity_for_days(2, thresholds) is Severity.CRITICAL
