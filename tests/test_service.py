from __future__ import annotations

from checker.config import TargetSpec
from checker.evaluation import error_result
from checker.models import ErrorReason, Thresholds
from checker.parsing import parse_certificate_bytes
from checker.service import exit_code, run_checks
from tests.conftest import FakeClock, make_certificate


class Source:
    def __init__(self, outcome):
        self.outcome = outcome

    def check(self, target: str, *, timeout: float):
        return [self.outcome(target)]


def test_one_failing_target_does_not_abort_others(now) -> None:
    source = Source(
        lambda target: error_result(target, ErrorReason.DNS_FAILURE, "dns failed")
        if target == "bad"
        else parse_certificate_bytes(make_certificate(now), target=target, source="fake")
    )
    results = run_checks(
        [TargetSpec("fake", "bad"), TargetSpec("fake", "good")],
        timeout=1,
        concurrency=2,
        thresholds=Thresholds(),
        now=FakeClock(now),
        sources={"fake": source},
    )
    assert [result.target for result in results] == ["bad", "good"]
    assert results[0].error_reason is ErrorReason.DNS_FAILURE
    assert results[1].days_remaining == 45


def test_exit_code_precedence(now) -> None:
    assert exit_code([error_result("bad", ErrorReason.DNS_FAILURE, "bad")]) == 3
    critical = error_result("not-used", ErrorReason.UNKNOWN, "bad")
    from checker.models import CheckResult, Severity

    assert exit_code([critical, CheckResult("x", Severity.WARNING, None, None, "warning")]) == 1
    assert exit_code([CheckResult("x", Severity.EXPIRED, None, None, "expired"), critical]) == 2
