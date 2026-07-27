from __future__ import annotations

from checker.evaluation import evaluate_certificate
from checker.models import Severity, Thresholds
from checker.parsing import parse_certificate_bytes
from checker.state import AlertState, JsonStateStore, Suppression
from tests.conftest import FakeClock, make_certificate


def _result(now, days: int):
    cert = parse_certificate_bytes(make_certificate(now, days=days), target="api.test:443", source="test")
    return evaluate_certificate(cert, Thresholds(), FakeClock(now))


def test_new_tier_notifies_but_duplicate_does_not(now) -> None:
    state = AlertState()
    warning = _result(now, 30)
    assert state.should_notify(warning, now)
    state.record_notified(warning)
    assert not state.should_notify(warning, now)
    high = _result(now, 15)
    # New certificate fingerprints form a different alert key, by design.
    assert state.should_notify(high, now)


def test_same_fingerprint_escalation_and_force(now) -> None:
    warning = _result(now, 30)
    state = AlertState()
    state.record_notified(warning)
    assert state.should_notify(warning, now, force=True)
    critical = warning.__class__(
        target=warning.target,
        severity=Severity.CRITICAL,
        certificate=warning.certificate,
        error_reason=None,
        message="escalated",
    )
    assert state.should_notify(critical, now)
    state.record_notified(critical)
    assert not state.should_notify(critical, now)


def test_suppression_only_affects_notifications(now) -> None:
    result = _result(now, 5)
    state = AlertState(suppressions=[Suppression(target=result.target, reason="maintenance")])
    assert result.severity is Severity.CRITICAL
    assert not state.should_notify(result, now)
    assert state.unsuppress(result.target)
    assert state.should_notify(result, now)


def test_json_state_round_trip(tmp_path, now) -> None:
    store = JsonStateStore(tmp_path / "state.json")
    state = AlertState(suppressions=[Suppression("api.test:443", expires_at=now, reason="test")])
    store.save(state)
    restored = store.load()
    assert restored.suppressions[0].reason == "test"
