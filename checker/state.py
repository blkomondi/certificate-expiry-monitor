"""Portable JSON persistence for alert deduplication and suppressions."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from .models import CheckResult, Severity

_RANKS = {
    Severity.OK: 0,
    Severity.WARNING: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
    Severity.EXPIRED: 4,
}


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("suppression expiry must include a timezone")
    return parsed.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class Suppression:
    target: str
    fingerprint: str | None = None
    expires_at: datetime | None = None
    reason: str | None = None

    def matches(self, result: CheckResult, now: datetime) -> bool:
        if self.target != result.target:
            return False
        if self.expires_at is not None and self.expires_at <= now:
            return False
        actual = result.certificate.fingerprint if result.certificate else None
        return self.fingerprint is None or self.fingerprint == actual


@dataclass(slots=True)
class AlertState:
    """State keyed by fingerprint + target; suppressions affect alerts only."""

    alerted: dict[str, str] = field(default_factory=dict)
    suppressions: list[Suppression] = field(default_factory=list)

    @staticmethod
    def key(result: CheckResult) -> str | None:
        if result.certificate is None:
            return None
        return f"{result.target}\x1f{result.certificate.fingerprint}"

    def is_suppressed(self, result: CheckResult, now: datetime) -> bool:
        return any(rule.matches(result, now) for rule in self.suppressions)

    def should_notify(self, result: CheckResult, now: datetime, *, force: bool = False) -> bool:
        if result.severity not in _RANKS or result.severity is Severity.OK:
            return False
        if self.is_suppressed(result, now):
            return False
        if force:
            return True
        key = self.key(result)
        if key is None:
            return False
        prior = self.alerted.get(key)
        return prior is None or _RANKS[result.severity] > _RANKS.get(Severity(prior), -1)

    def record_notified(self, result: CheckResult) -> None:
        key = self.key(result)
        if key is not None and result.severity in _RANKS:
            prior = self.alerted.get(key)
            if prior is None or _RANKS[result.severity] > _RANKS.get(Severity(prior), -1):
                self.alerted[key] = result.severity.value

    def suppress(self, rule: Suppression) -> None:
        self.suppressions = [
            existing
            for existing in self.suppressions
            if not (existing.target == rule.target and existing.fingerprint == rule.fingerprint)
        ]
        self.suppressions.append(rule)

    def unsuppress(self, target: str, fingerprint: str | None = None) -> bool:
        before = len(self.suppressions)
        self.suppressions = [
            rule
            for rule in self.suppressions
            if not (rule.target == target and (fingerprint is None or rule.fingerprint == fingerprint))
        ]
        return len(self.suppressions) != before


class JsonStateStore:
    """Load and atomically save small JSON state files."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load(self) -> AlertState:
        if not self.path.exists():
            return AlertState()
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        suppressions = [
            Suppression(
                target=item["target"],
                fingerprint=item.get("fingerprint"),
                expires_at=_parse_time(item.get("expires_at")),
                reason=item.get("reason"),
            )
            for item in raw.get("suppressions", [])
        ]
        return AlertState(alerted=dict(raw.get("alerted", {})), suppressions=suppressions)

    def save(self, state: AlertState) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "alerted": state.alerted,
            "suppressions": [
                {
                    "target": item.target,
                    "fingerprint": item.fingerprint,
                    "expires_at": item.expires_at.astimezone(UTC).isoformat().replace("+00:00", "Z") if item.expires_at else None,
                    "reason": item.reason,
                }
                for item in state.suppressions
            ],
        }
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(temporary, self.path)
