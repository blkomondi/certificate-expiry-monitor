"""Notifier contract used by the orchestration layer."""

from __future__ import annotations

from typing import Protocol

from ..models import CheckResult


class Notifier(Protocol):
    """A pluggable output channel for an already-decided alert."""

    def notify(self, result: CheckResult) -> None:
        """Deliver one notification or raise an I/O error."""
        ...
