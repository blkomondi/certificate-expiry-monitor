"""Extensible source contract."""

from __future__ import annotations

from typing import Protocol, TypeAlias

from ..models import CertInfo, CheckResult

SourceOutcome: TypeAlias = CertInfo | CheckResult


class CertificateSource(Protocol):
    """A source that discovers one or more certificates for a target string."""

    def check(self, target: str, *, timeout: float) -> list[SourceOutcome]:
        """Return all outcomes; expected target-level problems are CheckResults."""
        ...
