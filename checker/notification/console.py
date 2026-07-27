"""Human-readable console notification channel."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import TextIO

from ..models import CheckResult, Severity


@dataclass(slots=True)
class ConsoleNotifier:
    """Write notifications to stderr so structured results remain clean stdout."""

    stream: TextIO = sys.stderr

    def notify(self, result: CheckResult) -> None:
        if result.severity is Severity.EXPIRED and result.days_remaining is not None:
            text = f"expired {-result.days_remaining} days ago"
        elif result.days_remaining is not None:
            text = f"expires in {result.days_remaining} days"
        else:
            text = result.message
        print(f"[{result.severity.value}] {result.target} {text}", file=self.stream)
