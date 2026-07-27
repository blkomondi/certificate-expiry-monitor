"""A small Slack-style JSON webhook notifier."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC
from urllib.request import Request, urlopen

from ..models import CheckResult


def _iso8601(value: object) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")  # type: ignore[union-attr]


@dataclass(frozen=True, slots=True)
class WebhookNotifier:
    """POST a deliberately small, non-secret-bearing JSON alert payload."""

    url: str
    timeout: float = 10.0

    def notify(self, result: CheckResult) -> None:
        certificate = result.certificate
        payload = {
            "target": result.target,
            "severity": result.severity.value,
            "days_remaining": result.days_remaining,
            "expires_at": _iso8601(result.expires_at),
            "fingerprint": certificate.fingerprint if certificate else None,
            "reason_code": result.error_reason.value if result.error_reason else None,
            "message": result.message,
        }
        request = Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(request, timeout=self.timeout) as response:  # nosec B310: user-configured alert endpoint
            if not 200 <= response.status < 300:
                raise OSError(f"webhook returned HTTP {response.status}")
