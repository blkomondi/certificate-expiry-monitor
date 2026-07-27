"""Result serializers for table, JSON, and Prometheus exposition formats."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Iterable

from .models import CheckResult, Severity

_SEVERITY_VALUES = {
    Severity.OK: 0,
    Severity.WARNING: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
    Severity.EXPIRED: 4,
    Severity.ERROR: -1,
}


def _iso(value: datetime | None) -> str | None:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z") if value else None


def result_dict(result: CheckResult) -> dict[str, object]:
    certificate = result.certificate
    return {
        "target": result.target,
        "status": result.severity.value,
        "reason_code": result.error_reason.value if result.error_reason else None,
        "message": result.message,
        "days_remaining": result.days_remaining,
        "expires_at": _iso(result.expires_at),
        "certificate": (
            {
                "source": certificate.source,
                "fingerprint": certificate.fingerprint,
                "not_before": _iso(certificate.not_before),
                "not_after": _iso(certificate.not_after),
                "subject": certificate.subject,
                "subject_cn": certificate.subject_cn,
                "san": list(certificate.san),
                "issuer": certificate.issuer,
                "serial": certificate.serial,
                "signature_algorithm": certificate.signature_algorithm,
                "key_size": certificate.key_size,
                "chain_valid": certificate.chain_valid,
                "not_yet_valid": certificate.not_yet_valid,
            }
            if certificate
            else None
        ),
    }


def to_json(results: Iterable[CheckResult]) -> str:
    return json.dumps([result_dict(result) for result in results], indent=2, sort_keys=True) + "\n"


def to_table(results: Iterable[CheckResult]) -> str:
    rows = list(results)
    headings = ("TARGET", "STATUS", "DAYS", "EXPIRES", "CHAIN")
    values = [
        (
            result.target,
            result.severity.value,
            "" if result.days_remaining is None else str(result.days_remaining),
            _iso(result.expires_at) or "",
            "" if result.certificate is None or result.certificate.chain_valid is None else str(result.certificate.chain_valid).lower(),
        )
        for result in rows
    ]
    widths = [len(heading) for heading in headings]
    for row in values:
        widths = [max(width, len(value)) for width, value in zip(widths, row)]
    line = "  ".join(heading.ljust(width) for heading, width in zip(headings, widths))
    body = ["  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip() for row in values]
    return "\n".join([line, *body]) + "\n"


def _escape_label(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def to_prometheus(results: Iterable[CheckResult]) -> str:
    lines = [
        "# HELP certificate_days_remaining Whole UTC days until certificate expiry.",
        "# TYPE certificate_days_remaining gauge",
        "# HELP certificate_severity Certificate severity: OK=0, WARNING=1, HIGH=2, CRITICAL=3, EXPIRED=4, ERROR=-1.",
        "# TYPE certificate_severity gauge",
        "# HELP certificate_chain_valid Whether standard TLS validation succeeded (1/0).",
        "# TYPE certificate_chain_valid gauge",
        "# HELP certificate_check_error Whether checking this target produced an error (1/0).",
        "# TYPE certificate_check_error gauge",
    ]
    for result in results:
        labels = f'target="{_escape_label(result.target)}"'
        lines.append(f"certificate_severity{{{labels}}} {_SEVERITY_VALUES[result.severity]}")
        lines.append(f"certificate_check_error{{{labels}}} {1 if result.severity is Severity.ERROR else 0}")
        if result.days_remaining is not None:
            lines.append(f"certificate_days_remaining{{{labels}}} {result.days_remaining}")
        if result.certificate and result.certificate.chain_valid is not None:
            lines.append(f"certificate_chain_valid{{{labels}}} {1 if result.certificate.chain_valid else 0}")
    return "\n".join(lines) + "\n"
