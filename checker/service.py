"""I/O orchestration: source checks, pure evaluation, and alert dispatch."""

from __future__ import annotations

import logging
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Callable, Iterable

from .config import TargetSpec
from .evaluation import error_result, evaluate_certificate, utc_now
from .models import CheckResult, ErrorReason, Severity, Thresholds
from .notification.base import Notifier
from .sources import CertificateSource, FileCertificateSource, TLSCertificateSource, URLCertificateSource
from .state import AlertState

LOG = logging.getLogger(__name__)


def run_checks(
    targets: Iterable[TargetSpec],
    *,
    timeout: float,
    concurrency: int,
    thresholds: Thresholds,
    now: Callable[[], datetime] = utc_now,
    sources: dict[str, CertificateSource] | None = None,
) -> list[CheckResult]:
    """Check all independent targets concurrently while preserving input order."""

    registry = sources or {
        "tls": TLSCertificateSource(),
        "file": FileCertificateSource(),
        "url": URLCertificateSource(),
    }
    target_list = list(targets)
    current = now()

    def perform(spec: TargetSpec) -> list[CheckResult]:
        source = registry.get(spec.type)
        if source is None:
            return [error_result(spec.value, ErrorReason.UNKNOWN, f"unsupported source type: {spec.type}")]
        try:
            outcomes = source.check(spec.value, timeout=timeout)
        except Exception:  # source plugins cannot abort unrelated checks
            LOG.exception("unexpected source failure for target %s", spec.value)
            return [error_result(spec.value, ErrorReason.UNKNOWN, "unexpected source failure")]
        return [
            evaluate_certificate(outcome, thresholds, lambda: current) if not isinstance(outcome, CheckResult) else outcome
            for outcome in outcomes
        ]

    with ThreadPoolExecutor(max_workers=concurrency, thread_name_prefix="certificate-check") as executor:
        grouped = list(executor.map(perform, target_list))
    return [result for results in grouped for result in results]


def dispatch_alerts(
    results: Iterable[CheckResult],
    *,
    state: AlertState,
    notifiers: Iterable[Notifier],
    now: datetime,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[int, bool]:
    """Send newly escalated alerts, returning (would_send_count, delivery_failed)."""

    channels = list(notifiers)
    count = 0
    failed = False
    for result in results:
        if not state.should_notify(result, now, force=force):
            continue
        count += 1
        if dry_run:
            print(f"[DRY-RUN] would notify for {result.target} at {result.severity.value}", file=sys.stderr)
            continue
        if not channels:
            continue
        delivered = False
        for notifier in channels:
            try:
                notifier.notify(result)
                delivered = True
            except Exception:
                failed = True
                # Do not include a notifier URL, exception message, or configuration in logs.
                LOG.error("notification delivery failed for target %s", result.target)
        if delivered:
            state.record_notified(result)
    return count, failed


def exit_code(results: Iterable[CheckResult], *, tool_failure: bool = False) -> int:
    """Return documented cron/CI exit status, with severity taking precedence."""

    levels = {result.severity for result in results}
    if Severity.CRITICAL in levels or Severity.EXPIRED in levels:
        return 2
    if Severity.WARNING in levels or Severity.HIGH in levels:
        return 1
    if tool_failure or Severity.ERROR in levels:
        return 3
    return 0
