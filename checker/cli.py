"""Argparse CLI that keeps results on stdout and operational logs on stderr."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import UTC, datetime
from typing import Sequence

from .config import AppConfig, apply_cli_overrides, load_config
from .evaluation import utc_now
from .notification import ConsoleNotifier, WebhookNotifier
from .output import to_json, to_prometheus, to_table
from .service import dispatch_alerts, exit_code, run_checks
from .state import AlertState, JsonStateStore, Suppression

LOG = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor TLS and local certificate expiry.")
    parser.add_argument("command", nargs="?", default="check", choices=("check", "acknowledge", "suppress", "unsuppress"))
    parser.add_argument("--config", help="YAML or JSON configuration file")
    parser.add_argument("--domain", action="append", help="TLS target in host:port form; may be repeated")
    parser.add_argument("--file", action="append", help="certificate file, glob, or directory; may be repeated")
    parser.add_argument("--format", choices=("table", "json", "prometheus"), default="table")
    parser.add_argument("--dry-run", action="store_true", help="evaluate and show prospective alerts without sending or saving")
    parser.add_argument("--verbose", action="store_true", help="enable diagnostic logging")
    parser.add_argument("--quiet", action="store_true", help="only emit errors to stderr")
    parser.add_argument("--timeout", type=float, help="per-target TLS timeout in seconds")
    parser.add_argument("--concurrency", type=int, help="maximum parallel target checks")
    parser.add_argument("--force-notify", action="store_true", help="send eligible alerts even if their tier was previously sent")
    parser.add_argument("--state-file", help="override persistent JSON state path")
    parser.add_argument("--target", help="target to suppress or unsuppress")
    parser.add_argument("--fingerprint", help="optional SHA-256 fingerprint to scope a suppression")
    parser.add_argument("--until", help="optional aware ISO-8601 suppression expiry")
    parser.add_argument("--reason", help="optional acknowledgement/suppression reason")
    return parser


def configure_logging(verbose: bool, quiet: bool) -> None:
    level = logging.DEBUG if verbose else logging.ERROR if quiet else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


def _parse_until(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("--until must include a timezone, for example 2027-01-01T00:00:00Z")
    return parsed.astimezone(UTC)


def _notifiers(config: AppConfig) -> list[object]:
    channels: list[object] = []
    if config.notifications.console_enabled:
        channels.append(ConsoleNotifier())
    if config.notifications.webhook_enabled:
        if not config.notifications.webhook_url:
            raise ValueError("webhook is enabled but no webhook URL was configured")
        channels.append(WebhookNotifier(config.notifications.webhook_url, config.settings.timeout))
    return channels


def _state_command(args: argparse.Namespace, store: JsonStateStore) -> int:
    if not args.target:
        raise ValueError(f"{args.command} requires --target")
    state = store.load()
    if args.command in ("acknowledge", "suppress"):
        state.suppress(Suppression(args.target, args.fingerprint, _parse_until(args.until), args.reason))
        store.save(state)
        print(f"suppressed notifications for {args.target}")
    else:
        changed = state.unsuppress(args.target, args.fingerprint)
        store.save(state)
        print(f"{'removed' if changed else 'no'} suppression for {args.target}")
    return 0


def _render(format_name: str, results: list[object]) -> str:
    if format_name == "json":
        return to_json(results)  # type: ignore[arg-type]
    if format_name == "prometheus":
        return to_prometheus(results)  # type: ignore[arg-type]
    return to_table(results)  # type: ignore[arg-type]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    try:
        config = apply_cli_overrides(
            load_config(args.config),
            domains=args.domain,
            files=args.file,
            timeout=args.timeout,
            concurrency=args.concurrency,
            state_file=args.state_file,
        )
        store = JsonStateStore(config.settings.state_file)
        if args.command != "check":
            return _state_command(args, store)

        results = run_checks(
            config.targets,
            timeout=config.settings.timeout,
            concurrency=config.settings.concurrency,
            thresholds=config.thresholds,
        )
        sys.stdout.write(_render(args.format, results))
        try:
            state = store.load()
            now = utc_now()
            _, delivery_failed = dispatch_alerts(
                results,
                state=state,
                notifiers=_notifiers(config),
                now=now,
                force=args.force_notify,
                dry_run=args.dry_run,
            )
            if not args.dry_run:
                store.save(state)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            LOG.error("state or notification setup failed: %s", exc)
            delivery_failed = True
        return exit_code(results, tool_failure=delivery_failed)
    except (OSError, ValueError, TypeError) as exc:
        LOG.error("configuration or command failed: %s", exc)
        return 3
