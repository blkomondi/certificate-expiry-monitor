"""Argparse CLI that keeps results on stdout and operational logs on stderr."""

from __future__ import annotations

import argparse
import logging
import sys
import time
from datetime import UTC, datetime
from typing import Sequence

from .api import create_api_server
from .config import AppConfig, apply_cli_overrides, load_config
from .env import load_dotenv
from .evaluation import utc_now
from .notification import ConsoleNotifier, EmailNotifier, SendGridNotifier, WebhookNotifier
from .output import to_json, to_prometheus, to_table
from .service import dispatch_alerts, exit_code, run_checks
from .state import AlertState, JsonStateStore, Suppression

LOG = logging.getLogger(__name__)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Monitor TLS, URL, and local certificate expiry.")
    parser.add_argument(
        "command",
        nargs="?",
        default="check",
        choices=("check", "monitor", "serve", "acknowledge", "suppress", "unsuppress"),
    )
    parser.add_argument("--config", help="YAML or JSON configuration file")
    parser.add_argument("--domain", action="append", help="TLS target in host:port form; may be repeated")
    parser.add_argument("--url", action="append", help="URL target (e.g. https://example.com/api); may be repeated")
    parser.add_argument("--file", action="append", help="certificate file, glob, or directory; may be repeated")
    parser.add_argument("--format", choices=("table", "json", "prometheus"), default="table")
    parser.add_argument("--dry-run", action="store_true", help="evaluate and show prospective alerts without sending or saving")
    parser.add_argument("--verbose", action="store_true", help="enable diagnostic logging")
    parser.add_argument("--quiet", action="store_true", help="only emit errors to stderr")
    parser.add_argument("--timeout", type=float, help="per-target TLS timeout in seconds")
    parser.add_argument("--concurrency", type=int, help="maximum parallel target checks")
    parser.add_argument("--interval", type=int, help="check interval in seconds for monitor mode (default: 21600)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP API server port for serve mode (default: 8000)")
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="bind address for serve mode (use 0.0.0.0 to expose inside a container; default: 127.0.0.1)",
    )
    parser.add_argument("--once", action="store_true", help="run single iteration in monitor mode (for testing)")
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
    if config.notifications.email.enabled:
        email_cfg = config.notifications.email
        if not email_cfg.smtp_host:
            raise ValueError("email notification is enabled but no smtp_host was configured")
        if not email_cfg.to_addrs:
            raise ValueError("email notification is enabled but no to_addrs were configured")
        channels.append(
            EmailNotifier(
                smtp_host=email_cfg.smtp_host,
                smtp_port=email_cfg.smtp_port,
                username=email_cfg.username,
                password=email_cfg.password,
                use_tls=email_cfg.use_tls,
                starttls=email_cfg.starttls,
                ssl=email_cfg.ssl,
                from_addr=email_cfg.from_addr,
                to_addrs=email_cfg.to_addrs,
                subject_prefix=email_cfg.subject_prefix,
                timeout=config.settings.timeout,
            )
        )
    if config.notifications.sendgrid.enabled:
        sg_cfg = config.notifications.sendgrid
        if not sg_cfg.api_key:
            raise ValueError("sendgrid notification is enabled but no api_key was configured")
        if not sg_cfg.to_addrs:
            raise ValueError("sendgrid notification is enabled but no to_addrs were configured")
        if not sg_cfg.from_addr:
            raise ValueError("sendgrid notification is enabled but no from_addr was configured")
        channels.append(
            SendGridNotifier(
                api_key=sg_cfg.api_key,
                from_addr=sg_cfg.from_addr,
                to_addrs=sg_cfg.to_addrs,
                subject_prefix=sg_cfg.subject_prefix,
            )
        )
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


def _run_monitor_loop(config: AppConfig, store: JsonStateStore, interval: int, once: bool = False) -> int:
    LOG.info("Starting scheduled monitor loop with interval of %d seconds", interval)
    print(f"Starting certificate expiry monitor loop (interval: {interval}s)...")
    try:
        while True:
            results = run_checks(
                config.targets,
                timeout=config.settings.timeout,
                concurrency=config.settings.concurrency,
                thresholds=config.thresholds,
            )
            sys.stdout.write(_render("table", results))
            try:
                state = store.load()
                now = utc_now()
                dispatch_alerts(
                    results,
                    state=state,
                    notifiers=_notifiers(config),
                    now=now,
                    force=False,
                    dry_run=False,
                )
                store.save(state)
            except Exception as exc:
                LOG.error("error during alert dispatch: %s", exc)
            if once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopping monitor loop.")
    return 0


def _run_api_server(config: AppConfig, host: str, port: int) -> int:
    server = create_api_server(config, host=host, port=port)
    print(f"Starting Certificate Monitor API server on http://{host}:{port}/api/monitors")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.server_close()
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    configure_logging(args.verbose, args.quiet)
    try:
        load_dotenv()
        config = apply_cli_overrides(
            load_config(args.config),
            domains=args.domain,
            files=args.file,
            urls=args.url,
            timeout=args.timeout,
            concurrency=args.concurrency,
            state_file=args.state_file,
        )
        store = JsonStateStore(config.settings.state_file)

        if args.command in ("acknowledge", "suppress", "unsuppress"):
            return _state_command(args, store)

        if args.command == "monitor":
            interval = args.interval if args.interval is not None else config.settings.check_interval
            return _run_monitor_loop(config, store, interval, once=args.once)

        if args.command == "serve":
            return _run_api_server(config, host=args.host, port=args.port)

        # Default "check" command
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
