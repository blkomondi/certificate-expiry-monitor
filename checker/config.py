"""Configuration loading, environment expansion, and typed normalization."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .models import Thresholds

_ENV_PATTERN = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _expand_environment(value: Any) -> Any:
    """Expand ${VAR} patterns; missing vars become empty string instead of crashing."""
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            return os.environ.get(name, "")
        return _ENV_PATTERN.sub(replace, value)
    if isinstance(value, list):
        return [_expand_environment(item) for item in value]
    if isinstance(value, dict):
        return {key: _expand_environment(item) for key, item in value.items()}
    return value


@dataclass(frozen=True, slots=True)
class TargetSpec:
    type: str
    value: str


@dataclass(frozen=True, slots=True)
class Settings:
    timeout: float = 10.0
    concurrency: int = 8
    state_file: Path = Path(".certificate-monitor-state.json")
    check_interval: int = 21600


@dataclass(frozen=True, slots=True)
class EmailConfig:
    enabled: bool = False
    smtp_host: str | None = None
    smtp_port: int = 587
    username: str | None = None
    password: str | None = None
    use_tls: bool = True
    starttls: bool = True
    ssl: bool = False
    from_addr: str = "alerts@example.com"
    to_addrs: tuple[str, ...] = ()
    subject_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class SendGridConfig:
    enabled: bool = False
    api_key: str | None = None
    from_addr: str = "alerts@example.com"
    to_addrs: tuple[str, ...] = ()
    subject_prefix: str | None = None


@dataclass(frozen=True, slots=True)
class NotificationsConfig:
    console_enabled: bool = True
    webhook_enabled: bool = False
    webhook_url: str | None = None
    email: EmailConfig = EmailConfig()
    sendgrid: SendGridConfig = SendGridConfig()


@dataclass(frozen=True, slots=True)
class AppConfig:
    settings: Settings = Settings()
    thresholds: Thresholds = Thresholds()
    targets: tuple[TargetSpec, ...] = ()
    notifications: NotificationsConfig = NotificationsConfig()


def _target_from_mapping(item: dict[str, Any]) -> TargetSpec:
    kind = str(item.get("type", "")).lower()
    if not kind:
        if "url" in item:
            kind = "url"
        elif "host" in item:
            kind = "tls"
        elif "path" in item:
            kind = "file"
    if kind == "tls":
        host = item.get("host")
        port = item.get("port", 443)
        if not isinstance(host, str) or not host:
            raise ValueError("TLS target requires a non-empty host")
        display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        return TargetSpec("tls", f"{display_host}:{port}")
    if kind == "file":
        path = item.get("path")
        if not isinstance(path, str) or not path:
            raise ValueError("file target requires a non-empty path")
        return TargetSpec("file", path)
    if kind == "url":
        url_val = item.get("url") or item.get("value")
        if not isinstance(url_val, str) or not url_val:
            raise ValueError("URL target requires a non-empty url string")
        return TargetSpec("url", url_val)
    raise ValueError(f"unsupported target type: {kind or '<missing>'}")


def load_config(path: str | Path | None) -> AppConfig:
    """Load YAML or JSON configuration. Missing config means safe defaults."""

    if path is None:
        raw: dict[str, Any] = {}
    else:
        config_path = Path(path)
        text = config_path.read_text(encoding="utf-8")
        decoded = json.loads(text) if config_path.suffix.lower() == ".json" else yaml.safe_load(text)
        raw = decoded or {}
        if not isinstance(raw, dict):
            raise ValueError("configuration root must be a mapping")
    raw = _expand_environment(raw)
    settings_raw = raw.get("settings", {})
    threshold_raw = raw.get("thresholds", {})
    notification_raw = raw.get("notifications", {})
    if not all(isinstance(section, dict) for section in (settings_raw, threshold_raw, notification_raw)):
        raise ValueError("settings, thresholds, and notifications must be mappings")
    console_raw = notification_raw.get("console", {})
    webhook_raw = notification_raw.get("webhook", {})
    email_raw = notification_raw.get("email", {})
    sendgrid_raw = notification_raw.get("sendgrid", {})
    if not all(isinstance(item, dict) for item in (console_raw, webhook_raw, email_raw, sendgrid_raw)):
        raise ValueError("notification channels must be mappings")
    targets_raw = raw.get("targets", [])
    if not isinstance(targets_raw, list) or not all(isinstance(item, dict) for item in targets_raw):
        raise ValueError("targets must be a list of mappings")

    # Email env overrides
    smtp_host = os.environ.get("SMTP_HOST") or email_raw.get("smtp_host")
    smtp_port_raw = os.environ.get("SMTP_PORT") or email_raw.get("smtp_port", 587)
    smtp_port = int(smtp_port_raw)
    username = os.environ.get("SMTP_USERNAME") or email_raw.get("username")
    password = os.environ.get("SMTP_PASSWORD") or email_raw.get("password")
    from_addr = os.environ.get("SMTP_FROM") or email_raw.get("from_addr", "alerts@example.com")

    env_recipients = os.environ.get("ALERT_RECIPIENT") or os.environ.get("ALERT_RECIPIENTS")
    if env_recipients:
        to_addrs_list = [r.strip() for r in env_recipients.split(",") if r.strip()]
    else:
        to_addrs_raw = email_raw.get("to_addrs", [])
        if isinstance(to_addrs_raw, str):
            to_addrs_list = [to_addrs_raw] if to_addrs_raw.strip() else []
        elif isinstance(to_addrs_raw, list):
            to_addrs_list = [str(x) for x in to_addrs_raw if str(x).strip()]
        else:
            to_addrs_list = []

    # SendGrid config
    sendgrid_api_key = os.environ.get("SENDGRID_API_KEY") or sendgrid_raw.get("api_key")
    sendgrid_from_addr = os.environ.get("SENDGRID_FROM") or sendgrid_raw.get("from_addr", "alerts@example.com")

    env_sg_recipients = os.environ.get("SENDGRID_RECIPIENT") or os.environ.get("SENDGRID_RECIPIENTS")
    if env_sg_recipients:
        sg_to_addrs_list = [r.strip() for r in env_sg_recipients.split(",") if r.strip()]
    else:
        sg_to_addrs_raw = sendgrid_raw.get("to_addrs", [])
        if isinstance(sg_to_addrs_raw, str):
            sg_to_addrs_list = [sg_to_addrs_raw] if sg_to_addrs_raw.strip() else []
        elif isinstance(sg_to_addrs_raw, list):
            sg_to_addrs_list = [str(x) for x in sg_to_addrs_raw if str(x).strip()]
        else:
            sg_to_addrs_list = []

    sendgrid_enabled = bool(sendgrid_raw.get("enabled", False)) or bool(sendgrid_api_key)

    sendgrid_config = SendGridConfig(
        enabled=sendgrid_enabled,
        api_key=sendgrid_api_key,
        from_addr=sendgrid_from_addr,
        to_addrs=tuple(sg_to_addrs_list),
        subject_prefix=sendgrid_raw.get("subject_prefix"),
    )

    email_enabled = bool(email_raw.get("enabled", False)) or bool(smtp_host)

    email_config = EmailConfig(
        enabled=email_enabled,
        smtp_host=smtp_host,
        smtp_port=smtp_port,
        username=username,
        password=password,
        use_tls=bool(email_raw.get("use_tls", True)),
        starttls=bool(email_raw.get("starttls", True)),
        ssl=bool(email_raw.get("ssl", False)),
        from_addr=from_addr,
        to_addrs=tuple(to_addrs_list),
        subject_prefix=email_raw.get("subject_prefix"),
    )

    # Threshold overrides from ALERT_THRESHOLDS if set
    env_thresholds = os.environ.get("ALERT_THRESHOLDS")
    if env_thresholds:
        try:
            t_vals = sorted([int(t.strip()) for t in env_thresholds.split(",") if t.strip()], reverse=True)
            if t_vals:
                warning_days = t_vals[0]
                critical_days = t_vals[-1]
                high_days = t_vals[len(t_vals) // 2] if len(t_vals) > 2 else critical_days
                custom_days = tuple(t_vals)
            else:
                warning_days = int(threshold_raw.get("warning_days", 30))
                high_days = int(threshold_raw.get("high_days", 15))
                critical_days = int(threshold_raw.get("critical_days", 5))
                custom_days = (30, 14, 7, 3, 1)
        except ValueError:
            warning_days = int(threshold_raw.get("warning_days", 30))
            high_days = int(threshold_raw.get("high_days", 15))
            critical_days = int(threshold_raw.get("critical_days", 5))
            custom_days = (30, 14, 7, 3, 1)
    else:
        warning_days = int(threshold_raw.get("warning_days", 30))
        high_days = int(threshold_raw.get("high_days", 15))
        critical_days = int(threshold_raw.get("critical_days", 5))
        custom_days = (30, 14, 7, 3, 1)

    interval_raw = os.environ.get("CHECK_INTERVAL") or settings_raw.get("check_interval", 21600)

    return AppConfig(
        settings=Settings(
            timeout=float(settings_raw.get("timeout", 10)),
            concurrency=int(settings_raw.get("concurrency", 8)),
            state_file=Path(settings_raw.get("state_file", ".certificate-monitor-state.json")),
            check_interval=int(interval_raw),
        ),
        thresholds=Thresholds(
            warning_days=warning_days,
            high_days=high_days,
            critical_days=critical_days,
            custom_days=custom_days,
        ),
        targets=tuple(_target_from_mapping(item) for item in targets_raw),
        notifications=NotificationsConfig(
            console_enabled=bool(console_raw.get("enabled", True)),
            webhook_enabled=bool(webhook_raw.get("enabled", False)),
            webhook_url=webhook_raw.get("url"),
            email=email_config,
            sendgrid=sendgrid_config,
        ),
    )


def apply_cli_overrides(
    config: AppConfig,
    *,
    domains: list[str] | None = None,
    files: list[str] | None = None,
    urls: list[str] | None = None,
    timeout: float | None = None,
    concurrency: int | None = None,
    state_file: str | None = None,
) -> AppConfig:
    """Apply explicit command-line values, giving flags config precedence."""

    cli_targets = (
        tuple(TargetSpec("tls", value) for value in (domains or []))
        + tuple(TargetSpec("file", value) for value in (files or []))
        + tuple(TargetSpec("url", value) for value in (urls or []))
    )
    settings = Settings(
        timeout=timeout if timeout is not None else config.settings.timeout,
        concurrency=concurrency if concurrency is not None else config.settings.concurrency,
        state_file=Path(state_file) if state_file is not None else config.settings.state_file,
        check_interval=config.settings.check_interval,
    )
    if settings.timeout <= 0 or settings.concurrency <= 0:
        raise ValueError("timeout and concurrency must be positive")
    return AppConfig(settings, config.thresholds, config.targets + cli_targets, config.notifications)
