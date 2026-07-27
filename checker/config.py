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
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in os.environ:
                raise ValueError(f"environment variable {name} is not set")
            return os.environ[name]
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
    subject_prefix: str = "[Certificate Alert]"


@dataclass(frozen=True, slots=True)
class NotificationsConfig:
    console_enabled: bool = True
    webhook_enabled: bool = False
    webhook_url: str | None = None
    email: EmailConfig = EmailConfig()


@dataclass(frozen=True, slots=True)
class AppConfig:
    settings: Settings = Settings()
    thresholds: Thresholds = Thresholds()
    targets: tuple[TargetSpec, ...] = ()
    notifications: NotificationsConfig = NotificationsConfig()


def _target_from_mapping(item: dict[str, Any]) -> TargetSpec:
    kind = str(item.get("type", "")).lower()
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
    if not all(isinstance(item, dict) for item in (console_raw, webhook_raw, email_raw)):
        raise ValueError("notification channels must be mappings")
    targets_raw = raw.get("targets", [])
    if not isinstance(targets_raw, list) or not all(isinstance(item, dict) for item in targets_raw):
        raise ValueError("targets must be a list of mappings")

    to_addrs_raw = email_raw.get("to_addrs", [])
    if isinstance(to_addrs_raw, str):
        to_addrs_list = [to_addrs_raw]
    elif isinstance(to_addrs_raw, list):
        to_addrs_list = [str(x) for x in to_addrs_raw]
    else:
        to_addrs_list = []

    email_config = EmailConfig(
        enabled=bool(email_raw.get("enabled", False)),
        smtp_host=email_raw.get("smtp_host"),
        smtp_port=int(email_raw.get("smtp_port", 587)),
        username=email_raw.get("username"),
        password=email_raw.get("password"),
        use_tls=bool(email_raw.get("use_tls", True)),
        starttls=bool(email_raw.get("starttls", True)),
        ssl=bool(email_raw.get("ssl", False)),
        from_addr=str(email_raw.get("from_addr", "alerts@example.com")),
        to_addrs=tuple(to_addrs_list),
        subject_prefix=str(email_raw.get("subject_prefix", "[Certificate Alert]")),
    )

    return AppConfig(
        settings=Settings(
            timeout=float(settings_raw.get("timeout", 10)),
            concurrency=int(settings_raw.get("concurrency", 8)),
            state_file=Path(settings_raw.get("state_file", ".certificate-monitor-state.json")),
        ),
        thresholds=Thresholds(
            warning_days=int(threshold_raw.get("warning_days", 30)),
            high_days=int(threshold_raw.get("high_days", 15)),
            critical_days=int(threshold_raw.get("critical_days", 5)),
        ),
        targets=tuple(_target_from_mapping(item) for item in targets_raw),
        notifications=NotificationsConfig(
            console_enabled=bool(console_raw.get("enabled", True)),
            webhook_enabled=bool(webhook_raw.get("enabled", False)),
            webhook_url=webhook_raw.get("url"),
            email=email_config,
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
    """Apply only explicit command-line values, giving flags config precedence."""

    cli_targets = (
        tuple(TargetSpec("tls", value) for value in (domains or []))
        + tuple(TargetSpec("file", value) for value in (files or []))
        + tuple(TargetSpec("url", value) for value in (urls or []))
    )
    settings = Settings(
        timeout=timeout if timeout is not None else config.settings.timeout,
        concurrency=concurrency if concurrency is not None else config.settings.concurrency,
        state_file=Path(state_file) if state_file is not None else config.settings.state_file,
    )
    if settings.timeout <= 0 or settings.concurrency <= 0:
        raise ValueError("timeout and concurrency must be positive")
    return AppConfig(settings, config.thresholds, config.targets + cli_targets, config.notifications)
