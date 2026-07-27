"""SMTP Email notification channel."""

from __future__ import annotations

import smtplib
from dataclasses import dataclass, field
from datetime import UTC
from email.mime.text import MIMEText

from ..models import CheckResult


def _iso8601(value: object) -> str | None:
    if value is None:
        return None
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")  # type: ignore[union-attr]


@dataclass(frozen=True, slots=True)
class EmailNotifier:
    """Deliver alert notifications via SMTP email."""

    smtp_host: str
    smtp_port: int = 587
    username: str | None = None
    password: str | None = None
    use_tls: bool = True
    starttls: bool = True
    ssl: bool = False
    from_addr: str = "alerts@example.com"
    to_addrs: tuple[str, ...] = field(default_factory=tuple)
    subject_prefix: str = "[Certificate Alert]"
    timeout: float = 10.0

    def notify(self, result: CheckResult) -> None:
        if not self.to_addrs:
            return

        subject = f"{self.subject_prefix} [{result.severity.value}] Target: {result.target}"

        certificate = result.certificate
        lines = [
            f"Target: {result.target}",
            f"Severity: {result.severity.value}",
            f"Message: {result.message}",
        ]
        if result.days_remaining is not None:
            lines.append(f"Days Remaining: {result.days_remaining}")
        if result.expires_at is not None:
            lines.append(f"Expires At (UTC): {_iso8601(result.expires_at)}")
        if certificate:
            lines.extend([
                f"Subject CN: {certificate.subject_cn or 'N/A'}",
                f"Issuer: {certificate.issuer}",
                f"Fingerprint: {certificate.fingerprint}",
                f"Serial: {certificate.serial}",
            ])
        if result.error_reason:
            lines.append(f"Reason Code: {result.error_reason.value}")

        body = "\n".join(lines)

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        recipients = list(self.to_addrs)
        msg_str = msg.as_string()

        if self.ssl:
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=self.timeout) as server:
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, recipients, msg_str)
        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as server:
                if self.starttls or self.use_tls:
                    server.starttls()
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, recipients, msg_str)
