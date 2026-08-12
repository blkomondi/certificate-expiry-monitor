"""SMTP Email notification channel."""

from __future__ import annotations

import smtplib
import ssl
from dataclasses import dataclass, field
from datetime import UTC
from email.mime.text import MIMEText

from ..models import CheckResult, Severity
from ..output import to_table


def _format_utc(dt: object) -> str:
    if dt is None:
        return "N/A"
    utc_dt = dt.astimezone(UTC)  # type: ignore[union-attr]
    return utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _build_email_body(result: CheckResult) -> str:
    """Build the plain-text email body including terminal-style table and details."""
    hostname = result.hostname
    certificate = result.certificate
    status_str = result.status

    if result.severity == Severity.EXPIRED:
        header_title = "URGENT: TLS Certificate Expired"
        footer = "This certificate has expired!"
    elif result.severity == Severity.ERROR:
        header_title = "TLS Certificate Monitoring Error"
        footer = f"The certificate could not be checked: {result.message}"
    else:
        header_title = "TLS Certificate Expiry Alert"
        footer = "This certificate is approaching its expiry date."

    remaining_str = f"{result.days_remaining} days" if result.days_remaining is not None else "N/A"
    expires_str = _format_utc(result.expires_at) if result.expires_at else "N/A"

    # Terminal-style table output (same as what's shown in the CLI)
    table_output = to_table([result])

    lines = [
        header_title,
        "",
        "--- Check Results (Terminal Output) ---",
        table_output.rstrip(),
        "--- Details ---",
        f"URL: {result.target}",
        f"Hostname: {hostname}",
        f"Port: {result.port}",
        f"Issuer: {certificate.issuer if certificate else 'N/A'}",
        f"Subject: {certificate.subject_cn or certificate.subject if certificate else 'N/A'}",
        f"Fingerprint: {certificate.fingerprint if certificate else 'N/A'}",
        f"Serial: {certificate.serial if certificate else 'N/A'}",
        f"Signature Algorithm: {certificate.signature_algorithm if certificate else 'N/A'}",
        f"Key Size: {certificate.key_size if certificate else 'N/A'}",
        f"Chain Valid: {certificate.chain_valid if certificate else 'N/A'}",
        f"Expires: {expires_str}",
        f"Remaining: {remaining_str}",
        f"Status: {status_str}",
        footer,
    ]
    return "\n".join(lines)


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
    subject_prefix: str | None = None
    timeout: float = 10.0

    def notify(self, result: CheckResult) -> None:
        if not self.to_addrs:
            return

        hostname = result.hostname
        if result.severity == Severity.EXPIRED:
            subject = f"URGENT: TLS Certificate Expired: {hostname}"
        elif result.severity == Severity.ERROR:
            subject = f"TLS Certificate Monitoring Error: {hostname}"
        else:
            subject = f"TLS Certificate Expiry Alert: {hostname}"

        if self.subject_prefix:
            subject = f"{self.subject_prefix} {subject}"

        body = _build_email_body(result)

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = self.from_addr
        msg["To"] = ", ".join(self.to_addrs)

        recipients = list(self.to_addrs)
        msg_str = msg.as_string()

        ssl_context = ssl.create_default_context()

        if self.ssl:
            with smtplib.SMTP_SSL(self.smtp_host, self.smtp_port, timeout=self.timeout, context=ssl_context) as server:
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, recipients, msg_str)
        else:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=self.timeout) as server:
                if self.starttls or self.use_tls:
                    server.starttls(context=ssl_context)
                if self.username and self.password:
                    server.login(self.username, self.password)
                server.sendmail(self.from_addr, recipients, msg_str)
