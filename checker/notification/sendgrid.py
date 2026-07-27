"""SendGrid API notification channel (HTTPS/443, bypasses ISP SMTP blocking)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from ..models import CheckResult, Severity
from ..output import to_table


def _format_utc(dt: object) -> str:
    if dt is None:
        return "N/A"
    utc_dt = dt.astimezone(UTC)  # type: ignore[union-attr]
    return utc_dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _build_alert_content(result: CheckResult) -> tuple[str, str]:
    """Build (subject, plain_text_body) for a certificate alert."""
    hostname = result.hostname
    certificate = result.certificate
    status_str = result.status

    is_expired = result.severity == Severity.EXPIRED
    if is_expired:
        subject = f"URGENT: TLS Certificate Expired: {hostname}"
        header_title = "URGENT: TLS Certificate Expired"
        footer = "This certificate has expired!"
    else:
        subject = f"TLS Certificate Expiry Alert: {hostname}"
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
    return subject, "\n".join(lines)


@dataclass(frozen=True, slots=True)
class SendGridNotifier:
    """Deliver alert notifications via SendGrid REST API over HTTPS.

    This bypasses ISP SMTP port blocking by using port 443.
    Requires a SendGrid API key and a verified sender email address.
    """

    api_key: str
    from_addr: str
    to_addrs: tuple[str, ...] = field(default_factory=tuple)
    subject_prefix: str | None = None

    def notify(self, result: CheckResult) -> None:
        if not self.to_addrs:
            return

        subject, body = _build_alert_content(result)

        if self.subject_prefix:
            subject = f"{self.subject_prefix} {subject}"

        message = Mail(
            from_email=self.from_addr,
            to_emails=list(self.to_addrs),
            subject=subject,
            plain_text_content=body,
        )

        sg = SendGridAPIClient(self.api_key)
        response = sg.send(message)

        if response.status_code >= 400:
            raise OSError(f"SendGrid API returned HTTP {response.status_code}")
