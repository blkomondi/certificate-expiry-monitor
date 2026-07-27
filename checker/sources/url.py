"""URL certificate retrieval module for HTTPS targets."""

from __future__ import annotations

from dataclasses import replace
from urllib.parse import urlparse

from ..evaluation import error_result
from ..models import CertInfo, CheckResult, ErrorReason
from .base import SourceOutcome
from .tls import TLSCertificateSource


def parse_url_target(target: str) -> tuple[str, int]:
    """Extract host and port from a URL target string."""
    url = target if "://" in target else f"https://{target}"
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme == "http":
        raise ValueError("HTTP scheme does not use SSL/TLS encryption")
    if scheme != "https":
        raise ValueError(f"unsupported URL scheme: {scheme}")
    if not parsed.hostname:
        raise ValueError("URL contains no valid hostname")
    port = parsed.port if parsed.port is not None else 443
    return parsed.hostname, port


class URLCertificateSource:
    """Retrieve TLS certificates from URL targets."""

    def __init__(self, tls_source: TLSCertificateSource | None = None) -> None:
        self._tls_source = tls_source or TLSCertificateSource()

    def check(self, target: str, *, timeout: float) -> list[SourceOutcome]:
        try:
            host, port = parse_url_target(target)
        except ValueError as exc:
            return [error_result(target, ErrorReason.UNKNOWN, str(exc))]

        display_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        tls_target = f"{display_host}:{port}"
        outcomes = self._tls_source.check(tls_target, timeout=timeout)

        retargeted: list[SourceOutcome] = []
        for outcome in outcomes:
            if isinstance(outcome, CertInfo):
                retargeted.append(replace(outcome, target=target, source="url"))
            elif isinstance(outcome, CheckResult):
                retargeted.append(replace(outcome, target=target))
            else:
                retargeted.append(outcome)
        return retargeted
