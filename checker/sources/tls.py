"""Remote TLS leaf-certificate retrieval with independent chain validation."""

from __future__ import annotations

import errno
import ipaddress
import socket
import ssl

from ..evaluation import error_result
from ..models import ErrorReason
from ..parsing import CertificateParseError, parse_certificate_bytes
from .base import SourceOutcome


def split_host_port(target: str) -> tuple[str, int]:
    """Parse hostname:port and [ipv6]:port safely."""

    if target.startswith("["):
        end = target.find("]")
        if end < 0 or target[end + 1 : end + 2] != ":":
            raise ValueError("IPv6 targets must be in [address]:port form")
        host, port_text = target[1:end], target[end + 2 :]
    else:
        host, separator, port_text = target.rpartition(":")
        if not separator or not host:
            raise ValueError("TLS target must be host:port")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise ValueError("TLS port must be an integer") from exc
    if not 1 <= port <= 65535:
        raise ValueError("TLS port must be between 1 and 65535")
    return host, port


def _sni_name(host: str) -> str | None:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    return None


def _reason_for_socket_error(exc: BaseException) -> ErrorReason:
    if isinstance(exc, socket.gaierror):
        return ErrorReason.DNS_FAILURE
    if isinstance(exc, (TimeoutError, socket.timeout)):
        return ErrorReason.TIMEOUT
    if isinstance(exc, ConnectionRefusedError) or getattr(exc, "errno", None) == errno.ECONNREFUSED:
        return ErrorReason.CONNECTION_REFUSED
    return ErrorReason.CERTIFICATE_RETRIEVAL_FAILURE


class TLSCertificateSource:
    """Retrieve a TLS leaf without verification, then attempt normal validation."""

    def _validated_chain(self, host: str, port: int, timeout: float) -> bool | None:
        context = ssl.create_default_context()
        sni = _sni_name(host)
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=sni or host):
                    return True
        except ssl.SSLCertVerificationError:
            return False
        except (OSError, ssl.SSLError):
            return None

    def check(self, target: str, *, timeout: float) -> list[SourceOutcome]:
        try:
            host, port = split_host_port(target)
        except ValueError as exc:
            return [error_result(target, ErrorReason.UNKNOWN, str(exc))]
        context = ssl._create_unverified_context()  # scoped context: leaf retrieval only
        context.check_hostname = False
        try:
            with socket.create_connection((host, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=_sni_name(host)) as tls_socket:
                    der = tls_socket.getpeercert(binary_form=True)
            if not der:
                return [error_result(target, ErrorReason.CERTIFICATE_RETRIEVAL_FAILURE, "peer sent no certificate")]
        except ssl.SSLError as exc:
            return [error_result(target, ErrorReason.TLS_HANDSHAKE_FAILURE, "TLS handshake failed")]
        except OSError as exc:
            return [error_result(target, _reason_for_socket_error(exc), "TLS connection failed")]

        chain_valid = self._validated_chain(host, port, timeout)
        try:
            return [parse_certificate_bytes(der, target=target, source="tls", chain_valid=chain_valid)]
        except CertificateParseError:
            return [error_result(target, ErrorReason.CERTIFICATE_RETRIEVAL_FAILURE, "peer certificate could not be parsed")]
