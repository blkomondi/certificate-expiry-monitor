from __future__ import annotations

import socket

import pytest

from checker.models import ErrorReason
from checker.sources.files import FileCertificateSource
from checker.sources.tls import TLSCertificateSource, _reason_for_socket_error, split_host_port
from tests.conftest import make_certificate


def test_file_source_supports_file_glob_and_directory(tmp_path, now) -> None:
    (tmp_path / "one.pem").write_bytes(make_certificate(now))
    (tmp_path / "ignore.txt").write_text("not a certificate", encoding="utf-8")
    source = FileCertificateSource()
    direct = source.check(str(tmp_path / "one.pem"), timeout=1)
    globbed = source.check(str(tmp_path / "*.pem"), timeout=1)
    listed = source.check(str(tmp_path), timeout=1)
    assert len(direct) == len(globbed) == len(listed) == 1


def test_bad_certificate_file_becomes_error(tmp_path) -> None:
    path = tmp_path / "bad.pem"
    path.write_text("not a cert", encoding="utf-8")
    result = FileCertificateSource().check(str(path), timeout=1)[0]
    assert result.error_reason is ErrorReason.UNPARSEABLE_FILE


def test_permission_error_is_reported(monkeypatch, tmp_path) -> None:
    path = tmp_path / "locked.pem"
    path.write_text("x", encoding="utf-8")
    import checker.sources.files as files

    def denied(*args, **kwargs):
        raise PermissionError

    monkeypatch.setattr(files, "parse_certificate_file", denied)
    result = FileCertificateSource().check(str(path), timeout=1)[0]
    assert result.error_reason is ErrorReason.PERMISSION_DENIED


@pytest.mark.parametrize(
    ("exception", "reason"),
    [
        (socket.gaierror(), ErrorReason.DNS_FAILURE),
        (ConnectionRefusedError(), ErrorReason.CONNECTION_REFUSED),
        (socket.timeout(), ErrorReason.TIMEOUT),
    ],
)
def test_tls_socket_error_taxonomy(exception, reason) -> None:
    assert _reason_for_socket_error(exception) is reason


def test_tls_source_converts_dns_failure_to_result(monkeypatch) -> None:
    import checker.sources.tls as tls

    def no_dns(*args, **kwargs):
        raise socket.gaierror

    monkeypatch.setattr(tls.socket, "create_connection", no_dns)
    result = TLSCertificateSource().check("missing.example:443", timeout=1)[0]
    assert result.error_reason is ErrorReason.DNS_FAILURE


@pytest.mark.parametrize(
    ("exception", "reason"),
    [
        (ConnectionRefusedError(), ErrorReason.CONNECTION_REFUSED),
        (socket.timeout(), ErrorReason.TIMEOUT),
    ],
)
def test_tls_source_converts_connection_failures_to_results(monkeypatch, exception, reason) -> None:
    import checker.sources.tls as tls

    def fail(*args, **kwargs):
        raise exception

    monkeypatch.setattr(tls.socket, "create_connection", fail)
    result = TLSCertificateSource().check("example.test:443", timeout=1)[0]
    assert result.error_reason is reason


def test_tls_source_converts_handshake_failure_to_result(monkeypatch) -> None:
    import checker.sources.tls as tls

    class Raw:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    class Context:
        check_hostname = False

        def wrap_socket(self, *args, **kwargs):
            raise tls.ssl.SSLError("bad handshake")

    monkeypatch.setattr(tls.socket, "create_connection", lambda *args, **kwargs: Raw())
    monkeypatch.setattr(tls.ssl, "_create_unverified_context", lambda: Context())
    result = TLSCertificateSource().check("example.test:443", timeout=1)[0]
    assert result.error_reason is ErrorReason.TLS_HANDSHAKE_FAILURE


def test_host_port_parsing_supports_ipv6() -> None:
    assert split_host_port("example.com:443") == ("example.com", 443)
    assert split_host_port("[2001:db8::1]:8443") == ("2001:db8::1", 8443)
