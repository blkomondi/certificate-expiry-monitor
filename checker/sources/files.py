"""Local PEM/DER certificates, globs, and directory discovery."""

from __future__ import annotations

import glob
from pathlib import Path

from ..evaluation import error_result
from ..models import ErrorReason
from ..parsing import CertificateParseError, parse_certificate_file
from .base import SourceOutcome

_CERTIFICATE_EXTENSIONS = {".pem", ".crt", ".cer", ".der"}


class FileCertificateSource:
    """Read known certificate file types without hiding parsing failures."""

    def _paths(self, target: str) -> list[Path]:
        path = Path(target)
        if path.is_dir():
            return sorted(item for item in path.iterdir() if item.is_file() and item.suffix.lower() in _CERTIFICATE_EXTENSIONS)
        if glob.has_magic(target):
            return sorted(Path(item) for item in glob.glob(target, recursive=False) if Path(item).is_file())
        return [path]

    def check(self, target: str, *, timeout: float) -> list[SourceOutcome]:
        del timeout  # local source shares the interface but has no network timeout
        requested_path = Path(target)
        if not glob.has_magic(target) and not requested_path.exists():
            return [error_result(target, ErrorReason.UNKNOWN, "certificate path was not found")]
        try:
            paths = self._paths(target)
        except PermissionError:
            return [error_result(target, ErrorReason.PERMISSION_DENIED, "permission denied while listing certificate path")]
        except OSError:
            return [error_result(target, ErrorReason.UNKNOWN, "could not inspect certificate path")]

        outcomes: list[SourceOutcome] = []
        for path in paths:
            if path.suffix.lower() not in _CERTIFICATE_EXTENSIONS:
                continue
            display = str(path)
            try:
                outcomes.append(parse_certificate_file(path, target=display))
            except PermissionError:
                outcomes.append(error_result(display, ErrorReason.PERMISSION_DENIED, "permission denied reading certificate file"))
            except FileNotFoundError:
                outcomes.append(error_result(display, ErrorReason.UNKNOWN, "certificate file was not found"))
            except CertificateParseError:
                outcomes.append(error_result(display, ErrorReason.UNPARSEABLE_FILE, "certificate file is malformed or not PEM/DER"))
            except OSError:
                outcomes.append(error_result(display, ErrorReason.UNKNOWN, "certificate file could not be read"))
        return outcomes
