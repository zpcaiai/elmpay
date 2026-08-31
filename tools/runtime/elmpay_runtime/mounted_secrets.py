"""Bounded reads from deployment-owned, read-only secret mounts."""
from __future__ import annotations

import os
from pathlib import Path

from .common import ValidationError


def read_mounted_secret(path_value: str, label: str, *, maximum_bytes: int = 8_192) -> bytes:
    """Read one secret while rejecting relative, writable, missing, or oversized mounts."""
    if not isinstance(path_value, str) or not path_value.strip() or maximum_bytes < 1:
        raise ValidationError(f"{label} file is required")
    configured = Path(path_value)
    if not configured.is_absolute():
        raise ValidationError(f"{label} path must be absolute")
    try:
        mount_parent = configured.parent.resolve(strict=True)
        resolved = configured.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise ValidationError(f"{label} mount is unavailable") from exc
    # Kubernetes projected Secrets rotate through an in-mount ``..data``
    # symlink.  Follow that controlled indirection, but never accept a link
    # whose real target escapes the configured mount directory.
    if not resolved.is_relative_to(mount_parent):
        raise ValidationError(f"{label} mount escapes its controlled directory")
    if not resolved.is_file() or metadata.st_size < 1 or metadata.st_size > maximum_bytes:
        raise ValidationError(f"{label} mount must be a bounded regular file")
    if metadata.st_mode & 0o222:
        raise ValidationError(f"{label} mount must be read-only")
    try:
        value = resolved.read_bytes()
    except OSError as exc:
        raise ValidationError(f"{label} mount cannot be read") from exc
    if value.endswith(b"\r\n"):
        value = value[:-2]
    elif value.endswith(b"\n"):
        value = value[:-1]
    if not value or b"\x00" in value or b"\r" in value or b"\n" in value:
        raise ValidationError(f"{label} mount has an invalid value")
    return value


def secret_path_from_environment(name: str) -> str:
    value = os.environ.get(name)
    if value is None or not value.strip():
        raise ValidationError(f"{name} is required")
    return value
