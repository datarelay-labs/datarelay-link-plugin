"""Atomic durable OAuth and tenant-binding state.

Schema v1 is OAuth clients and refresh tokens only. Schema v2 adds
``server_bindings`` (explicit Plugin subject → DRLink server connections).
v1 files load as v2 with an empty binding map and are rewritten as v2 on the
next save.

Writes use a same-directory temp file, fsync the file contents, replace into
place, then fsync the parent directory so the directory entry is durable across
process crash and typical system crash on local filesystems.
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

STATE_VERSION = 2
_LEGACY_VERSION = 1
_FORBIDDEN_TOP_LEVEL = frozenset(
    {"owner_approval_secret", "upstream_token", "mock_plugin_token"}
)


class OAuthStateError(RuntimeError):
    """Fail-closed durable state load/save failure."""


def _assert_safe_dir(path: Path) -> None:
    if not path.exists():
        path.mkdir(mode=0o700, parents=True)
    st = path.stat()
    if not path.is_dir():
        raise OAuthStateError(f"oauth state parent is not a directory: {path}")
    if st.st_mode & 0o022:
        raise OAuthStateError(
            f"oauth state directory is group/world-writable: {path}"
        )


def _assert_safe_file_mode(path: Path) -> None:
    st = path.stat()
    if st.st_mode & 0o077:
        raise OAuthStateError(
            f"oauth state file permissions too open (expected 0600): {path}"
        )


def _normalize_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Return a v2 payload. v1 migrates in memory; disk updates on the next save."""
    version = payload.get("version")
    if version not in {_LEGACY_VERSION, STATE_VERSION}:
        raise OAuthStateError(
            f"unsupported oauth state schema version: {version!r} "
            f"(expected {STATE_VERSION})"
        )
    if _FORBIDDEN_TOP_LEVEL.intersection(payload.keys()):
        raise OAuthStateError("oauth state contains forbidden credential fields")
    clients_raw = payload.get("clients")
    refresh_raw = payload.get("refresh_tokens")
    if not isinstance(clients_raw, dict) or not isinstance(refresh_raw, dict):
        raise OAuthStateError("oauth state missing clients/refresh_tokens maps")
    bindings_raw = payload.get("server_bindings", {})
    if not isinstance(bindings_raw, dict):
        raise OAuthStateError("oauth state server_bindings must be an object")
    normalized = dict(payload)
    normalized["version"] = STATE_VERSION
    normalized["server_bindings"] = bindings_raw
    return normalized


class DurableOAuthStore:
    """Versioned JSON state file with atomic replace and restrictive permissions."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._io_lock = threading.RLock()
        if self.path.exists() and self.path.is_dir():
            raise OAuthStateError(
                f"oauth state path must be a file, not a directory: {self.path}"
            )
        _assert_safe_dir(self.path.parent)

    def load(self) -> dict[str, Any]:
        with self._io_lock:
            return self._load_unlocked()

    def save(self, payload: dict[str, Any]) -> None:
        with self._io_lock:
            self._save_unlocked(payload)

    def update(self, mutator: Callable[[dict[str, Any]], None]) -> dict[str, Any]:
        """Load, mutate, and save under one file lock so writers cannot drop keys."""
        with self._io_lock:
            payload = self._load_unlocked()
            mutator(payload)
            self._save_unlocked(payload)
            return payload

    def _load_unlocked(self) -> dict[str, Any]:
        if not self.path.exists():
            return {
                "version": STATE_VERSION,
                "clients": {},
                "refresh_tokens": {},
                "server_bindings": {},
            }
        _assert_safe_file_mode(self.path)
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise OAuthStateError(f"corrupt oauth state file: {self.path}") from exc

        if not isinstance(payload, dict):
            raise OAuthStateError("oauth state root must be an object")
        return _normalize_payload(payload)

    def _save_unlocked(self, payload: dict[str, Any]) -> None:
        _assert_safe_dir(self.path.parent)
        if not isinstance(payload, dict):
            raise OAuthStateError("oauth state root must be an object")
        normalized = _normalize_payload(payload)
        if normalized.get("version") != STATE_VERSION:
            raise OAuthStateError("refusing to persist unsupported oauth state version")
        encoded = json.dumps(normalized, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
        fd: int | None = None
        tmp_name: str | None = None
        try:
            fd, tmp_name = tempfile.mkstemp(
                prefix=".oauth-state-",
                suffix=".tmp",
                dir=str(self.path.parent),
            )
            os.write(fd, encoded)
            os.fsync(fd)
            os.close(fd)
            fd = None
            os.chmod(tmp_name, 0o600)
            os.replace(tmp_name, self.path)
            tmp_name = None
            # Durability of the directory entry after rename.
            dir_fd = os.open(str(self.path.parent), os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
            os.chmod(self.path, 0o600)
            _assert_safe_file_mode(self.path)
        except OAuthStateError:
            raise
        except OSError as exc:
            raise OAuthStateError(f"failed to persist oauth state: {self.path}") from exc
        finally:
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
