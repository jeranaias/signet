"""Storage backends for the HMAC audit chain.

A backend is a thin protocol: append a serialized entry, iterate previous
entries in order. The default :class:`JsonlBackend` writes one JSON object
per line to an append-only file. Custom backends can target databases,
object stores, or remote log aggregators.

The chain logic (HMAC compute, prev-link wiring) lives in
:mod:`signet.audit.chain` and uses these backends through the
:class:`AuditBackend` protocol so the storage choice is orthogonal to the
crypto.
"""

from __future__ import annotations

import contextlib
import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any, Protocol

from signet.core.audit import AuditEntry


# Module-level platform-specific lock implementations. Selected at
# import time so mypy's sys.platform narrowing keeps the per-platform
# branch type-checked AND reachable on its own platform.
class _LockImpl(Protocol):
    """Cross-process file-lock primitives. Implementations are platform-
    specific and selected at module import time."""

    def acquire(self, fileno: int) -> None: ...
    def release(self, fileno: int) -> None: ...


if sys.platform == "win32":
    import msvcrt

    class _MsvcrtLock:
        """Windows byte-range lock. Some file modes don't permit byte-range
        locks on append-mode files — single-process safety still holds via
        threading.Lock in HmacChain. Failures are suppressed."""

        def acquire(self, fileno: int) -> None:
            with contextlib.suppress(OSError):
                msvcrt.locking(fileno, msvcrt.LK_LOCK, 1)

        def release(self, fileno: int) -> None:
            with contextlib.suppress(OSError):
                msvcrt.locking(fileno, msvcrt.LK_UNLCK, 1)

    _LOCK_IMPL: _LockImpl = _MsvcrtLock()
else:
    import fcntl

    class _FcntlLock:
        """POSIX advisory file lock via fcntl.flock."""

        def acquire(self, fileno: int) -> None:
            fcntl.flock(fileno, fcntl.LOCK_EX)

        def release(self, fileno: int) -> None:
            fcntl.flock(fileno, fcntl.LOCK_UN)

    _LOCK_IMPL = _FcntlLock()


class AuditBackend(Protocol):
    """The storage protocol every audit backend implements."""

    def append(self, entry: AuditEntry) -> None:
        """Persist an entry. MUST NOT mutate prior entries.

        The caller (the chain writer) is responsible for setting
        ``entry.prev_hmac`` and ``entry.hmac`` before calling this method.
        """
        ...

    def iter_entries(self) -> Iterator[AuditEntry]:
        """Iterate entries in append order, oldest first.

        Used by :class:`signet.audit.chain.ChainVerifier` to walk the
        chain and check link integrity.
        """
        ...

    def last_entry(self) -> AuditEntry | None:
        """Return the most recently appended entry, or ``None`` if the
        backend is empty.

        Optimized lookup; the chain writer needs this on every append to
        compute the new entry's ``prev_hmac``.
        """
        ...


class JsonlBackend:
    """Append-only JSONL file backend.

    Each entry serializes to one JSON object via
    :meth:`AuditEntry.to_dict` and is written followed by a newline.
    Reads stream the file line by line.

    Suitable for: single-host deployments, low-to-medium volume
    (<10K entries/sec), and any setting where a file on disk is the
    audit-of-record. For higher throughput, multiple writers, or
    cloud-native deployments, plug in a custom backend.

    Durability: by default each append calls :func:`os.fsync` after
    writing so a crash between request handling and disk flush still
    leaves the chain consistent. Disable with ``fsync_after_append=False``
    if you need throughput and accept the post-crash audit-tail-loss
    window. There is no rotation, compression, or indexing — those
    belong in a dedicated backend.
    """

    def __init__(self, path: Path | str, *, fsync_after_append: bool = True) -> None:
        """Open the backend at ``path``.

        Args:
            path: File path. Created if it does not exist; parent
                directory must already exist.
            fsync_after_append: When True (default), :func:`os.fsync`
                is called after every write so a crash cannot leave
                the audit chain shorter than the responses already
                returned to callers. Set False for benchmark or
                ephemeral use; production must keep fsync on.
        """
        self._path = Path(path)
        self._path.touch(exist_ok=True)
        self._fsync = fsync_after_append

    @property
    def path(self) -> Path:
        """The underlying file path."""
        return self._path

    def append(self, entry: AuditEntry) -> None:
        line = json.dumps(
            entry.to_dict(),
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
            ensure_ascii=False,
        )
        with self._path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            if self._fsync:
                f.flush()
                os.fsync(f.fileno())

    def iter_entries(self) -> Iterator[AuditEntry]:
        if not self._path.exists():
            return
        with self._path.open("r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if not stripped:
                    continue
                yield AuditEntry.from_dict(json.loads(stripped))

    def last_entry(self) -> AuditEntry | None:
        # JSONL doesn't support efficient seek-to-last without indexing.
        # For the volumes JsonlBackend targets, a linear scan is acceptable;
        # callers needing high-throughput chain extension should use a
        # database-backed backend that exposes O(1) tail access.
        last: AuditEntry | None = None
        for entry in self.iter_entries():
            last = entry
        return last


class FileLockingJsonlBackend(JsonlBackend):
    """JsonlBackend with cross-process file locking for multi-worker deployments.

    The base :class:`JsonlBackend` is safe for single-process use only —
    :class:`signet.audit.chain.HmacChain`'s in-process lock prevents
    coroutine-level forks but does nothing across uvicorn workers. This
    subclass acquires an exclusive OS-level lock on the audit file
    around the read-prev + append sequence, so multiple workers can
    safely share one log file.

    Locking primitive: ``fcntl.flock`` on POSIX, ``msvcrt.locking`` on
    Windows. Both are advisory locks — they only constrain processes
    that themselves call into this backend. External processes that
    write to the audit file directly are not constrained (and should
    not be doing that anyway).

    The chain's :meth:`HmacChain.append` already calls ``last_entry()``
    once per append (cache-hit path), so this backend overrides
    ``append`` to take the lock, re-read the chain head from disk
    (invalidating any stale in-process cache), perform the chain
    update, and release the lock. To make this work cleanly with
    HmacChain's caching, callers using this backend should construct
    their HmacChain with ``cache_prev=False`` (added in v0.1.3).

    Performance: the lock is held only for the duration of one append
    (microseconds for small entries on local SSD). For high-throughput
    multi-worker deployments, consider a database-backed audit
    backend with native concurrency support instead.
    """

    def append_locked(self, entry: AuditEntry, on_locked: Any = None) -> None:
        """Append under an exclusive cross-process lock.

        ``on_locked`` is an optional zero-arg callable invoked AFTER the
        lock is acquired but BEFORE ``append`` runs. Used by
        :class:`HmacChain` to re-read the chain head under the lock so
        multi-worker prev_hmac stays correct without leaving the
        critical section.
        """
        with self._path.open("a", encoding="utf-8") as f:
            _LOCK_IMPL.acquire(f.fileno())
            try:
                if on_locked is not None:
                    on_locked()
                line = json.dumps(
                    entry.to_dict(),
                    separators=(",", ":"),
                    sort_keys=True,
                    allow_nan=False,
                    ensure_ascii=False,
                )
                f.write(line + "\n")
                if self._fsync:
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                _LOCK_IMPL.release(f.fileno())

    def append(self, entry: AuditEntry) -> None:
        """Single-writer append under cross-process lock.

        Multi-process safe: only one worker holds the lock at a time.
        For chain-aware appends that need to re-read prev_hmac under
        the lock, use :meth:`append_locked`.
        """
        self.append_locked(entry)
