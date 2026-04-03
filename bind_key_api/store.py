"""Locked read/modify/write for the TSIG key file + rndc reload."""

from __future__ import annotations

import fcntl
import os
import signal
import stat
import subprocess
import tempfile
import threading
from contextlib import contextmanager
from pathlib import Path

try:
    import grp
except ImportError:
    grp = None  # Windows

from bind_key_api.tsig import TsigKey, parse_keyfile, serialize_keyfile, verify_roundtrip
from bind_key_api.zone_cleanup import (
    ZoneCleanupError,
    ZoneCleanupParams,
    delete_rrsets_for_tsig_key,
)


class KeyStoreError(RuntimeError):
    pass


# Linux flock(2) is per open file description: each caller opens a new fd, so threads
# in the same process do not block each other on LOCK_EX. Serialize in-process first.
_process_lock = threading.Lock()


@contextmanager
def _store_lock(lock_path: Path, *, shared: bool = False):
    with _process_lock:
        with _file_lock(lock_path, shared=shared):
            yield


@contextmanager
def _file_lock(lock_path: Path, *, shared: bool = False):
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def read_keys(path: Path, *, lock_path: Path | None = None) -> dict[str, TsigKey]:
    lp = lock_path or path.with_name(path.name + ".lock")
    with _store_lock(lp, shared=True):
        if not path.exists():
            return {}
        data = path.read_text(encoding="utf-8")
        return parse_keyfile(data)


def _apply_keyfile_metadata(path: Path, st_before: os.stat_result | None) -> None:
    """mkstemp uses mode 0600; restore prior mode/owner or Debian bind-friendly defaults."""
    if st_before is not None:
        try:
            os.chmod(path, stat.S_IMODE(st_before.st_mode))
            os.chown(path, st_before.st_uid, st_before.st_gid)
        except OSError:
            pass
        return
    try:
        if grp is None:
            raise KeyError("no grp")
        bind_gid = grp.getgrnam("bind").gr_gid
        os.chmod(path, 0o640)
        os.chown(path, 0, bind_gid)
    except (KeyError, OSError):
        try:
            os.chmod(path, 0o644)
        except OSError:
            pass


def _atomic_write_same_dir(
    path: Path,
    content: str,
    *,
    preserved_stat: os.stat_result | None = None,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    st_before = preserved_stat if preserved_stat is not None else (path.stat() if path.exists() else None)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
        _apply_keyfile_metadata(path, st_before)
    except Exception:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _named_pid_candidates(explicit: Path | None) -> list[Path]:
    if explicit is not None:
        return [explicit]
    return [Path("/run/named/named.pid"), Path("/var/run/named/named.pid")]


def _resolve_named_pid_file(named_pid_path: Path | None) -> Path | None:
    for p in _named_pid_candidates(named_pid_path):
        if p.exists():
            return p
    return None


def _rndc(
    *,
    rndc_path: Path,
    timeout_sec: float,
    extra_args: list[str],
    subcommand: str,
) -> None:
    cmd = [str(rndc_path), *extra_args, subcommand]
    try:
        subprocess.run(
            cmd,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or "").strip() or str(e)
        raise KeyStoreError(f"rndc {subcommand} failed: {msg}") from e
    except subprocess.TimeoutExpired as e:
        raise KeyStoreError(f"rndc {subcommand} timed out") from e


def reload_named(*, rndc_path: Path, timeout_sec: float, extra_args: list[str]) -> None:
    _rndc(
        rndc_path=rndc_path,
        timeout_sec=timeout_sec,
        extra_args=extra_args,
        subcommand="reload",
    )


def reconfig_named(*, rndc_path: Path, timeout_sec: float, extra_args: list[str]) -> None:
    """Re-read named.conf (and included key files) without full zone reload."""
    _rndc(
        rndc_path=rndc_path,
        timeout_sec=timeout_sec,
        extra_args=extra_args,
        subcommand="reconfig",
    )


def _rndc_permission_denied(err: KeyStoreError) -> bool:
    return "permission denied" in str(err).lower()


def reload_named_after_key_change(
    *,
    rndc_path: Path,
    rndc_timeout_sec: float,
    rndc_extra_args: list[str],
    named_pid_path: Path | None,
    sighup_on_rndc_permission_denied: bool,
) -> None:
    try:
        reload_named(
            rndc_path=rndc_path,
            timeout_sec=rndc_timeout_sec,
            extra_args=rndc_extra_args,
        )
        return
    except KeyStoreError as e_reload:
        if not sighup_on_rndc_permission_denied:
            raise
        if not _rndc_permission_denied(e_reload):
            raise
        # Some BIND builds restrict `reload` but allow `reconfig`; included TSIG keys
        # are re-read on reconfig.
        try:
            reconfig_named(
                rndc_path=rndc_path,
                timeout_sec=rndc_timeout_sec,
                extra_args=rndc_extra_args,
            )
            return
        except KeyStoreError as e_reconfig:
            if not _rndc_permission_denied(e_reconfig):
                raise
            rndc_err = e_reconfig
    pid_file = _resolve_named_pid_file(named_pid_path)
    if pid_file is None:
        raise KeyStoreError(
            "rndc reload/reconfig not permitted (permission denied) and no named PID file "
            "found for SIGHUP fallback (set BIND_KEY_API_NAMED_PID_PATH)"
        ) from rndc_err
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        os.kill(pid, signal.SIGHUP)
    except OSError as ex:
        raise KeyStoreError(
            f"rndc reload/reconfig not permitted and SIGHUP to named failed: {ex}"
        ) from rndc_err


def add_key(
    path: Path,
    lock_path: Path,
    key: TsigKey,
    *,
    rndc_path: Path,
    rndc_timeout_sec: float,
    rndc_extra_args: list[str],
    named_pid_path: Path | None,
    sighup_on_rndc_permission_denied: bool,
) -> None:
    with _store_lock(lock_path):
        previous = path.read_text(encoding="utf-8") if path.exists() else ""
        keys = parse_keyfile(previous) if previous.strip() else {}
        if key.name in keys:
            raise KeyStoreError(f"key already exists: {key.name}")
        keys[key.name] = key
        verify_roundtrip(keys)
        new_text = serialize_keyfile(list(keys.values()))
        _write_verify_reload(
            path,
            new_text,
            previous,
            rndc_path=rndc_path,
            rndc_timeout_sec=rndc_timeout_sec,
            rndc_extra_args=rndc_extra_args,
            named_pid_path=named_pid_path,
            sighup_on_rndc_permission_denied=sighup_on_rndc_permission_denied,
        )


def remove_key(
    path: Path,
    lock_path: Path,
    name: str,
    *,
    rndc_path: Path,
    rndc_timeout_sec: float,
    rndc_extra_args: list[str],
    named_pid_path: Path | None,
    sighup_on_rndc_permission_denied: bool,
    zone_cleanup: ZoneCleanupParams | None = None,
) -> None:
    with _store_lock(lock_path):
        if not path.exists():
            raise KeyStoreError("key file does not exist")
        previous = path.read_text(encoding="utf-8")
        keys = parse_keyfile(previous)
        if name not in keys:
            raise KeyStoreError(f"key not found: {name}")
        tk = keys[name]
        if zone_cleanup is not None:
            try:
                delete_rrsets_for_tsig_key(tk, zone_cleanup)
            except ZoneCleanupError as e:
                raise KeyStoreError(f"zone cleanup failed: {e}") from e
        del keys[name]
        verify_roundtrip(keys)
        new_text = serialize_keyfile(list(keys.values()))
        _write_verify_reload(
            path,
            new_text,
            previous,
            rndc_path=rndc_path,
            rndc_timeout_sec=rndc_timeout_sec,
            rndc_extra_args=rndc_extra_args,
            named_pid_path=named_pid_path,
            sighup_on_rndc_permission_denied=sighup_on_rndc_permission_denied,
        )


def _write_verify_reload(
    path: Path,
    new_text: str,
    previous: str,
    *,
    rndc_path: Path,
    rndc_timeout_sec: float,
    rndc_extra_args: list[str],
    named_pid_path: Path | None,
    sighup_on_rndc_permission_denied: bool,
) -> None:
    st_orig = path.stat() if path.exists() else None
    _atomic_write_same_dir(path, new_text, preserved_stat=st_orig)
    try:
        on_disk = path.read_text(encoding="utf-8")
        parsed = parse_keyfile(on_disk)
        verify_roundtrip(parsed)
    except Exception as e:
        _atomic_write_same_dir(path, previous, preserved_stat=st_orig)
        raise KeyStoreError(f"post-write verification failed, restored backup: {e}") from e

    try:
        reload_named_after_key_change(
            rndc_path=rndc_path,
            rndc_timeout_sec=rndc_timeout_sec,
            rndc_extra_args=rndc_extra_args,
            named_pid_path=named_pid_path,
            sighup_on_rndc_permission_denied=sighup_on_rndc_permission_denied,
        )
    except KeyStoreError as e:
        _atomic_write_same_dir(path, previous, preserved_stat=st_orig)
        raise KeyStoreError(
            f"key file updated but reload failed (restored previous file): {e}"
        ) from e
