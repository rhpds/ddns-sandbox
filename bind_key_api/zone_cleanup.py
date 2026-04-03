"""Remove DNS RRsets associated with a TSIG key name before the key is removed from disk."""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

import dns.name
import dns.zone

from bind_key_api.tsig import TsigKey


class ZoneCleanupError(RuntimeError):
    pass


@dataclass(frozen=True)
class ZoneCleanupParams:
    zone_name: str
    zone_file: Path
    nsupdate_server: str
    nsupdate_port: int
    timeout_sec: float
    rndc_path: Path
    rndc_extra_args: list[str]
    zone_view: str | None
    freeze_zone_before: bool


def _sort_deepest_first(names: list[dns.name.Name]) -> list[dns.name.Name]:
    return sorted(names, key=lambda n: len(n.labels), reverse=True)


def _collect_owners_for_key(zone_path: Path, zone_origin: str, key_fqdn: str) -> list[dns.name.Name]:
    """Return all zone node names that are the key name or a subdomain of it."""
    origin = dns.name.from_text(zone_origin)
    keyn = dns.name.from_text(key_fqdn)
    try:
        z = dns.zone.from_file(str(zone_path), origin=origin, relativize=False)
    except Exception as e:
        raise ZoneCleanupError(f"cannot parse zone file {zone_path}: {e}") from e

    out: list[dns.name.Name] = []
    for name in z.nodes.keys():  # type: ignore[attr-defined]
        if name == keyn or name.is_subdomain(keyn):
            out.append(name)
    if not out:
        out.append(keyn)
    return _sort_deepest_first(out)


def _write_tsig_keyfile(path: Path, tk: TsigKey) -> None:
    text = (
        f'key "{tk.name}" {{\n'
        f"\talgorithm {tk.algorithm};\n"
        f'\tsecret "{tk.secret_b64}";\n'
        "};\n"
    )
    path.write_text(text, encoding="utf-8")


def delete_rrsets_for_tsig_key(tk: TsigKey, params: ZoneCleanupParams) -> None:
    """
    Run nsupdate to delete ANY rrsets at names under this key (selfsub-style).
    Must be called while the key is still present in named's key file.

    Limitations: only names present in zone_file are seen. Dynamic-only RRs that
    exist only in the journal are missed unless journal is merged (rndc freeze).
    """
    zf = params.zone_file
    if not zf.is_file():
        raise ZoneCleanupError(f"zone file not found: {zf}")

    froze = False
    try:
        if params.freeze_zone_before and params.zone_view:
            try:
                subprocess.run(
                    [
                        str(params.rndc_path),
                        *params.rndc_extra_args,
                        "freeze",
                        params.zone_name,
                        "in",
                        params.zone_view,
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=params.timeout_sec,
                )
                froze = True
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
                raise ZoneCleanupError(f"rndc freeze failed: {e}") from e

        owners = _collect_owners_for_key(zf, params.zone_name, tk.name)

        lines = [
            f"server {params.nsupdate_server} {params.nsupdate_port}",
            f"zone {params.zone_name}",
        ]
        for n in owners:
            lines.append(f"update delete {n.to_text()} ANY")
        lines.append("send")
        script = "\n".join(lines) + "\n"

        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".key",
            delete=False,
            encoding="utf-8",
        ) as tf:
            kpath = Path(tf.name)
        try:
            _write_tsig_keyfile(kpath, tk)
            proc = subprocess.run(
                ["nsupdate", "-k", str(kpath)],
                input=script,
                text=True,
                capture_output=True,
                timeout=params.timeout_sec,
            )
            if proc.returncode != 0:
                msg = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
                raise ZoneCleanupError(f"nsupdate failed: {msg}")
        finally:
            try:
                kpath.unlink(missing_ok=True)
            except OSError:
                pass
    finally:
        if froze and params.zone_view:
            try:
                subprocess.run(
                    [
                        str(params.rndc_path),
                        *params.rndc_extra_args,
                        "thaw",
                        params.zone_name,
                        "in",
                        params.zone_view,
                    ],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=params.timeout_sec,
                )
            except subprocess.TimeoutExpired:
                pass
