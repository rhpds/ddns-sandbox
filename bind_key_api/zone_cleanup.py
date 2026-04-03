"""Remove DNS RRsets associated with a TSIG key name before the key is removed from disk.

Zone cleanup **only** uses `nsupdate` to remove data: each `update delete <owner> ANY` is one
dynamic update. There is no BIND API to say “delete every RR this TSIG key created” in one
packet — you must name each owner (apex and/or children). This module either **enumerates**
owners (zone file + optional AXFR + optional freeze) or, in **nsupdate_key_only** mode, deletes
**only** RRsets at the TSIG key name itself (not subdomains like api.client.key…).
"""

from __future__ import annotations

import io
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
    """strategy: enumerate (discover names) or nsupdate_key_only (single delete at key name)."""

    zone_name: str
    strategy: str
    zone_file: Path | None
    nsupdate_path: Path
    nsupdate_server: str
    nsupdate_port: int
    timeout_sec: float
    rndc_path: Path
    rndc_extra_args: list[str]
    zone_view: str | None
    freeze_zone_before: bool
    freeze_zone_strict: bool
    enumerate_via_axfr: bool
    dig_path: Path


def _sort_deepest_first(names: list[dns.name.Name]) -> list[dns.name.Name]:
    return sorted(names, key=lambda n: len(n.labels), reverse=True)


def _rndc_zone_cmd(
    rndc_path: Path,
    rndc_extra_args: list[str],
    subcommand: str,
    zone_name: str,
    zone_view: str | None,
) -> list[str]:
    """Build `rndc freeze|thaw <zone> [in <view>]` — view optional for single-view setups."""
    cmd = [str(rndc_path), *rndc_extra_args, subcommand, zone_name]
    if zone_view:
        cmd.extend(["in", zone_view])
    return cmd


def _rndc_thaw_zone(params: ZoneCleanupParams) -> None:
    """Best-effort thaw (matches cleanup finally behavior)."""
    try:
        subprocess.run(
            _rndc_zone_cmd(
                params.rndc_path,
                params.rndc_extra_args,
                "thaw",
                params.zone_name,
                params.zone_view,
            ),
            check=False,
            capture_output=True,
            text=True,
            timeout=params.timeout_sec,
        )
    except subprocess.TimeoutExpired:
        pass


def _fqdn_node_name(name: dns.name.Name, zone_origin: dns.name.Name) -> dns.name.Name:
    """Make zone node names comparable: relative owners must be expanded to the zone apex."""
    if name.is_absolute():
        return name
    return name.derelativize(zone_origin)


def _names_matching_key(
    z: dns.zone.Zone,
    zone_origin: dns.name.Name,
    keyn: dns.name.Name,
) -> list[dns.name.Name]:
    out: list[dns.name.Name] = []
    for name in z.nodes.keys():  # type: ignore[attr-defined]
        fq = _fqdn_node_name(name, zone_origin)
        if fq == keyn or fq.is_subdomain(keyn):
            out.append(fq)
    return out


def _zone_from_axfr(
    *,
    dig_path: Path,
    zone_name: str,
    server: str,
    port: int,
    keyfile: Path,
    origin: dns.name.Name,
    timeout_sec: float,
) -> dns.zone.Zone | None:
    """Best-effort AXFR using the same TSIG key as nsupdate (needs allow-transfer)."""
    cmd = [
        str(dig_path),
        "+tcp",
        "+nocmd",
        "-k",
        str(keyfile),
        f"@{server}",
        "-p",
        str(port),
        zone_name,
        "axfr",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
        )
    except FileNotFoundError:
        return None
    if proc.returncode != 0:
        return None
    try:
        return dns.zone.from_text(
            io.StringIO(proc.stdout),
            origin=origin,
            relativize=False,
            check_origin=False,
        )
    except Exception:
        return None


def _collect_owners_for_key(
    zone_path: Path,
    zone_origin: str,
    key_fqdn: str,
    *,
    axfr_zone: dns.zone.Zone | None,
) -> list[dns.name.Name]:
    """Return distinct FQDNs under this TSIG key from the zone file and optional AXFR."""
    origin = dns.name.from_text(zone_origin)
    keyn = dns.name.from_text(key_fqdn)
    try:
        z_file = dns.zone.from_file(
            str(zone_path),
            origin=origin,
            relativize=False,
            check_origin=False,
        )
    except Exception as e:
        raise ZoneCleanupError(f"cannot parse zone file {zone_path}: {e}") from e

    merged: dict[str, dns.name.Name] = {}
    for z in (z_file, axfr_zone):
        if z is None:
            continue
        for n in _names_matching_key(z, origin, keyn):
            merged[n.to_text()] = n

    out = list(merged.values())
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
    """Send `nsupdate` with one `update delete` per owner name (see module docstring)."""
    froze = False
    zf: Path | None = None
    owners: list[dns.name.Name]

    if params.strategy == "nsupdate_key_only":
        owners = _sort_deepest_first([dns.name.from_text(tk.name)])
    else:
        zf = params.zone_file
        if zf is None or not zf.is_file():
            raise ZoneCleanupError(
                f"zone file not found: {zf!r}" if zf is not None else "zone file path not set"
            )
        if params.freeze_zone_before:
            try:
                proc = subprocess.run(
                    _rndc_zone_cmd(
                        params.rndc_path,
                        params.rndc_extra_args,
                        "freeze",
                        params.zone_name,
                        params.zone_view,
                    ),
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=params.timeout_sec,
                )
            except subprocess.TimeoutExpired as e:
                raise ZoneCleanupError(f"rndc freeze timed out: {e}") from e
            if proc.returncode == 0:
                froze = True
            elif params.freeze_zone_strict:
                err = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
                raise ZoneCleanupError(
                    f"rndc freeze failed: {err}. "
                    "Set BIND_KEY_API_ZONE_VIEW if the zone is in a view, "
                    "or set BIND_KEY_API_FREEZE_ZONE_BEFORE_CLEANUP=false / "
                    "BIND_KEY_API_FREEZE_ZONE_STRICT=false."
                )

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".key",
            delete=False,
            encoding="utf-8",
        ) as tf:
            kpath = Path(tf.name)
        try:
            _write_tsig_keyfile(kpath, tk)
            if params.strategy != "nsupdate_key_only":
                assert zf is not None
                axfr_zone: dns.zone.Zone | None = None
                if params.enumerate_via_axfr:
                    origin = dns.name.from_text(params.zone_name)
                    axfr_zone = _zone_from_axfr(
                        dig_path=params.dig_path,
                        zone_name=params.zone_name,
                        server=params.nsupdate_server,
                        port=params.nsupdate_port,
                        keyfile=kpath,
                        origin=origin,
                        timeout_sec=params.timeout_sec,
                    )
                owners = _collect_owners_for_key(
                    zf,
                    params.zone_name,
                    tk.name,
                    axfr_zone=axfr_zone,
                )

            # Freeze disables dynamic updates; nsupdate must run after thaw.
            if froze:
                _rndc_thaw_zone(params)
                froze = False

            lines = [
                f"server {params.nsupdate_server} {params.nsupdate_port}",
                f"zone {params.zone_name}",
            ]
            for n in owners:
                lines.append(f"update delete {n.to_text()} ANY")
            lines.append("send")
            script = "\n".join(lines) + "\n"

            try:
                proc = subprocess.run(
                    [str(params.nsupdate_path), "-k", str(kpath)],
                    input=script,
                    text=True,
                    capture_output=True,
                    timeout=params.timeout_sec,
                )
            except FileNotFoundError as e:
                raise ZoneCleanupError(
                    f"nsupdate not found at {params.nsupdate_path} "
                    f"(install bind9-utils / bind-utils, or set BIND_KEY_API_NSUPDATE_PATH)"
                ) from e
            if proc.returncode != 0:
                msg = (proc.stderr or proc.stdout or "").strip() or f"exit {proc.returncode}"
                err = f"nsupdate failed: {msg}"
                umsg = msg.upper()
                if "NOTAUTH" in umsg:
                    err += (
                        " (confirm BIND_KEY_API_ZONE_NAME matches named.conf; TSIG and update-policy; "
                        "BIND_KEY_API_NSUPDATE_SERVER reaches the primary.)"
                    )
                elif "FROZEN" in umsg or (
                    "REFUSED" in umsg and "frozen" in msg.lower()
                ):
                    err += (
                        " (zone was frozen: cleanup thaws before nsupdate in current versions; "
                        "if you still see this, run rndc thaw manually and retry.)"
                    )
                raise ZoneCleanupError(err)
        finally:
            try:
                kpath.unlink(missing_ok=True)
            except OSError:
                pass
    finally:
        if froze:
            _rndc_thaw_zone(params)
