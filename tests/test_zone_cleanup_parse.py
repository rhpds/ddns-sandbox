"""Zone file parsing for cleanup must tolerate missing on-disk SOA (common for dynamic zones)."""

from pathlib import Path

from bind_key_api.zone_cleanup import (
    _collect_owners_for_key,
    _fqdn_node_name,
    _rndc_zone_cmd,
)


def test_collect_owners_without_soa_at_origin(tmp_path: Path) -> None:
    # Mirrors journal-heavy dynamic zones: updates exist but SOA is not in the plain file yet.
    zf = tmp_path / "dyn.example.zone"
    zf.write_text(
        "$TTL 3600\n"
        "$ORIGIN dyn.example.\n"
        "; no SOA here — allowed when check_origin=False (dynamic zone stub)\n"
        "client._update 3600 IN A 192.0.2.1\n",
        encoding="utf-8",
    )
    owners = _collect_owners_for_key(
        zf,
        "dyn.example",
        "client._update.dyn.example",
        axfr_zone=None,
    )
    texts = {n.to_text() for n in owners}
    assert "client._update.dyn.example." in texts


def test_fqdn_node_name_expands_relative_owner() -> None:
    import dns.name

    origin = dns.name.from_text("dyn.example")
    rel = dns.name.from_text("api.client", None)  # type: ignore[arg-type]
    fq = _fqdn_node_name(rel, origin)
    assert fq.to_text() == "api.client.dyn.example."


def test_rndc_freeze_cmd_optional_view() -> None:
    assert _rndc_zone_cmd(Path("/usr/sbin/rndc"), [], "freeze", "dyn.example.com", None) == [
        "/usr/sbin/rndc",
        "freeze",
        "dyn.example.com",
    ]
    assert _rndc_zone_cmd(Path("/usr/sbin/rndc"), [], "thaw", "dyn.example.com", "internal") == [
        "/usr/sbin/rndc",
        "thaw",
        "dyn.example.com",
        "in",
        "internal",
    ]
