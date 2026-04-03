"""Zone file parsing for cleanup must tolerate missing on-disk SOA (common for dynamic zones)."""

import tempfile
from pathlib import Path

import dns.name

from bind_key_api.zone_cleanup import _collect_owners_for_key


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
    owners = _collect_owners_for_key(zf, "dyn.example", "client._update.dyn.example")
    texts = {n.to_text() for n in owners}
    assert "client._update.dyn.example." in texts
