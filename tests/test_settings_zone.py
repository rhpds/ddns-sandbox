"""Zone-related Settings validation when delete-on-key-delete is enabled."""

from pathlib import Path

import pytest
from pydantic import ValidationError

from bind_key_api.settings import Settings


def test_zone_cleanup_requires_zone_name_and_file() -> None:
    with pytest.raises(ValidationError, match="BIND_KEY_API_ZONE_NAME"):
        Settings(
            auth_token="x" * 20,
            delete_zone_rrsets_on_key_delete=True,
            zone_name="",
            zone_file_path=Path("/tmp/z.zone"),
        )


def test_zone_cleanup_rejects_placeholder_zone_name() -> None:
    with pytest.raises(ValidationError, match="ddns.example.com"):
        Settings(
            auth_token="x" * 20,
            delete_zone_rrsets_on_key_delete=True,
            zone_name="ddns.example.com",
            zone_file_path=Path("/tmp/z.zone"),
        )


def test_zone_cleanup_ok_when_configured() -> None:
    s = Settings(
        auth_token="x" * 20,
        delete_zone_rrsets_on_key_delete=True,
        zone_name="dyn.redhatworkshops.io",
        zone_file_path=Path("/var/named/dyn.redhatworkshops.io.zone"),
    )
    assert s.zone_name == "dyn.redhatworkshops.io"


def test_zone_optional_when_cleanup_disabled() -> None:
    s = Settings(
        auth_token="x" * 20,
        delete_zone_rrsets_on_key_delete=False,
        zone_name="",
        zone_file_path=None,
    )
    assert s.zone_name == ""
