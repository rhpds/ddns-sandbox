from __future__ import annotations

import json
import shlex
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="BIND_KEY_API_", extra="ignore")

    bind_keys_path: Path = Field(
        default=Path("/etc/bind/keys/ddns.example.com.key"),
        description="Path to the TSIG key file managed by this service",
    )
    auth_token: str = Field(
        ...,
        min_length=16,
        description="Bearer token: Authorization: Bearer <token>. Env: BIND_KEY_API_AUTH_TOKEN",
    )
    rndc_path: Path = Field(default=Path("/usr/sbin/rndc"))
    rndc_timeout_sec: float = Field(default=30.0, ge=1.0, le=120.0)
    rndc_extra_args: list[str] = Field(
        default_factory=list,
        description="Extra args before reload. Env: JSON array or shell-style string.",
    )
    named_pid_path: Path | None = Field(
        default=None,
        description=(
            "PID file for named (SIGHUP fallback). Default: first of "
            "/run/named/named.pid, /var/run/named/named.pid that exists."
        ),
    )
    sighup_on_rndc_permission_denied: bool = Field(
        default=True,
        description=(
            "If rndc reload fails with permission denied (common on some BIND 9.10 "
            "multi-view setups), send SIGHUP to named using named_pid_path."
        ),
    )
    delete_zone_rrsets_on_key_delete: bool = Field(
        default=False,
        description=(
            "Before removing a TSIG key, delete DNS names in the zone file that are "
            "this key name or a subdomain (update-policy selfsub). When true, "
            "BIND_KEY_API_ZONE_NAME and BIND_KEY_API_ZONE_FILE_PATH are required."
        ),
    )
    zone_name: str = Field(
        default="",
        description=(
            "Zone apex exactly as in named.conf (e.g. dyn.redhatworkshops.io). "
            "Required when DELETE_ZONE_RRSETS_ON_KEY_DELETE is true."
        ),
    )
    zone_file_path: Path | None = Field(
        default=None,
        description=(
            "Master zone file path for enumerating names to delete (see zone_cleanup). "
            "Required when DELETE_ZONE_RRSETS_ON_KEY_DELETE is true."
        ),
    )
    nsupdate_server: str = Field(default="127.0.0.1")
    nsupdate_port: int = Field(default=53, ge=1, le=65535)
    nsupdate_path: Path = Field(
        default=Path("/usr/bin/nsupdate"),
        description=(
            "Path to nsupdate (bind9-utils). Debian/Ubuntu: /usr/bin/nsupdate; "
            "RHEL/Fedora: often /usr/sbin/nsupdate."
        ),
    )
    zone_view: str | None = Field(
        default=None,
        description="BIND view containing the zone (for rndc freeze/thaw if enabled).",
    )
    freeze_zone_before_cleanup: bool = Field(
        default=True,
        description=(
            "Run rndc freeze/thaw so the dynamic journal is merged into the zone file "
            "before enumerating names to delete. Without this, names added only via "
            "nsupdate (journal) are often missing from the file and will not be removed. "
            "Set false only if the zone is static or you use another cleanup path. "
            "Multi-view: set BIND_KEY_API_ZONE_VIEW if freeze without view fails."
        ),
    )
    zone_cleanup_enumerate_via_axfr: bool = Field(
        default=True,
        description=(
            "Also list names via `dig … axfr` with the TSIG key (same server/port as nsupdate). "
            "Catches RRs the on-disk file still does not show after freeze. Requires "
            "allow-transfer for this key (often already true if the key updates the zone). "
            "Set false if AXFR is denied and you rely on the zone file only."
        ),
    )
    dig_path: Path = Field(
        default=Path("/usr/bin/dig"),
        description="Path to `dig` (bind9-dnsutils / bind-utils) for optional AXFR enumeration.",
    )

    @field_validator("named_pid_path", mode="before")
    @classmethod
    def _empty_named_pid_path(cls, v: Any) -> Path | None:
        if v is None or v == "":
            return None
        return Path(v)

    @field_validator("rndc_extra_args", mode="before")
    @classmethod
    def _coerce_rndc_extra_args(cls, v: Any) -> list[str]:
        if v is None or v == "":
            return []
        if isinstance(v, list):
            return [str(x) for x in v]
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return []
            try:
                parsed = json.loads(s)
                if isinstance(parsed, list):
                    return [str(x) for x in parsed]
            except json.JSONDecodeError:
                pass
            return shlex.split(s)
        raise TypeError("rndc_extra_args must be a list or string")

    @field_validator("zone_file_path", mode="before")
    @classmethod
    def _empty_zone_file_path(cls, v: Any) -> Path | None:
        if v is None or v == "":
            return None
        return Path(v)

    @model_validator(mode="after")
    def _require_zone_identity_when_cleanup_enabled(self) -> Settings:
        if not self.delete_zone_rrsets_on_key_delete:
            return self
        zn = (self.zone_name or "").strip()
        if not zn:
            raise ValueError(
                "BIND_KEY_API_ZONE_NAME must be set to your zone apex from named.conf "
                "(e.g. dyn.redhatworkshops.io) when BIND_KEY_API_DELETE_ZONE_RRSETS_ON_KEY_DELETE is true."
            )
        if zn == "ddns.example.com":
            raise ValueError(
                "BIND_KEY_API_ZONE_NAME must not be left as the old placeholder "
                "ddns.example.com; set it to your real zone name."
            )
        if self.zone_file_path is None:
            raise ValueError(
                "BIND_KEY_API_ZONE_FILE_PATH must be set to your zone master file "
                "when BIND_KEY_API_DELETE_ZONE_RRSETS_ON_KEY_DELETE is true."
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
