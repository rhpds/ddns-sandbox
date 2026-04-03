from __future__ import annotations

import json
import shlex
from functools import lru_cache
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator
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
        default=True,
        description=(
            "Before removing a TSIG key, delete DNS names in the zone file that are "
            "this key name or a subdomain (update-policy selfsub). Set false for tests."
        ),
    )
    zone_name: str = Field(default="ddns.example.com")
    zone_file_path: Path = Field(
        default=Path("/etc/bind/db.ddns.example.com"),
        description="Master zone file used to enumerate names to delete (see zone_cleanup).",
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
        default="ddnsinternal",
        description="BIND view containing the zone (for rndc freeze/thaw if enabled).",
    )
    freeze_zone_before_cleanup: bool = Field(
        default=False,
        description=(
            "Run rndc freeze/thaw so the journal is merged into the zone file before "
            "enumerating names (needed if some RRs exist only in the journal)."
        ),
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


@lru_cache
def get_settings() -> Settings:
    return Settings()
