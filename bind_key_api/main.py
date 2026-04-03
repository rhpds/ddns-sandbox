from __future__ import annotations

import hmac
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from bind_key_api.settings import Settings, get_settings
from bind_key_api.store import KeyStoreError, add_key, read_keys, remove_key
from bind_key_api.zone_cleanup import ZoneCleanupParams
from bind_key_api.tsig import (
    ALLOWED_ALGORITHMS,
    TsigKey,
    TsigParseError,
    generate_tsig_secret,
    validate_key_name,
)

security = HTTPBearer(auto_error=False)


def verify_token(
    creds: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing or invalid Authorization header",
        )
    if not hmac.compare_digest(creds.credentials, settings.auth_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid token",
        )


class KeyAddBody(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    algorithm: str = Field(default="hmac-sha256")


class KeyCreatedOut(BaseModel):
    name: str
    secret: str
    algorithm: str


class KeyListOut(BaseModel):
    names: list[str]


def create_app() -> FastAPI:
    # Avoid 307 redirects when clients use /keys/{name}/ vs /keys/{name} (DELETE must not bounce).
    app = FastAPI(
        title="BIND TSIG key API",
        version="1.0.0",
        redirect_slashes=False,
    )

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/keys", dependencies=[Depends(verify_token)])
    def list_keys(settings: Annotated[Settings, Depends(get_settings)]) -> KeyListOut:
        lock_path = settings.bind_keys_path.with_name(settings.bind_keys_path.name + ".lock")
        try:
            keys = read_keys(settings.bind_keys_path, lock_path=lock_path)
        except TsigParseError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"key file is unreadable or corrupt: {e}",
            ) from e
        return KeyListOut(names=sorted(keys.keys()))

    @app.post("/keys", status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_token)])
    def create_key(
        body: KeyAddBody,
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> KeyCreatedOut:
        try:
            validate_key_name(body.name)
        except TsigParseError as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)) from e

        algo = body.algorithm.strip().lower()
        if algo not in ALLOWED_ALGORITHMS:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"unsupported algorithm (allowed: {sorted(ALLOWED_ALGORITHMS)})",
            )
        secret_b64 = generate_tsig_secret()
        key = TsigKey(name=body.name, algorithm=algo, secret_b64=secret_b64)
        lock_path = settings.bind_keys_path.with_name(settings.bind_keys_path.name + ".lock")
        try:
            add_key(
                settings.bind_keys_path,
                lock_path,
                key,
                rndc_path=settings.rndc_path,
                rndc_timeout_sec=settings.rndc_timeout_sec,
                rndc_extra_args=settings.rndc_extra_args,
                named_pid_path=settings.named_pid_path,
                sighup_on_rndc_permission_denied=settings.sighup_on_rndc_permission_denied,
            )
        except TsigParseError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"existing key file is corrupt: {e}",
            ) from e
        except KeyStoreError as e:
            msg = str(e)
            if "already exists" in msg:
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=msg) from e
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=msg) from e

        return KeyCreatedOut(name=body.name, secret=secret_b64, algorithm=algo)

    @app.delete("/keys/{name}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_token)])
    def delete_key(
        name: str,
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> None:
        try:
            validate_key_name(name)
        except TsigParseError as e:
            raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e)) from e

        lock_path = settings.bind_keys_path.with_name(settings.bind_keys_path.name + ".lock")
        zone_cleanup: ZoneCleanupParams | None = None
        if settings.delete_zone_rrsets_on_key_delete:
            zone_cleanup = ZoneCleanupParams(
                zone_name=settings.zone_name,
                zone_file=settings.zone_file_path,
                nsupdate_path=settings.nsupdate_path,
                nsupdate_server=settings.nsupdate_server,
                nsupdate_port=settings.nsupdate_port,
                timeout_sec=settings.rndc_timeout_sec,
                rndc_path=settings.rndc_path,
                rndc_extra_args=settings.rndc_extra_args,
                zone_view=settings.zone_view,
                freeze_zone_before=settings.freeze_zone_before_cleanup,
            )
        try:
            remove_key(
                settings.bind_keys_path,
                lock_path,
                name,
                rndc_path=settings.rndc_path,
                rndc_timeout_sec=settings.rndc_timeout_sec,
                rndc_extra_args=settings.rndc_extra_args,
                named_pid_path=settings.named_pid_path,
                sighup_on_rndc_permission_denied=settings.sighup_on_rndc_permission_denied,
                zone_cleanup=zone_cleanup,
            )
        except TsigParseError as e:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"key file is corrupt: {e}",
            ) from e
        except KeyStoreError as e:
            msg = str(e)
            if "key not found" in msg or "key file does not exist" in msg:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=msg) from e
            raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=msg) from e

    return app


app = create_app()
