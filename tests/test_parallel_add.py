"""Stress test: many concurrent POST /keys (file lock + unique names)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest
from fastapi.testclient import TestClient

import bind_key_api.store as store


def _post_add(i: int) -> tuple[int, dict]:
    # TestClient is not thread-safe; use one client per worker.
    from bind_key_api.main import app

    with TestClient(app) as client:
        r = client.post(
            "/keys",
            headers={"Authorization": "Bearer test-token-1234567890abc"},
            json={"name": f"parallel-{i:02d}.client.ddns.example.com"},
        )
        return r.status_code, r.json()


def test_20_parallel_add_requests(app_env, monkeypatch):
    monkeypatch.setenv("BIND_KEY_API_SIGHUP_ON_RNDC_PERMISSION_DENIED", "false")
    monkeypatch.setattr(store, "reload_named_after_key_change", lambda **kw: None)

    from bind_key_api.settings import get_settings

    get_settings.cache_clear()

    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = [pool.submit(_post_add, i) for i in range(20)]
        results = [f.result() for f in as_completed(futures)]

    assert len(results) == 20
    for code, body in results:
        assert code == 201, body
        assert "secret" in body and body["secret"]
        assert body["algorithm"] == "hmac-sha256"

    names = {b["name"] for _, b in results}
    assert len(names) == 20
    secrets = {b["secret"] for _, b in results}
    assert len(secrets) == 20
