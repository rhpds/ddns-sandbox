import pytest

from bind_key_api.settings import get_settings


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    monkeypatch.setenv("BIND_KEY_API_AUTH_TOKEN", "test-token-1234567890abc")
    monkeypatch.setenv("BIND_KEY_API_BIND_KEYS_PATH", str(tmp_path / "ddns.example.com.key"))
    monkeypatch.setenv("BIND_KEY_API_DELETE_ZONE_RRSETS_ON_KEY_DELETE", "false")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()
