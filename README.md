# bind-key-api

HTTP API for managing **BIND TSIG keys** in a key file on disk. It adds, lists, and deletes `key { ... };` blocks, runs **`rndc reload`** (with **`reconfig`** / **SIGHUP** fallbacks when needed), and optionally cleans up zone records on delete when a dynamic-DNS-style zone is configured.

Typical use: automate TSIG credentials for clients that update DNS via `nsupdate`, without editing `named.conf` by hand for every key.

## Requirements

- **BIND 9** (`named`) on the same host or reachable for **`rndc`** (and **`nsupdate`** if you use zone cleanup on DELETE).
- **`rndc`** authentication (for example `/etc/bind/rndc.key`) so the service can reload configuration after the key file changes.
- A **writable TSIG key file** path (and directory for the companion lock file `*.key.lock`).
- **Python 3.11+** for a bare-metal install; the container image bundles **Python 3.12** and **`bind9-utils`**.

## HTTP API

All endpoints except **`GET /health`** require:

```http
Authorization: Bearer <BIND_KEY_API_AUTH_TOKEN>
```

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check (`{"status":"ok"}`). |
| `GET` | `/keys` | List TSIG key names. |
| `POST` | `/keys` | Create a key: JSON `{"name":"<dns-name>","algorithm":"hmac-sha256"}` (algorithm optional, default `hmac-sha256`). Returns the generated **secret** once. |
| `DELETE` | `/keys/{name}` | Remove the key; optional zone cleanup (see configuration). |

Key names must match the server’s validation rules (DNS-like names; see the API’s allowed character set).

Interactive documentation is available from the app via **OpenAPI** (for example `/docs` when using Uvicorn with defaults).

## Configuration

Environment variables use the prefix **`BIND_KEY_API_`**. The important ones:

| Variable | Purpose |
|----------|---------|
| `BIND_KEY_API_AUTH_TOKEN` | **Required.** Bearer token (minimum 16 characters). |
| `BIND_KEY_API_BIND_KEYS_PATH` | Path to the TSIG key file (default in code: `/etc/bind/keys/ddns.example.com.key`). |
| `BIND_KEY_API_RNDC_EXTRA_ARGS` | Extra `rndc` arguments, often `["-k","/etc/bind/rndc.key"]` as JSON or shell-style. |
| `BIND_KEY_API_ZONE_FILE_PATH` | Zone master file, used if you enable RRset cleanup on delete. |
| `BIND_KEY_API_DELETE_ZONE_RRSETS_ON_KEY_DELETE` | If `true`, DELETE may remove names in the zone that match the TSIG key name (and subdomains). Set `false` for tests or if you manage the zone elsewhere. |
| `BIND_KEY_API_NSUPDATE_PATH` | Full path to `nsupdate` (default `/usr/bin/nsupdate`). On RHEL/Fedora use `/usr/sbin/nsupdate` if needed. |

Additional options (timeouts, `named` PID file for SIGHUP fallback, view name for `rndc freeze`, etc.) are documented on the **Settings** model in `bind_key_api/settings.py`. A fuller commented example lives in `deploy/bind-key-api.env.example`.

## Run locally (development)

From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
export BIND_KEY_API_AUTH_TOKEN="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
# Point paths at files your user can read/write, or run tests only:
pytest
```

To run the server against real BIND paths (usually as root or a user with access to `/etc/bind`):

```bash
export BIND_KEY_API_BIND_KEYS_PATH=/etc/bind/keys/your-zone.key
export BIND_KEY_API_RNDC_EXTRA_ARGS='["-k","/etc/bind/rndc.key"]'
uvicorn bind_key_api.main:app --host 127.0.0.1 --port 8080
```

## Container (Docker / Podman)

The **`Dockerfile`** builds an image that includes **`rndc`** and **`nsupdate`**. **`named`** should run on the **host**; the usual approach is **host networking** so `rndc` can reach `127.0.0.1:953`, and bind-mounts for keys, `rndc.key`, the zone file (if used), and often `/run/named` for the **`named.pid`** SIGHUP fallback.

```bash
cp .env.example .env
# Edit .env — set BIND_KEY_API_AUTH_TOKEN to a long random secret.
docker compose up -d --build
# or: podman compose up -d --build
```

Compose defaults and volume paths are in **`compose.yaml`**; adjust them to match your host’s BIND layout. More detail (including a `podman run` example and SELinux volume labels) is in **`deploy/container/README.md`**.

## Production install (systemd)

For a venv under `/opt` and a **systemd** unit, see **`deploy/README.md`**:

```bash
sudo ./deploy/install.sh
# Edit /etc/bind-key-api/bind-key-api.env, then:
sudo systemctl enable --now bind-key-api
```

## Project layout

| Path | Role |
|------|------|
| `bind_key_api/` | FastAPI app, TSIG parse/serialize, locked key-file store, zone cleanup, reload logic. |
| `deploy/` | systemd install scripts, env example, container notes. |
| `tests/` | Pytest suite. |
