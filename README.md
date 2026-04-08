# bind-key-api

HTTP API for managing **BIND TSIG keys** in a key file on disk. It adds, lists, and deletes `key { ... };` blocks, runs **`rndc reload`** (with **`reconfig`** / **SIGHUP** fallbacks when needed), and optionally cleans up zone records on delete when a dynamic-DNS-style zone is configured.

Typical use: automate TSIG credentials for clients that update DNS via `nsupdate`, without editing `named.conf` by hand for every key.

## Requirements

- **BIND 9** (`named`) on the same host or reachable for **`rndc`** (and **`nsupdate`** if you use zone cleanup on DELETE).
- **`rndc`** authentication (for example `/etc/bind/rndc.key`) so the service can reload configuration after the key file changes.
- A **writable TSIG key file** path (and directory for the companion lock file `*.key.lock`).
- **Python 3.11+** for a bare-metal install; the container image bundles **Python 3.12**, **`bind9-utils`** (`rndc`), and **`bind9-dnsutils`** (`nsupdate`).

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
| `BIND_KEY_API_ZONE_NAME` | Zone apex **exactly** as in `named.conf` (e.g. `dyn.redhatworkshops.io`). **Required** when `DELETE_ZONE_RRSETS_ON_KEY_DELETE` is `true`. |
| `BIND_KEY_API_ZONE_FILE_PATH` | Master zone file path on this host. **Required** when zone cleanup on delete is enabled. |
| `BIND_KEY_API_DELETE_ZONE_RRSETS_ON_KEY_DELETE` | Default `false`. If `true`, DELETE also runs `nsupdate` to remove RRsets for that key; then `ZONE_NAME` and `ZONE_FILE_PATH` must be set (never rely on example defaults). |
| `BIND_KEY_API_NSUPDATE_PATH` | Full path to `nsupdate` (default `/usr/bin/nsupdate`). The Docker image sets `/usr/local/bin/nsupdate` (symlink to wherever `bind9-utils` installs the binary). On RHEL/Fedora hosts, `/usr/sbin/nsupdate` is common. |
| `BIND_KEY_API_NSUPDATE_SERVER` / `BIND_KEY_API_NSUPDATE_PORT` | Address and port `nsupdate` uses for the dynamic update (default `127.0.0.1:53`). Must reach the **primary** that accepts RFC 2136 updates for this zone. |

Additional options (timeouts, `named` PID file for SIGHUP fallback, view name for `rndc freeze`, etc.) are documented on the **Settings** model in `bind_key_api/settings.py`. A fuller commented example lives in `deploy/bind-key-api.env.example`.

### Zone cleanup: journal vs zone file vs AXFR

Names added only via **dynamic update** often live in the **journal** (`.jnl`) until BIND merges them. Cleanup lists names from **AXFR** (dnspython, same TSIG as updates) plus the zone file when **`BIND_KEY_API_ZONE_CLEANUP_ENUMERATE_VIA_AXFR`** is on (default). **`allow-transfer`** for the TSIG key is strongly recommended so AXFR sees all names. Optional **`rndc freeze`** (`BIND_KEY_API_FREEZE_ZONE_BEFORE_CLEANUP`, default **false**) merges the journal into the master file before reading it; while frozen, **dynamic updates are refused**, so leave freeze **off** unless you know you need it. If DELETE fails with **REFUSED / zone is frozen**, the API also runs a **best-effort `rndc thaw`** before **`nsupdate`** when it did not freeze the zone itself (clears stuck state). If it still fails, run **`rndc thaw <zone>`** on the BIND host (with **`in <view>`** if applicable), verify **`BIND_KEY_API_RNDC_PATH`** / **`RNDC_EXTRA_ARGS`** reach that **`named`**, set **`BIND_KEY_API_FREEZE_ZONE_BEFORE_CLEANUP=false`** if you had enabled freeze, or disable cleanup with **`BIND_KEY_API_DELETE_ZONE_RRSETS_ON_KEY_DELETE=false`** and remove DNS names manually.

### Zone cleanup (`nsupdate`) and `NOTAUTH`

If DELETE returns **`zone cleanup failed: nsupdate failed: … NOTAUTH`**, BIND rejected the dynamic update. Typical causes:

1. **Wrong target for `nsupdate`** — With **bridge** networking, `127.0.0.1` is the container itself, not `named` on the host. Use **host networking** (`network_mode: host` in Compose), or set **`BIND_KEY_API_NSUPDATE_SERVER`** to the host’s IP (or the DNS master’s IP if it is remote).
2. **TSIG** — The key name and secret in the managed key file must match what **`named` loads** (same `key "name" { … }` block). Reload/reconfig after key changes.
3. **`update-policy` / `allow-update`** — The policy must allow this TSIG key to remove the RRsets being deleted (often `grant <key-name> …` for the same name your clients use for DDNS).
4. **Primary only** — Updates must be sent to the **hidden primary / MNAME** that accepts updates, not to a secondary-only host.

To confirm TSIG and policy, run **`nsupdate -k`** manually with the same key file and a small update script.

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
uvicorn bind_key_api.main:app --host 0.0.0.0 --port 8080
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
