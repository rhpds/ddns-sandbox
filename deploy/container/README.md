# Container image (Podman / Docker)

The image includes **Python 3.12**, **pip-installed** `bind-key-api`, and **`bind9-utils`** (`rndc`, `nsupdate`).

## Build

From the repository root:

```bash
podman build -t bind-key-api:latest .
# or
docker build -t bind-key-api:latest .
```

`Dockerfile` is standard OCI; Podman uses it as-is (you can `ln -s Dockerfile Containerfile` if you prefer that name).

## Run (host runs BIND)

`named` must be on the **host**. The API needs:

- The **TSIG key file** and **lock file** directory (writable)
- **`rndc.key`** to run `rndc` / `reconfig` / reload fallback
- **Zone file** if you use **zone cleanup on DELETE**
- **`/run/named`** so **SIGHUP** can read **`named.pid`** (optional but recommended)

**Host networking** is the least painful way for `rndc` to reach `127.0.0.1:953`:

```bash
podman run --rm -d --name bind-key-api \
  --network host \
  --env-file .env \
  -e BIND_KEY_API_BIND_KEYS_PATH=/etc/bind/keys/ddns.example.com.key \
  -e BIND_KEY_API_RNDC_EXTRA_ARGS='["-k","/etc/bind/rndc.key"]' \
  -e BIND_KEY_API_ZONE_FILE_PATH=/etc/bind/db.ddns.example.com \
  -v /etc/bind/keys:/etc/bind/keys \
  -v /etc/bind/rndc.key:/etc/bind/rndc.key:ro \
  -v /etc/bind/db.ddns.example.com:/etc/bind/db.ddns.example.com \
  -v /run/named:/run/named \
  bind-key-api:latest
```

Create `.env` with at least:

```bash
BIND_KEY_API_AUTH_TOKEN=your-long-secret
```

## Compose

```bash
cp .env.example .env
# edit .env — set BIND_KEY_API_AUTH_TOKEN
podman compose up -d --build
```

On **SELinux** (Fedora), add `:z` or `:Z` to volume mounts if you hit permission errors.

## Port publishing

With **`--network host`**, the app listens on **`UVICORN_HOST`:`UVICORN_PORT`** (default in **Dockerfile** `0.0.0.0:8080`; **compose** sets `127.0.0.1:8080`).  
If you **do not** use host networking, you must still reach **`named`** for `rndc` (e.g. extra routes or publishing port **953** — not covered here).

## Root in the container

The process runs as **root** so it can match typical host **permissions** on `/etc/bind`. For a stricter setup, use a user with **`SupplementaryGroups=bind`**-style mapping and narrow volume mounts.
