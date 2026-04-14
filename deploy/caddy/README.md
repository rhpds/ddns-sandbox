# Caddy (HTTPS in front of bind-key-api)

The **`https`** Compose profile runs **[Caddy](https://caddyserver.com/)** with **`deploy/caddy/Caddyfile`**: it obtains and renews **Let’s Encrypt** certificates using the default **HTTP-01** challenge (Caddy listens on **80** and **443** on the host).

## Requirements

- **`CADDY_DOMAIN`** in **`.env`**: FQDN that resolves to this server (public **A** / **AAAA**).
- **Ports 80 and 443** reachable from the internet (for Let’s Encrypt).
- **`UVICORN_HOST=127.0.0.1`** in **`.env`** so **bind-key-api** only binds on localhost; clients use **HTTPS** to Caddy, not raw **8080**.

## Start

```bash
# .env must include at least: CADDY_DOMAIN, UVICORN_HOST=127.0.0.1, BIND_KEY_API_*, etc.
docker compose --profile https up -d --build
# or: podman compose --profile https up -d --build
```

Certificates and Caddy state are stored in Docker volumes **`caddy_data`** and **`caddy_config`**.

## Optional: ACME account email

Let’s Encrypt expiry notices: add a **global** block at the top of **`Caddyfile`** (before the site block):

```caddyfile
{
	email you@example.com
}
```

Reload Caddy after editing (`docker compose restart caddy`).

## Staging / tests

For the Let’s Encrypt **staging** CA (avoids rate limits while testing), add inside the site block:

```caddyfile
tls {
	ca https://acme-staging-v02.api.letsencrypt.org/directory
}
```

Remove for production.

## Without Caddy

Omit the profile (default): **`docker compose up -d`** runs only **bind-key-api** (set **`UVICORN_HOST`** as needed, e.g. **`0.0.0.0`** for direct access on **8080**).
