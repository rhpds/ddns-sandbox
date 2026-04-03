# OCI image for bind-key-api (Docker / Podman).
# Typical use: host runs named; container mounts /etc/bind keys + rndc key, uses --network host.

FROM python:3.12-slim-bookworm AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bind9-utils \
    && rm -rf /var/lib/apt/lists/* \
    && export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
    && NSU="$(command -v nsupdate 2>/dev/null || true)" \
    && if [ -z "$NSU" ]; then \
         for d in /usr/bin /usr/sbin; do [ -x "$d/nsupdate" ] && NSU="$d/nsupdate" && break; done; \
       fi \
    && test -n "$NSU" && test -x "$NSU" \
    && ln -sf "$NSU" /usr/local/bin/nsupdate

WORKDIR /app

COPY pyproject.toml ./
COPY bind_key_api ./bind_key_api/

RUN pip install --no-cache-dir --upgrade pip setuptools wheel \
    && pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    BIND_KEY_API_NSUPDATE_PATH=/usr/local/bin/nsupdate

EXPOSE 8080

# Listen on all interfaces so -p 8080:8080 works; use UVICORN_HOST=127.0.0.1 if only exposing via reverse proxy on host network.
ENV UVICORN_HOST=0.0.0.0 \
    UVICORN_PORT=8080

CMD ["sh", "-c", "exec uvicorn bind_key_api.main:app --host \"${UVICORN_HOST}\" --port \"${UVICORN_PORT}\" --workers 1"]
