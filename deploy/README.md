# Production install (systemd)

## Requirements

- Linux with **systemd**
- **Python 3.11+** (`python3` or set `PYTHON_BIN`)
- **root** for install (reads/writes `/etc/bind/keys`, `rndc`, optional `nsupdate`)

## Install

From the repository root:

```bash
sudo ./deploy/install.sh
```

Environment:

| Variable | Default | Meaning |
|----------|---------|---------|
| `INSTALL_ROOT` | `/opt/bind-key-api` | Application directory |
| `ENV_DIR` | `/etc/bind-key-api` | Directory for `bind-key-api.env` |
| `PYTHON_BIN` | auto | Python interpreter for venv |

First run creates `/etc/bind-key-api/bind-key-api.env` from the example. **Edit** at least `BIND_KEY_API_AUTH_TOKEN`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now bind-key-api
```

## Operations

| Action | Command |
|--------|---------|
| Status | `sudo systemctl status bind-key-api` |
| Logs | `sudo journalctl -u bind-key-api -f` |
| Restart | `sudo systemctl restart bind-key-api` |

## Uninstall

```bash
sudo ./deploy/uninstall.sh
```

Then remove `/opt/bind-key-api` and `/etc/bind-key-api` if you no longer need them.
