# Deploying Mini-Ops

## Recommended Path: One-Command Bootstrap (Ubuntu)

The script `scripts/bootstrap_server.sh` automates:
1. Baseline hardening (`ufw`, `fail2ban`) when `DEPLOY_HARDENING=1`
   (default).
2. Installing Mini-Ops as a systemd service. The default service user is `root`
   for full VPS-control functionality.
3. Installing/Verifying Docker (optional).
4. Local build and binary deployment.
5. Creating `.env` and systemd unit.
6. Optional PAM hook setup for SSH alerts (`setup_ssh_alerts.sh`).
7. Optional plain-HTTP Nginx reverse proxy when `DEPLOY_SETUP_NGINX=1`.
   In `test` mode it is enabled by default; in `production` mode it is disabled
   unless explicitly set.

### Requirements
1. SSH access to the server (`root` or user with `sudo`).
2. Local: `cargo`, `npm`, `ssh`, `scp`.
3. Server OS: Ubuntu/Debian-compatible (uses `apt`).

### Quick Start (Test Mode, No SSL)
```bash
DEPLOY_HOST=203.0.113.10 ./scripts/bootstrap_server.sh
```

With default flags, the app listens on `127.0.0.1:3000` and generated Nginx
serves the dashboard on `http://203.0.113.10:8090`.

### Important Variables
```bash
DEPLOY_HOST=203.0.113.10
DEPLOY_SSH_USER=root
DEPLOY_SSH_PORT=22
DEPLOY_TARGET_DIR=/opt/mini-ops
DEPLOY_APP_USER=root               # root|miniops
DEPLOY_MODE=test                   # test|production
DEPLOY_SETUP_NGINX=1               # 1|0 (default: test=1, production=0)
DEPLOY_EXPOSE_HTTP=1               # 1|0 (default: test=1, production=0)
DEPLOY_NGINX_PORT=8090             # external Nginx port when enabled
DEPLOY_APP_PORT=3000               # internal app port
DEPLOY_INSTALL_DOCKER=1            # 1|0
DEPLOY_ENABLE_SSH_ALERTS=1         # 1|0
DEPLOY_RUN_LOCAL_BUILD=1           # 1|0
DEPLOY_HARDENING=1                 # 1|0 (ufw + fail2ban packages/service)
DEPLOY_MINIMAL=0                   # 1|0 (skip user/systemd/.env changes)
DEPLOY_WRITE_ENV=0                 # 1|0 (write .env when DEPLOY_MINIMAL=1)
DEPLOY_SYSTEMD_ONLY=0              # 1|0 (rewrite systemd unit and restart)
AUTH_TOKEN=<strong 32+ char token> # optional; generated if absent/empty
TELEGRAM_BOT_TOKEN=...             # optional
TELEGRAM_CHAT_ID=...               # optional
```

### Network Modes
`DEPLOY_MODE`, `DEPLOY_SETUP_NGINX`, and `DEPLOY_EXPOSE_HTTP` decide what is
installed and what UFW opens:

1. Default `DEPLOY_MODE=test`: writes a plain-HTTP Nginx reverse proxy on
   `DEPLOY_NGINX_PORT` and UFW allows that port when `DEPLOY_HARDENING=1`.
   The generated Nginx config blocks `/api/internal/*`.
2. Default `DEPLOY_MODE=production`: does not write generated Nginx and does
   not open an HTTP dashboard port unless you explicitly set
   `DEPLOY_SETUP_NGINX=1` and `DEPLOY_EXPOSE_HTTP=1`.
3. With `DEPLOY_SETUP_NGINX=0 DEPLOY_MODE=test`, UFW allows `DEPLOY_APP_PORT`
   only when `DEPLOY_HARDENING=1` and `DEPLOY_EXPOSE_HTTP=1`.
4. `DEPLOY_EXPOSE_HTTP=0` prevents the script from adding UFW allow rules for
   the dashboard, but it does not replace TLS, VPN, or external firewall policy.

The script does not configure TLS certificates. For production, add HTTPS with
your own Nginx/Caddy/Cloudflare Tunnel setup or restrict access to a private
network/VPN.

### Reduced Mutation Mode
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_HARDENING=0 \
DEPLOY_ENABLE_SSH_ALERTS=0 \
./scripts/bootstrap_server.sh
```

This skips UFW/Fail2Ban hardening and the PAM hook. In test mode with default
`DEPLOY_SETUP_NGINX=1`, the script may still install/write Nginx. Add
`DEPLOY_SETUP_NGINX=0` to skip Nginx automation, and `DEPLOY_INSTALL_DOCKER=0`
to skip Docker installation.

### Minimal Mode (Binary Deployment Only)
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_MINIMAL=1 \
./scripts/bootstrap_server.sh
```

### Minimal + .env
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_MINIMAL=1 \
DEPLOY_WRITE_ENV=1 \
AUTH_TOKEN="$(openssl rand -hex 32)" \
./scripts/bootstrap_server.sh
```

### Systemd Only (Recreate Unit and Restart)
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_SYSTEMD_ONLY=1 \
DEPLOY_APP_USER=root \
DEPLOY_TARGET_DIR=/opt/mini-ops \
./scripts/bootstrap_server.sh
```

### Privilege Modes

Mini-Ops is a local VPS control panel. The default `DEPLOY_APP_USER=root` mode
is recommended when you want the full feature set: Docker control, journal
inspection/cleanup, SSH/PAM alert setup, filesystem size checks, and richer
security audits. Keep `APP_HOST=127.0.0.1`, use a strong `AUTH_TOKEN`, and put
public access behind a TLS-enabled reverse proxy, tunnel, private network, or
VPN. The default bootstrap Nginx config is plain HTTP.

You can still run a reduced installation with `DEPLOY_APP_USER=miniops`. In that
mode some dashboard features may be restricted:

1. **System Logs**: Reading system logs (`journalctl`) requires membership in the `systemd-journal` group or `root`.
2. **System Cleansing**: Clearing system caches (`apt`, `journald`) is impossible without `sudo`.
3. **Frontend Cache**: If the `node_modules` folder was created during a build by another user, cleanup might fail (although `bootstrap_server.sh` performs `chown`).
4. **Docker**: Works correctly (user is added to the `docker` group).

## Legacy Scripts

`scripts/deploy.sh` and `scripts/provision.sh` are kept for compatibility,
but `scripts/bootstrap_server.sh` is recommended for new installations.
