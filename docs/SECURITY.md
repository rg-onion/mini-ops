# Security Guide

Mini-Ops is designed to be a lightweight and secure agent for VPS management.

## 🛡️ Core Principles

1.  **Zero Trust**: User-facing API routes require a valid `Authorization: Bearer <AUTH_TOKEN>`. The internal SSH-login endpoint uses a separate localhost PAM token.
2.  **Least Privilege**: The agent can run as a non-root user (`miniops`), providing only necessary functionality.
3.  **Audit**: Continuous monitoring of security configurations (SSH, UFW, Fail2Ban).

## 🔑 Authentication

### Auth Token
The token is set in the `.env` file:
```env
AUTH_TOKEN=<strong random token>
```
We recommend generating a strong token:
```bash
openssl rand -hex 32
```

### API Exposure
Mini-Ops does not throttle all API routes itself. If the dashboard is reachable outside a trusted network, put it behind a reverse proxy, VPN, or edge service that provides TLS and request throttling.

### Web-Triggered Updates
The `POST /api/deploy/webhook` endpoint remains protected by `AUTH_TOKEN`, but
it is disabled by default. Set `MINI_OPS_ALLOW_WEB_UPDATE=true` only when this
host should accept dashboard-triggered source updates.

When enabled, Mini-Ops runs `scripts/update.sh` from the local checkout. The
script refuses non-git directories and tracked local changes, uses
`git pull --ff-only`, installs frontend dependencies from the lockfile when
available, and builds the backend with `cargo build --release --locked`. Only
one update can run at a time, and `/api/deploy/logs` streams recent update logs
over SSE.

## 📝 SSH Monitoring

The agent includes a PAM hook script that catches SSH login events and sends alerts to Telegram.

### How it Works
1.  **PAM Configuration**: The script `scripts/setup_ssh_alerts.sh` adds a call to `pam_exec.so` in `/etc/pam.d/sshd`.
2.  **Hook Script**: When a user logs in, PAM executes `/opt/mini-ops/scripts/ssh-alert.sh`.
3.  **Token Validation**: Mini-Ops generates a random internal token at startup and writes it to `MINI_OPS_INTERNAL_TOKEN_FILE` (or `mini-ops-internal.token` by default). The hook reads that file and sends a request to the Mini-Ops API on localhost.
4.  **Telegram Alert**: The API verifies the internal token, validates the source IP, throttles repeated alerts per IP, and sends a message to the administrator unless the IP is trusted.

Does not require exposing the API to the internet (communication happens via `localhost`).

## ⚙️ Hardening Checks

The "Security Audit" section checks:
- **SSH**:
    - Root login disabled (`PermitRootLogin no`).
    - Password authentication disabled (`PasswordAuthentication no`).
- **Firewall (UFW)**:
    - Status (Active/Inactive).
- **Fail2Ban**:
    - Service status via `systemctl is-active fail2ban`.
- **Listening ports**:
    - Open TCP/UDP ports via `ss -H -tuln`.
    - Ports outside `22`, `80`, `443`, `APP_PORT` (default `3000`), and `DEPLOY_NGINX_PORT` (default `8090`) are reported as warnings.
- **Docker**:
    - Docker socket world-writable permission check.
    - Exposed Docker TCP API ports `2375`/`2376`.
    - Container hardening risks when Docker is available.
- **Disk encryption**:
    - Presence of `crypt` block devices via `lsblk`.

## Security Events

Mini-Ops stores security audit findings as local events in SQLite. Events are
created when an audit check reports `FAIL` or `WARN`, updated while the finding
remains active, and resolved when the check returns to `PASS`.

- Active events are shown on the Security page.
- Operators can acknowledge open events to reduce noise while keeping evidence.
- Resolved events are retained for `SECURITY_EVENTS_RETENTION_HOURS` hours
  (`168` by default).
- Telegram notifications are sent only when a failed check first opens/reopens
  and when it resolves.

## Local Data Retention

Mini-Ops bounds local operational history so small VPS databases do not grow
forever:

- Metrics rows older than `METRICS_RETENTION_HOURS` are pruned periodically
  (`168` hours by default).
- SSH login history rows older than `SSH_LOGINS_RETENTION_DAYS` are pruned when
  new SSH login events are recorded (`90` days by default).
- Resolved security events use `SECURITY_EVENTS_RETENTION_HOURS` as described
  above.

The app creates indexes on `metrics(timestamp)`, `ssh_logins(timestamp)`, and
`ssh_logins(ip, timestamp)` for these retention and history queries. Deleting old
rows does not necessarily shrink the SQLite file immediately; run `VACUUM`
manually during a maintenance window if you need to reclaim file space.

## Audit Runtime Controls

Security audit work is bounded with local runtime controls:

- `SECURITY_AUDIT_INTERVAL_SECS` controls the background monitor interval
  (`300` seconds by default, minimum `60`).
- `SECURITY_AUDIT_CACHE_TTL_SECS` caches `/api/security/audit` responses for the
  dashboard/API (`30` seconds by default; set `0` to disable).
- `SECURITY_AUDIT_DOCKER_TIMEOUT_SECS` limits Docker container inspection during
  security audit (`10` seconds by default).

If Docker inspection times out, the Docker container hardening check returns
`WARN` with timeout evidence instead of blocking the whole audit.

## 🌐 Network & Deployment Security

### Automated Deployment
The deployment script (`scripts/bootstrap_server.sh`) currently behaves as follows:

1. **Internal binding**: Mini-Ops listens on `127.0.0.1:3000` by default. The script appends `APP_HOST=127.0.0.1` and `APP_PORT=3000` to the deployed `.env` if they are missing.
2. **Nginx automation**: In `DEPLOY_MODE=test`, generated plain-HTTP Nginx is enabled by default on `DEPLOY_NGINX_PORT` (default `8090`). In `DEPLOY_MODE=production`, generated Nginx is disabled unless `DEPLOY_SETUP_NGINX=1` is explicitly set. The generated config blocks `/api/internal/*`.
3. **Firewall automation**: With `DEPLOY_HARDENING=1` (default), UFW allows OpenSSH. Dashboard ports are opened only when `DEPLOY_EXPOSE_HTTP=1` for either Nginx (`DEPLOY_SETUP_NGINX=1`) or direct test app access (`DEPLOY_SETUP_NGINX=0 DEPLOY_MODE=test`).
4. **TLS**: The bootstrap script does not configure HTTPS certificates. For production exposure, add TLS with Nginx/Caddy/Cloudflare Tunnel or restrict access to a private network/VPN.

### Environment Variable (`.env`) Syncing
The deployment script builds a temporary `.env` locally and uploads it via SCP:

- If a project-root `.env` exists, it is used as the source.
- If no `.env` exists, `.env.example` is used as a template. When `AUTH_TOKEN`
  is absent or empty, bootstrap generates a strong token before upload.
- `AUTH_TOKEN`, `TELEGRAM_BOT_TOKEN`, and `TELEGRAM_CHAT_ID` overrides are applied locally before upload, so they are not passed as remote command-line arguments.
- Runtime defaults such as `APP_HOST`, `APP_PORT`, `DEPLOY_NGINX_PORT`, `DATABASE_URL`, `MINI_OPS_INTERNAL_TOKEN_FILE`, `RUST_LOG`, `AGENT_LANG`, and `SERVER_NAME` are appended on the server only when missing.
