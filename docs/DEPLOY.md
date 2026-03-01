# Deploying Mini-Ops

## Recommended Path: One-Command Bootstrap (Ubuntu)

The script `scripts/bootstrap_server.sh` automates:
1. Baseline hardening (`ufw`, `fail2ban`).
2. Creating a non-root service user (`miniops`).
3. Installing/Verifying Docker (optional).
4. Local build and binary deployment.
5. Creating `.env` and systemd unit.
6. Optional PAM hook setup for SSH alerts (`setup_ssh_alerts.sh`).

### Requirements
1. SSH access to the server (`root` or user with `sudo`).
2. Local: `cargo`, `npm`, `ssh`, `scp`.
3. Server OS: Ubuntu/Debian-compatible (uses `apt`).

### Quick Start (Test Mode, No SSL)
```bash
DEPLOY_HOST=203.0.113.10 ./scripts/bootstrap_server.sh
```

### Important Variables
```bash
DEPLOY_HOST=203.0.113.10
DEPLOY_SSH_USER=root
DEPLOY_SSH_PORT=22
DEPLOY_TARGET_DIR=/opt/mini-ops
DEPLOY_APP_USER=miniops
DEPLOY_MODE=test                 # test|production
DEPLOY_ENABLE_SSH_ALERTS=1       # 1|0
DEPLOY_HARDENING=1               # 1|0 (ufw + fail2ban)
DEPLOY_MINIMAL=0                 # 1|0 (skip user/systemd/.env changes)
DEPLOY_WRITE_ENV=0               # 1|0 (write .env when DEPLOY_MINIMAL=1)
DEPLOY_SYSTEMD_ONLY=0            # 1|0 (rewrite systemd unit and restart)
AUTH_TOKEN=your_strong_token     # optional but recommended
TELEGRAM_BOT_TOKEN=...           # optional
TELEGRAM_CHAT_ID=...             # optional
```

### Network Modes
1. `DEPLOY_MODE=test`: opens `8090/tcp` in UFW (for demo/lab).
2. `DEPLOY_MODE=production`: does not open `8090/tcp` (expects reverse proxy + HTTPS).

### Safe Mode (No Firewall/Package Changes)
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_HARDENING=0 \
DEPLOY_ENABLE_SSH_ALERTS=0 \
./scripts/bootstrap_server.sh
```

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
AUTH_TOKEN=your_strong_token \
./scripts/bootstrap_server.sh
```

### Systemd Only (Recreate Unit and Restart)
```bash
DEPLOY_HOST=203.0.113.10 \
DEPLOY_SYSTEMD_ONLY=1 \
DEPLOY_APP_USER=miniops \
DEPLOY_TARGET_DIR=/opt/mini-ops \
./scripts/bootstrap_server.sh
```

### Non-Root Mode Limitations
When running as the `miniops` user, some dashboard features may be restricted:
1. **System Logs**: Reading system logs (`journalctl`) requires membership in the `systemd-journal` group or `root`.
2. **System Cleansing**: Clearing system caches (`apt`, `journald`) is impossible without `sudo`.
3. **Frontend Cache**: If the `node_modules` folder was created during a build by another user, cleanup might fail (although `bootstrap_server.sh` performs `chown`).
4. **Docker**: Works correctly (user is added to the `docker` group).

For full access to system functions, `sudo` rules configuration or running the agent as `root` (not recommended) is required.

## Legacy Scripts

`scripts/deploy.sh` and `scripts/provision.sh` are kept for compatibility,
but `scripts/bootstrap_server.sh` is recommended for new installations.
