# 🚀 Mini-Ops

[![Ru](https://img.shields.io/badge/lang-ru-blue.svg)](README.ru.md)
[![En](https://img.shields.io/badge/lang-en-red.svg)](README.md)


![Rust](https://img.shields.io/badge/backend-Rust-orange?style=for-the-badge&logo=rust)
![React](https://img.shields.io/badge/frontend-React-blue?style=for-the-badge&logo=react)
![License](https://img.shields.io/badge/license-MIT-green?style=for-the-badge)
![Docker](https://img.shields.io/badge/docker-ready-2496ED?style=for-the-badge&logo=docker)

**Mini-Ops** is a lightweight self-hosted ops panel for VPS servers.  
Backend: **Rust** (Axum), Frontend: **React** (Vite, embedded into the binary at build time).

> "Your personal DevOps engineer that fits in a single binary."

---

## ✨ Features

- **📦 Single service deployment**: one backend binary serves API + embedded frontend build.
- **🐳 Docker Management**: list/start/stop/restart containers, stream container logs.
- **🛡️ Security Auditor**:
  - **SSH Monitoring**: Telegram alerts on login (PAM hook).
  - **Hardening Checks**: Audits SSH config, Fail2Ban status, UFW firewall, and listening ports.
  - **Trusted IPs**: Whitelist management for secure access.
- **📊 System Monitoring**: CPU/RAM/Disk usage + metrics history.
- **🔔 Alerts**: Telegram alerts for CPU and disk thresholds + security state changes.
- **🧹 Disk Cleanup**: clean `target`, `node_modules`, Docker cache, and old journal logs.
- **🌍 Localization**: Full support for English and Russian languages.

---

## 🚀 Quick Start

### 1. Installation

Mini-Ops is designed to be built from source or deployed via an automated script.

#### Option A: Automated Ubuntu Bootstrap (Recommended)
This script will build the app locally and deploy it to your server:
```bash
DEPLOY_HOST=your-server-ip ./scripts/bootstrap_server.sh
```

#### Option B: Manual Installation
See the [Development](#-development) section below to build the binary from source.

### 2. Configuration (`.env`)

Create `.env` from the template:
```bash
cp .env.example .env
```

Minimal required variable:
```env
AUTH_TOKEN=
```

Leave it empty to let Mini-Ops/bootstrap generate a strong token, or generate
one in your shell and paste the resulting value into `.env`:
```bash
openssl rand -hex 32
```

Optional:
```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
DATABASE_URL=sqlite:mini-ops.db
SERVER_NAME=My-VPS-1
RUST_LOG=info
```

### 3. Run as Service

```bash
# Create systemd service
sudo tee /etc/systemd/system/mini-ops.service <<EOF
[Unit]
Description=Mini-Ops Agent
After=network.target docker.service

[Service]
ExecStart=/usr/local/bin/mini-ops
Restart=always
EnvironmentFile=/path/to/.env

[Install]
WantedBy=multi-user.target
EOF

# Start
sudo systemctl enable --now mini-ops
```

With this manual service example, Mini-Ops listens on
**http://127.0.0.1:3000** by default. Put it behind a reverse proxy or set
`APP_HOST`/`APP_PORT` intentionally before exposing it.

Automated Ubuntu bootstrap (recommended for fast demo):
```bash
DEPLOY_HOST=your-server-ip ./scripts/bootstrap_server.sh
```
Default bootstrap access: **http://your-server-ip:8090** through the generated
plain-HTTP Nginx reverse proxy.

Reduced mutation mode (skip UFW/Fail2Ban, PAM hook, Nginx, and Docker automation):
```bash
DEPLOY_HOST=your-server-ip \
DEPLOY_HARDENING=0 \
DEPLOY_ENABLE_SSH_ALERTS=0 \
DEPLOY_SETUP_NGINX=0 \
DEPLOY_INSTALL_DOCKER=0 \
./scripts/bootstrap_server.sh
```
Minimal mode (only uploads binary, no user/systemd/.env changes):
```bash
DEPLOY_HOST=your-server-ip DEPLOY_MINIMAL=1 ./scripts/bootstrap_server.sh
```
Minimal + .env:
```bash
DEPLOY_HOST=your-server-ip DEPLOY_MINIMAL=1 DEPLOY_WRITE_ENV=1 AUTH_TOKEN="$(openssl rand -hex 32)" ./scripts/bootstrap_server.sh
```
Systemd only (rewrite unit + restart):
```bash
DEPLOY_HOST=your-server-ip DEPLOY_SYSTEMD_ONLY=1 DEPLOY_APP_USER=miniops DEPLOY_TARGET_DIR=/opt/mini-ops ./scripts/bootstrap_server.sh
```
See [docs/DEPLOY.md](docs/DEPLOY.md) for full options.

---

## 🌐 Networking Modes

- **Default bootstrap test access**: `http://server-ip:8090` via generated
  Nginx config. This is plain HTTP and intended for lab/internal testing.
- **Production mode**: `DEPLOY_MODE=production` does not enable the generated
  plain-HTTP Nginx proxy unless you explicitly set `DEPLOY_SETUP_NGINX=1`.
- **Production exposure**: add TLS with Nginx/Caddy/Cloudflare Tunnel or
  restrict access to a private network/VPN. Do not expose `3000` directly.

---

## 🛠 Development

### Prerequisites
- **Rust** (latest stable)
- **Node.js** (v20+)
- **Docker**

### Local Setup

1. **Clone & Install Frontend**:
   ```bash
   git clone https://github.com/rg-onion/mini-ops.git
   cd mini-ops/frontend
   npm install
   npm run build
   ```

2. **Run Backend**:
   ```bash
   cd ..
   cargo run
   ```

---

## 🔒 Security

Mini-Ops is designed with security in mind:
- **Internal PAM Token**: SSH alert integration uses a random token generated
  at startup and read by the localhost PAM hook.
- **SSH Alert Throttling**: repeated SSH login alerts are throttled per source
  IP.
- **Protected API**: all user-facing API routes require `AUTH_TOKEN`.

Production recommendations:
- Put Mini-Ops behind HTTPS reverse proxy (Nginx/Caddy/Cloudflare Tunnel).
- Avoid exposing port `8090` publicly without TLS.
- Run service as dedicated non-root user whenever possible.
- Keep dashboard-triggered updates disabled unless explicitly needed
  (`MINI_OPS_ALLOW_WEB_UPDATE=false` by default).

See [docs/SECURITY.md](docs/SECURITY.md) for details.

Documentation index: [docs/README.md](docs/README.md)

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
