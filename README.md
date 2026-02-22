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

## 📸 Screenshots

| Dashboard | Security Audit |
|-----------|----------------|
| *Add screenshot link here* | *Add screenshot link here* |

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
AUTH_TOKEN=change-me-strong-random-token

# Optional:
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

Access dashboard at: **http://your-server-ip:3000**

Automated Ubuntu bootstrap (recommended for fast demo):
```bash
DEPLOY_HOST=your-server-ip ./scripts/bootstrap_server.sh
```
Safe mode (no firewall or package changes):
```bash
DEPLOY_HOST=your-server-ip DEPLOY_HARDENING=0 ./scripts/bootstrap_server.sh
```
Minimal mode (only uploads binary, no user/systemd/.env changes):
```bash
DEPLOY_HOST=your-server-ip DEPLOY_MINIMAL=1 ./scripts/bootstrap_server.sh
```
Minimal + .env:
```bash
DEPLOY_HOST=your-server-ip DEPLOY_MINIMAL=1 DEPLOY_WRITE_ENV=1 AUTH_TOKEN=your_strong_token ./scripts/bootstrap_server.sh
```
Systemd only (rewrite unit + restart):
```bash
DEPLOY_HOST=your-server-ip DEPLOY_SYSTEMD_ONLY=1 DEPLOY_APP_USER=miniops DEPLOY_TARGET_DIR=/opt/mini-ops ./scripts/bootstrap_server.sh
```
See [docs/DEPLOY.md](docs/DEPLOY.md) for full options.

---

## 🌐 Networking Modes

- **Test mode (no SSL)**: direct access to `http://server-ip:3000` for lab/internal testing.
- **Production mode (SSL)**: run Mini-Ops behind Nginx/Caddy/Cloudflare Tunnel and expose only HTTPS.

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
- **Internal Tokens**: PAM integration uses secure, ephemeral tokens generated at startup.
- **Rate Limiting**: Brute-force protection for alerts.
- **Protected API**: all user-facing API routes require `AUTH_TOKEN`.

Production recommendations:
- Put Mini-Ops behind HTTPS reverse proxy (Nginx/Caddy/Cloudflare Tunnel).
- Avoid exposing port `3000` publicly without TLS.
- Run service as dedicated non-root user whenever possible.

See [docs/SECURITY.md](docs/SECURITY.md) for details.

Documentation index: [docs/README.md](docs/README.md)

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
