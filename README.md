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
  - **Truthful Posture**: Separates confirmed findings and recommendations from partial audit coverage.
  - **Sensitive-File Integrity**: opt-in, low-privilege drift detection with a local private baseline.
  - **TLS Certificate Monitoring**: opt-in checks for up to 32 explicitly configured served endpoints; no filesystem or private-key discovery.
  - **Trusted IPs**: Whitelist management for secure access.
- **📊 System Monitoring**: current CPU, RAM, and disk capacity plus
  [bounded metrics history](docs/METRICS_HISTORY.md) from one hour to seven days.
- **🔔 Alerts**: Telegram alerts for CPU and disk thresholds + security state changes.
- **☁️ Fleet Observation Push**: optional, outbound-only v1 projection of minimized system, security, and certificate state to an operator-controlled Hub.
- **🌍 Localization**: Full support for English and Russian languages.

---

## 🚀 Quick Start

### 1. Installation

For tagged OSS releases, download the binary archive, `SHA256SUMS`, and SBOM
from the same GitHub Release and verify them before use. See
[docs/RELEASING.md](docs/RELEASING.md).

Use the managed bootstrap only after reviewing its zero-mutation dry run:

```bash
DEPLOY_HOST=server.example DEPLOY_DRY_RUN=1 ./scripts/bootstrap_server.sh
```

Defaults keep the app on loopback and leave Docker, Nginx, UFW, public HTTP,
Docker-group access, and PAM unchanged. The legacy `deploy.sh` and
`provision.sh` entrypoints remain hard-stopped. See the actual invocation,
explicit mutation flags, rollback boundaries, and manual alternative in
[docs/DEPLOY.md](docs/DEPLOY.md).

### 2. Configuration (`.env`)

Create `.env` from the template:
```bash
cp .env.example .env
```

Minimal required variable:
```env
AUTH_TOKEN=
```

Standalone local mode can generate a token when this value is empty. Managed
systemd mode requires a preconfigured strong token and fails fast otherwise.
Generate one and paste it into `.env`:
```bash
openssl rand -hex 32
```

Optional:
```env
TELEGRAM_BOT_TOKEN=your_bot_token
TELEGRAM_CHAT_ID=your_chat_id
# Standalone-only override; omit it for the managed systemd service.
# DATABASE_URL=sqlite:mini-ops.db
SERVER_NAME=My-VPS-1
RUST_LOG=info
```

### 3. Run as a managed service

The shipped unit keeps code/config root-owned, stores mutable state under
`/var/lib/mini-ops`, rotates the PAM token under `/run/mini-ops`, and applies
`UMask=0077`, `ProtectSystem=strict`, and `ProtectHome=true`. See the exact
installation and verification commands in [docs/DEPLOY.md](docs/DEPLOY.md).

---

## 🌐 Networking Modes

- **Default**: the application listens on `127.0.0.1:3000`.
- **External access**: configure TLS and a reverse proxy, VPN, tunnel, or
  private network separately. Do not expose `3000` directly.

---

## 🛠 Development

### Prerequisites
- **Rust** (`1.93.0`)
- **Node.js** (`24.17.0`) and **npm** (`12.0.1`)
- **Docker**

### Local Setup

1. **Clone & Install Frontend**:
   ```bash
   git clone https://github.com/rg-onion/mini-ops.git
   cd mini-ops/frontend
   npm ci --strict-allow-scripts
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
- Perform upgrades through the documented host deployment workflow with a
  verified artifact, backup, rollback point, and post-change health checks.

See [docs/SECURITY.md](docs/SECURITY.md) for details.

The repository contains an opt-in agent-side Fleet observation protocol, but no
hosted Hub or bundled Fleet server. Its current implementation status, privacy
boundary, and receiver contract are documented in
[docs/CLOUD_PUSH.md](docs/CLOUD_PUSH.md) and
[docs/FLEET_INTEGRATION.md](docs/FLEET_INTEGRATION.md).

Documentation index: [docs/README.md](docs/README.md)

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
