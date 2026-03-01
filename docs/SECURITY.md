# Security Guide

Mini-Ops is designed to be a lightweight and secure agent for VPS management.

## 🛡️ Core Principles

1.  **Zero Trust**: All requests (except static assets) require a valid `Authorization: Bearer <AUTH_TOKEN>`.
2.  **Least Privilege**: The agent can run as a non-root user (`miniops`), providing only necessary functionality.
3.  **Audit**: Continuous monitoring of security configurations (SSH, UFW, Fail2Ban).

## 🔑 Authentication

### Auth Token
The token is set in the `.env` file:
```env
AUTH_TOKEN=your-random-secure-string-at-least-32-chars
```
We recommend generating a strong token:
```bash
openssl rand -hex 32
```

### Rate Limiting
To protect against brute-force attacks on the API:
- **Login attempts**: Limit of 5 requests per minute per IP.
- **Sensitive actions**: Additional limits on critical endpoints.

## 📝 SSH Monitoring

The agent includes a PAM hook script that catches SSH login events and sends alerts to Telegram.

### How it Works
1.  **PAM Configuration**: The script `scripts/setup_ssh_alerts.sh` adds a call to `pam_exec.so` in `/etc/pam.d/sshd`.
2.  **Hook Script**: When a user logs in, PAM executes `/opt/mini-ops/scripts/ssh-alert.sh`.
3.  **Token Validation**: The hook generates a short-lived TOTP-like token and sends a request to the Mini-Ops API.
4.  **Telegram Alert**: The API verifies the token and sends a message to the administrator.

Does not require exposing the API to the internet (communication happens via `localhost`).

## ⚙️ Hardening Checks

The "Security Audit" section checks:
- **SSH**:
    - Root login disabled (`PermitRootLogin no`).
    - Password authentication disabled (`PasswordAuthentication no`).
    - Non-standard port (not 22).
- **Firewall (UFW)**:
    - Status (Active/Inactive).
    - Open ports.
- **Fail2Ban**:
    - Service status.
    - Active jails.

## 🌐 Network & Deployment Security

### Automated Secure Deployment
The deployment script (`bootstrap_server.sh`) is designed to be secure by default:
1. **Reverse Proxy (Nginx)**: It automatically installs Nginx and configures it to reverse proxy incoming connections on port `8090` (configurable via `DEPLOY_NGINX_PORT`) to the internal app.
2. **Internal Binding**: The `mini-ops` Rust application is bound strictly to `127.0.0.1:3000`. This prevents any external entity from connecting directly to the application, circumventing the reverse proxy. 
3. **Firewall (UFW)**: Direct access to port `3000` is blocked by default, while port `8090` is explicitly allowed if Nginx automation is used.

### Environment Variable (`.env`) Syncing
The deployment script natively syncs the `.env` file from your local machine to the target server:
- If a `.env` file exists in the project root locally (`/home/aid/PycharmProjects/mini-ops/.env`), it is securely uploaded to the server via SCP, replacing the configuration on the server.
- If no `.env` exists locally, the script falls back to uploading `.env.example` as a template, enabling you to bootstrap the server effortlessly.
- Optional parameters like `TELEGRAM_BOT_TOKEN` will strictly mirror your local setup. Only core networking variables (`APP_HOST`, `APP_PORT`) are forcefully appended to guarantee stable startup.
