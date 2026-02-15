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

## 🌐 Network Security

### Recommended Deployment
1.  **Reverse Proxy**: Do not expose port `3000` directly. use Nginx, Caddy, or Cloudflare Tunnel.
2.  **SSL/TLS**: Always use HTTPS in production.
3.  **Firewall**: Allow connections to port `3000` only from `localhost` (if using proxy) or trusted IPs.

### Trusted IPs (Whitelist)
Be sure to configure allowed IP addresses in your firewall or reverse proxy.
