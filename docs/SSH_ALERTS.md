# SSH Alerts Setup

Mini-Ops can send Telegram notifications for every successful SSH login.

## How It Works

1.  **PAM Module**: Uses `pam_exec.so` to trigger a script on login.
2.  **Micro-script**: A lightweight bash script (`ssh-alert.sh`) gathers session info (User, IP).
3.  **Internal API**: The script sends a POST request to `http://127.0.0.1:3000/api/webhooks/ssh-login`.
4.  **Security**: The request is signed with a short-lived internal token to prevent spoofing.

## Automatic Installation

Using `bootstrap_server.sh` with `DEPLOY_ENABLE_SSH_ALERTS=1` automatically configures everything.

## Manual Installation

If you deployed manually or want to enable alerts later:

1.  Ensure `mini-ops` is running.
2.  Run the setup script:
    ```bash
    cd /opt/mini-ops/scripts
    sudo ./setup_ssh_alerts.sh
    ```

## Configuration

In `.env`:

```env
# Required for alerts
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
```

## Troubleshooting

### No alerts on login?
1. Check if `mini-ops` is running: `systemctl status mini-ops`.
2. check logs: `journalctl -u mini-ops -f`.
3. Verify PAM config: `grep "pam_exec.so" /etc/pam.d/sshd`.
4. Run the alert script manually to test connectivity:
   ```bash
   PAM_USER=test PAM_RHOST=1.2.3.4 PAM_TYPE=open_session ./scripts/ssh-alert.sh
   ```
