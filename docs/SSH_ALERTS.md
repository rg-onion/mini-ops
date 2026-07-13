# SSH Alerts Setup

Mini-Ops records successful SSH logins. Alerts for untrusted source IPs are
placed in a durable Telegram queue with bounded cooldown and retry.

## How It Works

1.  **PAM Module**: Uses `pam_exec.so` to trigger a script on login.
2.  **Micro-script**: A lightweight bash script (`ssh-alert.sh`) gathers session info (User, IP).
3.  **Internal API**: The script sends a POST request to `http://127.0.0.1:3000/api/internal/ssh-login`.
4.  **Security**: The request is signed with a private runtime token generated
    at Mini-Ops startup. The PAM hook supplies the bearer header to `curl`
    through bounded stdin configuration, so the token is not placed in process
    arguments or hook logs.
5.  **Source-IP baseline**: Mini-Ops compares the login source IP with the
    trusted IP list managed on the SSH Security page.
6.  **Durable delivery**: An untrusted occurrence is queued; the worker performs
    bounded provider attempts. Trusted occurrences and duplicates within the
    suppression/live window are not queued.

## Manual Installation

SSH-alert setup is an explicit manual PAM mutation:

1.  Ensure `mini-ops` is running.
2.  Run the setup script:
    ```bash
    cd /opt/mini-ops/scripts
    sudo env MINI_OPS_APP_USER=miniops \
      MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token \
      DEPLOY_APP_PORT=3000 \
      ./setup_ssh_alerts.sh
    ```

## Configuration

In `.env`:

```env
# Required for alerts
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...

# Managed systemd default
MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token
```

The managed systemd unit creates `/run/mini-ops` with `0700` permissions. The
agent rotates `internal.token` at startup using an atomic same-directory write
and keeps the file at `0600`. `setup_ssh_alerts.sh` installs a root-owned
`/etc/mini-ops/ssh-alert.conf` containing only the loopback URL, token file
path, and token-owner account; the bearer value is never copied into that
configuration. The root PAM hook drops to that account for a bounded no-follow
token read before calling curl with proxy and curlrc behavior disabled.

Custom standalone deployments can set `MINI_OPS_INTERNAL_TOKEN_FILE` and
`MINI_OPS_APP_USER` before running `setup_ssh_alerts.sh`. The configured path
must be absolute, and the account must match the owner running Mini-Ops. Keep
the token in a private directory and ensure the agent and PAM hook use the same
path and owner.

## Trusted Source IP Baseline

The trusted IP list is the local baseline for SSH source IPs.

- Logins from trusted IPs are still recorded in SSH history, but Telegram
  notifications are suppressed.
- Logins from untrusted IPs are recorded, enqueue the normal SSH Telegram alert,
  and create a `ssh.untrusted_source_ip` security event. The durable outbox
  suppresses the same normalized source IP for 10 seconds; failed retryable
  delivery survives restart.
- Adding an IP to the trusted list resolves any active security event for that
  source IP.
- The existing SSH history `notified` flag means the occurrence was accepted by
  the durable queue; it is not proof of provider delivery. The linked local
  security event carries the redacted delivery status.
- IPs are normalized before comparison, so equivalent IPv6 spellings compare as
  the same address.

## Troubleshooting

### No alerts on login?
1. Check if `mini-ops` is running: `systemctl status mini-ops`.
2. check logs: `journalctl -u mini-ops -f`.
3. Verify PAM config: `grep "pam_exec.so" /etc/pam.d/sshd`.
4. Verify the non-secret hook configuration and token metadata without printing
   the token: `sudo stat /etc/mini-ops/ssh-alert.conf /run/mini-ops/internal.token`.
5. Run the installed alert script as root to test connectivity without printing
   the token:
   ```bash
   sudo env PAM_USER=test PAM_RHOST=192.0.2.10 PAM_TYPE=open_session \
     /usr/local/bin/ssh-alert.sh
   ```
