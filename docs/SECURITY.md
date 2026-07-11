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

### Experimental Web Source Builds
The `POST /api/deploy/webhook` endpoint remains protected by `AUTH_TOKEN`, but
it is disabled by default. Set `MINI_OPS_ALLOW_WEB_UPDATE=true` only when this
host should accept an experimental source-build request.

When enabled, Mini-Ops runs `scripts/update.sh` from the local checkout. The
script refuses non-git directories and tracked local changes, uses
`git pull --ff-only`, installs frontend dependencies from the lockfile when
available, and builds the backend with `cargo build --release --locked`. Only
one update can run at a time, and `/api/deploy/logs` streams bounded status
events without raw command output. `MINI_OPS_WEB_UPDATE_TIMEOUT_SECS` bounds each web-triggered update
(`1800` seconds by default). A successful terminal state means only that the
source build completed. Installation, service restart, health validation, and
rollback remain manual; the dashboard does not present this endpoint as an
agent update action.

### Disk Cleanup

The dashboard reports disk usage but does not expose cleanup actions. The
server-side cleanup endpoint is disabled unless
`MINI_OPS_ALLOW_DISK_CLEANUP=true` is set exactly. Even with that experimental
gate enabled, the `docker` target always returns `403 operation_unavailable`
and cannot invoke `docker system prune -af`.

## 📝 SSH Monitoring

The agent includes a PAM hook script that catches SSH login events and sends alerts to Telegram.

### How it Works
1.  **PAM Configuration**: The script `scripts/setup_ssh_alerts.sh` adds a call to `pam_exec.so` in `/etc/pam.d/sshd`.
2.  **Hook Script**: When a user logs in, PAM executes the root-owned `/usr/local/bin/ssh-alert.sh` installed by the setup script.
3.  **Token Validation**: Mini-Ops generates a random internal token at startup. Managed mode atomically writes `/run/mini-ops/internal.token`; standalone mode defaults to `mini-ops-internal.token`. The hook performs a bounded no-follow read as the configured service account and sends the bearer only to the loopback API with proxy and curlrc behavior disabled.
4.  **Telegram Alert**: The API verifies the internal token, validates the source IP, throttles repeated alerts per IP, and sends a message to the administrator unless the IP is trusted.

Does not require exposing the API to the internet (communication happens via `localhost`).

## ⚙️ Hardening Checks

The "Security Audit" section checks:
- **SSH**:
    - Bounded effective configuration via separate `sshd -T -C` root and
      representative non-root remote contexts. The selected TEST-NET context
      is included in evidence; it does not claim to enumerate every possible
      `Match` branch.
    - Root login disabled (`PermitRootLogin no`).
    - Password and keyboard-interactive authentication disabled, including the
      effective PAM path. A fallback read of `sshd_config` can only produce
      `WARN`, never `PASS`, because it cannot resolve `Include`/`Match` rules.
- **Firewall (UFW)**:
    - Status (Active/Inactive).
- **Fail2Ban**:
    - Service status via `systemctl is-active fail2ban`.
- **Listening ports**:
    - Open TCP/UDP ports via `ss -H -tuln`.
    - Protocol, local address, and loopback/wildcard/non-loopback scope are
      preserved. An unknown or malformed socket result remains `WARN`.
    - Ports outside `22`, `80`, `443`, `APP_PORT` (default `3000`), and `DEPLOY_NGINX_PORT` (default `8090`) are reported as warnings.
- **Docker**:
    - Docker socket world-writable permission check.
    - TCP API listeners on `2375`/`2376`: public or wildcard listeners fail,
      loopback-only listeners warn, and UDP listeners with the same port
      number do not count as the Docker TCP API.
    - Container hardening risks when Docker is available.
- **Disk encryption**:
    - A `PASS` requires a `crypt` device in the actual root filesystem backing
      tree reported by bounded `lsblk` JSON. An unrelated encrypted volume,
      missing root mount, or ambiguous output cannot prove encryption and is
      reported as `WARN`.

## Security Events

Mini-Ops stores security audit findings as local events in SQLite. Events are
created when an audit check reports `FAIL` or `WARN`, updated while the finding
remains active, and resolved when the check returns to `PASS`.

- Active events are shown on the Security page.
- Operators can acknowledge open events to reduce noise while keeping evidence.
- SSH logins from source IPs outside the trusted SSH IP baseline create
  `ssh.untrusted_source_ip` events; adding the IP to the trusted list resolves
  the matching event.
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

## Listening Port Baseline

Mini-Ops reports listening sockets that are not part of the local expected-port
baseline. It distinguishes public/wildcard listeners from loopback-only
listeners, and it does not change firewall rules or close ports.

The built-in baseline includes:

- `22`
- `80`
- `443`
- public/wildcard: `22`, `80`, `443`, `DEPLOY_NGINX_PORT` (`8090` by default)
- loopback-only: `APP_PORT` (`3000` by default)

Add site-specific expected ports with separate public and loopback baselines:

```env
SECURITY_ALLOWED_PUBLIC_PORTS=81,82,86
SECURITY_ALLOWED_LOOPBACK_PORTS=53,5435,9001
```

Invalid entries make the port check `WARN`; evidence exposes only a closed
configuration error code and invalid-entry count, never the raw environment
value.

## 🌐 Network & Deployment Security

### Deployment boundary

Legacy automated deployment scripts are disabled and exit before build,
network, firewall, PAM, or service mutations. The supported manual unit binds
the application to loopback, keeps code/config root-owned, uses private
state/runtime directories, and does not grant Docker-group access. See
[DEPLOY.md](DEPLOY.md).
