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

The embedded HTML applies a restrictive same-origin Content Security Policy and
does not load third-party browser resources. The supported Nginx renderer adds
the equivalent response CSP plus clickjacking, MIME-sniffing, referrer,
permissions, and cross-origin isolation headers. It deliberately does not add
HSTS because TLS termination is outside Mini-Ops. Keep the direct Axum listener
on loopback; an external reverse proxy must preserve these headers or provide
an equivalent policy.

The dashboard keeps the bearer token only in JavaScript module memory after a
successful login and removes the legacy `auth_token` key from both
`localStorage` and `sessionStorage`. Reloading, closing the
tab, or opening a new independent tab requires login again. This limits
credential persistence but is not equivalent to an `HttpOnly` server
session: script execution in the active page can still act with that page's
authority, so CSP remains defense-in-depth rather than the primary control.
CLI/API clients continue to use `Authorization: Bearer`.

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
    - `/var/run/docker.sock` must be a real final Unix socket and must not be
      world-writable and must be owned by root; a symlink or another file type
      cannot pass the check.
    - TCP API listeners on `2375`/`2376`: public or wildcard listeners fail,
      loopback-only listeners warn, and UDP listeners with the same port
      number do not count as the Docker TCP API.
    - Container hardening checks cover privileged mode; host network, PID,
      IPC, UTS, user, and cgroup namespaces; explicit capabilities and device
      access; sensitive host bind mounts; seccomp, no-new-privileges and
      unconfined system paths; and effective AppArmor/SELinux confinement.
      Only closed built-in/default profile facts prove confinement. Custom or
      malformed profiles, incomplete inspect data, and unavailable SELinux
      enforcement state remain `WARN`; known critical/high risks remain
      `FAIL` even when other facts are incomplete.
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
- Alert-worthy transitions and their Telegram delivery row are committed in one
  SQLite transaction. Retryable failures survive restart; a transition is
  marked delivered only after Telegram returns HTTP `2xx` with `ok=true`.
- Acknowledging an event does not cancel its pending delivery. Delivery state
  uses closed error codes and never stores the bot token, chat ID, request URL,
  or raw provider response.
- Security event JSON exposes nullable `notification_delivery_status`, attempt
  count, update time, and a closed error code. The internal transition sequence
  is not exposed.
- Security event JSON keeps the legacy `evidence_json` field and adds a typed
  `evidence` envelope with `schema_version`, `kind`, `data`, and `error_code`.
  For a valid v1 row, `kind` exactly matches `event_type`, `data` contains only
  allowlisted fields for that event kind, and `error_code` is `null`;
  `evidence_json` is the exact JSON serialization of that data. Unsupported or
  invalid stored evidence is not returned raw: `data` is `null`, `error_code`
  is `unsupported_schema_version` or `invalid_stored_payload`, and the legacy
  field is the exact string `{}`. Projection does not rewrite the stored row.

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

Docker audit work uses one internal deadline and bounded projections: at most
`256` containers; per inspected container, `256` capabilities, mounts, and
entries in each device category plus `64` security options; `64` daemon
security options; and `128` retained global risk rows. An overflow or timeout
returns closed incomplete evidence instead of a clean result. Risks collected
before the deadline are preserved, so a known `FAIL` is not downgraded by a
later timeout. Docker daemon error bodies are not copied into API responses or
application logs.

The API, background monitor, and optional Cloud Push consumer share one
language-neutral, single-flight audit snapshot. Concurrent refreshes join one
collection, and changing the API language does not run probes again. The
existing `/api/security/audit` body remains an array; successful responses add
`X-Security-Collector-Epoch`, `X-Security-Generation`,
`X-Security-Collected-At`, and `X-Security-Collection-Status` headers. If no new
publishable snapshot is available within the bounded collection window, the
route returns `503` with error code `security_audit_unavailable` rather than a
stale healthy result.

Unknown or incomplete facts remain visible as `WARN` and mark the snapshot
`degraded`. Cloud Push reads snapshots only; it skips a push when the snapshot
is missing, degraded, or older than twice the audit interval, because its
current security payload cannot express unknown values without misleading
zero/healthy fields.

## Sensitive-File Integrity

Sensitive-file integrity polling is a separate opt-in collector. Enable it with
`SECURITY_FILE_INTEGRITY_ENABLED=true`; the default is `false`. The collector
must run as a non-root service account. Explicit enablement while Mini-Ops has
effective UID `0` fails startup with the redacted code
`unsupported_runtime_identity` before integrity tables, worker tasks, or file
reads are created. The shipped managed unit runs as `miniops` and keeps
`ProtectHome=true`.

The initial allowlist covers `/etc/passwd`, `/etc/group`, `/etc/sudoers`,
`/etc/ssh/sshd_config`, `/etc/crontab`, and direct children of
`/etc/sudoers.d`, `/etc/ssh/sshd_config.d`, `/etc/cron.d`,
`/etc/cron.daily`, `/etc/cron.hourly`, and `/etc/cron.weekly`. It never recurses,
follows symlinks, reads devices/FIFOs/sockets, or traverses network/FUSE or
unclassified filesystems. Permission denial, an unsafe file type, an unknown
filesystem, timeout, or a capacity limit produces `degraded` coverage, never a
clean result. Home and root authorized-key files are intentionally outside this
low-privilege coverage boundary.

The first eligible scan creates a local trust-on-first-use baseline. Regular
file contents are streamed through SHA-256 on every scan; the 32-byte digest is
stored only in the private SQLite integrity tables. Contents, excerpts,
digests, symlink targets, and raw OS/SQL errors are never returned by the API or
written to security-event evidence, Telegram messages, or Cloud Push. Metadata
and content drift create bounded `file.sensitive_changed` events. Acknowledge
keeps the incident active and never changes the baseline.

The authenticated Security page and API expose aggregate states
`disabled`, `initializing`, `healthy`, `drift`, and `degraded`. Accepting a
complete current snapshot is a separate confirmed whole-snapshot action with
baseline/observation generation CAS; stale requests return `409`. Logical
baseline corruption requires a distinct confirmed re-enrollment action and a
fresh complete observation. Neither action runs automatically after package
updates. Structural SQLite corruption remains a restore-from-backup condition.

`SECURITY_FILE_INTEGRITY_INTERVAL_SECS` defaults to `300` and is clamped to
`60..86400`. Each single-flight scan is limited to `256` distinct path IDs,
`1 MiB` per file, `8 MiB` total bytes, a `64 KiB` streaming buffer, and a
`15 second` deadline. Current baseline/observation data has a `256 KiB` encoded
cap and no per-poll history. An unchanged healthy scan does not write SQLite.
This collector does not add a general audit check, change the security score,
or extend the Cloud Push schema.

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

The supported managed bootstrap validates a deterministic dry run before build
or network activity. Its defaults bind the app to loopback, keep code/config
root-owned, use private state/runtime directories, and leave firewall, public
HTTP, PAM, Docker installation, and root-equivalent Docker-group access
unchanged. Each expansion is explicit; the UFW option uses a bounded rollback
timer and a new SSH connection before commit. Legacy `deploy.sh` and
`provision.sh` remain hard-stopped. See [DEPLOY.md](DEPLOY.md).
