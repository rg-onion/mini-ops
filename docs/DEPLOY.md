# Deploying Mini-Ops

The legacy automated deployment scripts are disabled in this release. They
exit before building, opening SSH connections, installing packages, changing
firewall rules, writing PAM configuration, or restarting services. Use the
manual managed-systemd procedure below.

## Build locally

```bash
npm --prefix frontend ci
npm --prefix frontend run build
cargo build --release --locked
```

## Prepare the server

Record the local checksums, transfer the binary, unit, and SSH-alert scripts to
an unpredictable administrator-owned `0700` staging directory, and verify the
checksums again on the server before installation:

```bash
sha256sum target/release/mini-ops scripts/mini-ops.service \
  scripts/setup_ssh_alerts.sh scripts/ssh-alert.sh
```

Use your normal authenticated SSH/SCP workflow for the transfer. In the server
commands below, `/path/to/private-upload` means that verified private staging
directory; do not use a shared or predictable upload path.

Create the service account and immutable code/config directory:

```bash
sudo useradd --system --home /var/lib/mini-ops --shell /usr/sbin/nologin miniops
sudo install -d -o root -g root -m 0755 /opt/mini-ops
sudo install -d -o root -g root -m 0755 /opt/mini-ops/scripts
sudo install -o root -g root -m 0755 /path/to/private-upload/mini-ops \
  /opt/mini-ops/mini-ops
sudo install -o root -g root -m 0755 \
  /path/to/private-upload/setup_ssh_alerts.sh \
  /opt/mini-ops/scripts/setup_ssh_alerts.sh
sudo install -o root -g root -m 0755 /path/to/private-upload/ssh-alert.sh \
  /opt/mini-ops/scripts/ssh-alert.sh
```

Create `/opt/mini-ops/.env` as `root:root` mode `0600`:

```env
AUTH_TOKEN=
APP_HOST=127.0.0.1
APP_PORT=3000
DATABASE_URL=sqlite:///var/lib/mini-ops/mini-ops.db
MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token
MINI_OPS_ALLOW_WEB_UPDATE=false
MINI_OPS_ALLOW_DISK_CLEANUP=false
```

Generate `AUTH_TOKEN` with `openssl rand -hex 32`. Managed startup fails if the
token is missing, blank, weak, or a known placeholder; it never writes a state
`.env` file.

```bash
sudo install -o root -g root -m 0600 /path/to/prepared.env /opt/mini-ops/.env
sudo install -o root -g root -m 0644 /path/to/private-upload/mini-ops.service \
  /etc/systemd/system/mini-ops.service
sudo systemctl daemon-reload
sudo systemctl enable --now mini-ops
```

The unit creates `/var/lib/mini-ops` and `/run/mini-ops` as private
`miniops:miniops` directories. Code and `.env` remain root-owned. The service
uses `UMask=0077`, `ProtectSystem=strict`, and `ProtectHome=true`.

Verify without printing secrets:

```bash
sudo systemctl status mini-ops --no-pager -l
sudo journalctl -u mini-ops --since "10 minutes ago" --no-pager -n 100
sudo stat /opt/mini-ops/mini-ops /opt/mini-ops/.env \
  /var/lib/mini-ops/mini-ops.db /run/mini-ops/internal.token
curl --fail --silent http://127.0.0.1:3000/
```

## Optional SSH alerts

PAM configuration is a separate explicit operation:

```bash
sudo env MINI_OPS_APP_USER=miniops \
  MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token \
  DEPLOY_APP_PORT=3000 \
  /opt/mini-ops/scripts/setup_ssh_alerts.sh
```

The setup script does not change firewall rules. See [SSH_ALERTS.md](SSH_ALERTS.md).

## Network and Docker boundaries

The shipped service listens on loopback by default. Configure TLS and a reverse
proxy, VPN, or private network separately before external exposure. The unit
does not add the service account to the root-equivalent Docker group. Docker
integration requires an explicit administrator override and a separate risk
review.

Existing installations that keep mutable state under `/opt/mini-ops` must not
replace only the binary or unit with this layout. Preserve the current service
and state until you can perform a stopped-service migration with a verified
backup and rollback point.
