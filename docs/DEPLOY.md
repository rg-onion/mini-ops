# Deploying Mini-Ops

`scripts/bootstrap_server.sh` is the supported managed installer. The legacy
`deploy.sh` and `provision.sh` entrypoints remain disabled and exit before any
build, network, or mutation; they point operators to the managed bootstrap.
The manual managed-systemd procedure remains available below.

## Tagged release archive

The supported GitHub release asset contains the prebuilt binary at
`target/release/mini-ops` together with tracked scripts, configuration examples,
and public documentation. Verify `SHA256SUMS` and the GitHub attestation as
described in [RELEASING.md](RELEASING.md), then keep local compilation disabled:

```bash
DEPLOY_HOST=server.example \
  DEPLOY_DRY_RUN=1 \
  DEPLOY_RUN_LOCAL_BUILD=0 \
  ./scripts/bootstrap_server.sh
```

The dry run remains mandatory before providing a host or authorizing mutation.

## Managed bootstrap

Start with a deterministic dry run. Validation finishes before build, DNS,
SSH, package installation, or remote mutation:

```bash
DEPLOY_HOST=server.example \
  DEPLOY_DRY_RUN=1 \
  ./scripts/bootstrap_server.sh
```

The default plan builds from lockfiles, verifies the artifact architecture,
uses strict existing-host-key checking, installs a non-root `miniops` service,
binds the app to `127.0.0.1:3000`, and performs paired backup/rollback plus
service, API, SQLite path, owner, and mode proofs. It does not install Docker or
Nginx, expose HTTP, change UFW, add the Docker group, or write PAM.

For an existing managed installation, the default preserves and normalizes its
existing root-owned `.env`:

```bash
DEPLOY_HOST=server.example ./scripts/bootstrap_server.sh
```

For a fresh installation, explicitly provide a strong token and authorize the
private environment-file write. Keep the token out of command arguments and
unset it after the installer returns:

```bash
AUTH_TOKEN="$(openssl rand -hex 32)"
export AUTH_TOKEN
DEPLOY_HOST=server.example \
  DEPLOY_WRITE_ENV=1 \
  ./scripts/bootstrap_server.sh
unset AUTH_TOKEN
```

The remote account must be root or have passwordless `sudo`; SSH is
non-interactive. A new host key is rejected unless
`DEPLOY_ACCEPT_NEW_HOST_KEY=1` is explicitly selected and the learned
fingerprint is verified out of band.

Every additional mutation is separately opt-in:

- `DEPLOY_INSTALL_DOCKER=1` installs/enables Docker;
- `DEPLOY_ENABLE_DOCKER_INTEGRATION=1` grants the root-equivalent Docker group;
- `DEPLOY_SETUP_NGINX=1` creates a loopback listener;
- `DEPLOY_EXPOSE_HTTP=1` additionally permits a wildcard plain-HTTP listener;
- `DEPLOY_ENABLE_SSH_ALERTS=1` changes PAM;
- `DEPLOY_HARDENING=1` changes UFW and enables Fail2Ban.

The UFW path is unsupported behind NAT/port forwarding. It requires the
validated actual SSH listener port, a root-only snapshot, a bounded systemd
rollback timer, exact post-rule checks, and a new independent SSH connection
before commit. Failure restores the original files/state and rechecks SSH.
Firewall configuration is unchanged when `DEPLOY_HARDENING=0` (the default).

## Manual managed-systemd installation

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
