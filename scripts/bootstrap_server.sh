#!/bin/bash
set -euo pipefail

# One-command bootstrap for Ubuntu VPS.
# - Baseline hardening (UFW + fail2ban)
# - Non-root systemd service user
# - Deploy Mini-Ops binary
# - Optional SSH alerts PAM hook setup

DEPLOY_HOST="${DEPLOY_HOST:-}"
DEPLOY_SSH_USER="${DEPLOY_SSH_USER:-root}"
DEPLOY_SSH_PORT="${DEPLOY_SSH_PORT:-22}"
DEPLOY_TARGET_DIR="${DEPLOY_TARGET_DIR:-/opt/mini-ops}"
DEPLOY_APP_USER="${DEPLOY_APP_USER:-miniops}"
DEPLOY_MODE="${DEPLOY_MODE:-test}"                       # test | production
DEPLOY_INSTALL_DOCKER="${DEPLOY_INSTALL_DOCKER:-1}"      # 1 | 0
DEPLOY_SETUP_NGINX="${DEPLOY_SETUP_NGINX:-1}"            # 1 | 0
DEPLOY_NGINX_PORT="${DEPLOY_NGINX_PORT:-8090}"
DEPLOY_APP_PORT="${DEPLOY_APP_PORT:-3000}"               # internal app port
DEPLOY_ENABLE_SSH_ALERTS="${DEPLOY_ENABLE_SSH_ALERTS:-1}" # 1 | 0
DEPLOY_RUN_LOCAL_BUILD="${DEPLOY_RUN_LOCAL_BUILD:-1}"    # 1 | 0
DEPLOY_HARDENING="${DEPLOY_HARDENING:-1}"                # 1 | 0
DEPLOY_MINIMAL="${DEPLOY_MINIMAL:-0}"                    # 1 | 0 (no user/systemd/.env changes)
DEPLOY_WRITE_ENV="${DEPLOY_WRITE_ENV:-0}"                # 1 | 0 (only used with DEPLOY_MINIMAL=1)
DEPLOY_SYSTEMD_ONLY="${DEPLOY_SYSTEMD_ONLY:-0}"          # 1 | 0 (write systemd + restart only)

AUTH_TOKEN="${AUTH_TOKEN:-}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
SERVER_NAME="${SERVER_NAME:-}"
AGENT_LANG="${AGENT_LANG:-en}"
RUST_LOG="${RUST_LOG:-info}"

if [ -z "$DEPLOY_HOST" ]; then
  echo "Set DEPLOY_HOST, example:"
  echo "  DEPLOY_HOST=203.0.113.10 ./scripts/bootstrap_server.sh"
  exit 1
fi

if [ "$DEPLOY_MODE" != "test" ] && [ "$DEPLOY_MODE" != "production" ]; then
  echo "DEPLOY_MODE must be either 'test' or 'production'"
  exit 1
fi

if [ "$DEPLOY_SYSTEMD_ONLY" = "1" ] && [ "$DEPLOY_MINIMAL" = "1" ]; then
  echo "DEPLOY_SYSTEMD_ONLY=1 is incompatible with DEPLOY_MINIMAL=1"
  exit 1
fi

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd"
    exit 1
  fi
}

require_cmd ssh
require_cmd scp

if [ "$DEPLOY_SYSTEMD_ONLY" != "1" ] && [ "$DEPLOY_RUN_LOCAL_BUILD" = "1" ]; then
  require_cmd cargo
  require_cmd npm
fi

if [ "$DEPLOY_SYSTEMD_ONLY" != "1" ] && [ "$DEPLOY_RUN_LOCAL_BUILD" = "1" ]; then
  echo "[1/7] Building frontend and backend locally..."
  (cd frontend && npm install && npm run build)
  cargo build --release
fi

if [ "$DEPLOY_SYSTEMD_ONLY" != "1" ]; then
  if [ ! -x "target/release/mini-ops" ]; then
    echo "Binary not found: target/release/mini-ops"
    echo "Run with DEPLOY_RUN_LOCAL_BUILD=1 or build manually."
    exit 1
  fi
fi

SSH_OPTS=(-o StrictHostKeyChecking=accept-new)
REMOTE_SSH=(ssh -p "$DEPLOY_SSH_PORT" "${SSH_OPTS[@]}")
REMOTE_SCP=(scp -P "$DEPLOY_SSH_PORT" "${SSH_OPTS[@]}")
REMOTE="${DEPLOY_SSH_USER}@${DEPLOY_HOST}"

echo "[2/7] Detecting remote privileges..."
REMOTE_UID="$("${REMOTE_SSH[@]}" "$REMOTE" "id -u")"
REMOTE_SUDO=""
if [ "$REMOTE_UID" != "0" ]; then
  REMOTE_SUDO="sudo"
fi

if [ "$DEPLOY_SYSTEMD_ONLY" = "1" ]; then
  echo "[3/7] Systemd-only mode: skipping package installs and deploy steps"
else
  if [ "$DEPLOY_HARDENING" = "1" ] && [ "$DEPLOY_MINIMAL" != "1" ]; then
    echo "[3/7] Installing baseline packages and hardening tools..."
    if [ "$DEPLOY_SETUP_NGINX" = "1" ]; then
      "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO bash -lc 'apt-get update && apt-get install -y ca-certificates curl git ufw fail2ban rsync nginx && systemctl enable fail2ban --now'"
    else
      "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO bash -lc 'apt-get update && apt-get install -y ca-certificates curl git ufw fail2ban rsync && systemctl enable fail2ban --now'"
    fi
  else
    echo "[3/7] Skipping hardening step (DEPLOY_HARDENING=0)"
    if [ "$DEPLOY_SETUP_NGINX" = "1" ]; then
      echo "Ensuring Nginx is installed even though hardening is disabled..."
      "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO bash -lc 'if ! command -v nginx >/dev/null 2>&1; then apt-get update && apt-get install -y nginx; fi'"
    fi
  fi
fi

if [ "$DEPLOY_SYSTEMD_ONLY" != "1" ] && [ "$DEPLOY_INSTALL_DOCKER" = "1" ] && [ "$DEPLOY_MINIMAL" != "1" ]; then
  echo "[4/7] Ensuring Docker is installed..."
  "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO bash -lc 'if ! command -v docker >/dev/null 2>&1; then apt-get install -y docker.io; fi; systemctl enable docker --now'"
fi

if [ "$DEPLOY_SYSTEMD_ONLY" != "1" ]; then
  echo "[5/7] Deploying artifacts..."
  if [ "$DEPLOY_MINIMAL" != "1" ]; then
  "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO env DEPLOY_TARGET_DIR='$DEPLOY_TARGET_DIR' DEPLOY_APP_USER='$DEPLOY_APP_USER' bash -s" <<'EOF'
set -euo pipefail

id -u "$DEPLOY_APP_USER" >/dev/null 2>&1 || useradd --system --create-home --shell /usr/sbin/nologin "$DEPLOY_APP_USER"
if getent group docker >/dev/null 2>&1; then
  usermod -aG docker "$DEPLOY_APP_USER"
fi
mkdir -p "$DEPLOY_TARGET_DIR/scripts"
chown -R "$DEPLOY_APP_USER":"$DEPLOY_APP_USER" "$DEPLOY_TARGET_DIR"
EOF
  else
    "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO env DEPLOY_TARGET_DIR='$DEPLOY_TARGET_DIR' bash -s" <<'EOF'
set -euo pipefail

mkdir -p "$DEPLOY_TARGET_DIR/scripts"
EOF
  fi

"${REMOTE_SCP[@]}" target/release/mini-ops "$REMOTE:/tmp/mini-ops.new"
  "${REMOTE_SCP[@]}" scripts/setup_ssh_alerts.sh "$REMOTE:/tmp/setup_ssh_alerts.sh"
  "${REMOTE_SCP[@]}" scripts/ssh-alert.sh "$REMOTE:/tmp/ssh-alert.sh"

  "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO env DEPLOY_TARGET_DIR='$DEPLOY_TARGET_DIR' DEPLOY_APP_USER='$DEPLOY_APP_USER' DEPLOY_MINIMAL='$DEPLOY_MINIMAL' bash -s" <<'EOF'
set -euo pipefail

install -m 0755 /tmp/mini-ops.new "$DEPLOY_TARGET_DIR/mini-ops"
install -m 0755 /tmp/setup_ssh_alerts.sh "$DEPLOY_TARGET_DIR/scripts/setup_ssh_alerts.sh"
install -m 0755 /tmp/ssh-alert.sh "$DEPLOY_TARGET_DIR/scripts/ssh-alert.sh"
if [ "$DEPLOY_MINIMAL" != "1" ]; then
  chown "$DEPLOY_APP_USER":"$DEPLOY_APP_USER" "$DEPLOY_TARGET_DIR/mini-ops"
  chown -R root:root "$DEPLOY_TARGET_DIR/scripts"
fi
rm -f /tmp/mini-ops.new /tmp/setup_ssh_alerts.sh /tmp/ssh-alert.sh
EOF
fi

if [ "$DEPLOY_SYSTEMD_ONLY" = "1" ]; then
  echo "[6/7] Writing systemd unit only..."
  "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO env DEPLOY_TARGET_DIR='$DEPLOY_TARGET_DIR' DEPLOY_APP_USER='$DEPLOY_APP_USER' bash -s" <<'EOF'
set -euo pipefail

cat > /etc/systemd/system/mini-ops.service <<SERVICE
[Unit]
Description=Mini-Ops Agent
After=network.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=$DEPLOY_APP_USER
Group=$DEPLOY_APP_USER
SupplementaryGroups=docker
WorkingDirectory=$DEPLOY_TARGET_DIR
ExecStart=$DEPLOY_TARGET_DIR/mini-ops
EnvironmentFile=$DEPLOY_TARGET_DIR/.env
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DEPLOY_TARGET_DIR /tmp

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl restart mini-ops
EOF
elif [ "$DEPLOY_MINIMAL" != "1" ] || [ "$DEPLOY_WRITE_ENV" = "1" ]; then
  if [ "$DEPLOY_MINIMAL" != "1" ]; then
    echo "[6/7] Writing .env and systemd service..."
  else
    echo "[6/7] Writing .env only (DEPLOY_MINIMAL=1, DEPLOY_WRITE_ENV=1)"
  fi

  SCP_CMD=(scp -P "${SSH_PORT:-22}")
  if [ -n "${SSH_KEY_PATH:-}" ]; then
    SCP_CMD+=("-i" "$SSH_KEY_PATH")
  fi

  if [ -f ".env" ]; then
    echo "Found local .env file. Syncing to target..."
    "${SCP_CMD[@]}" .env "$REMOTE:/tmp/mini-ops-env.new"
  elif [ -f ".env.example" ]; then
    echo "No local .env found. Uploading .env.example as fallback..."
    "${SCP_CMD[@]}" .env.example "$REMOTE:/tmp/mini-ops-env.new"
  fi

  "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO env DEPLOY_TARGET_DIR='$DEPLOY_TARGET_DIR' DEPLOY_APP_USER='$DEPLOY_APP_USER' AUTH_TOKEN='$AUTH_TOKEN' TELEGRAM_BOT_TOKEN='$TELEGRAM_BOT_TOKEN' TELEGRAM_CHAT_ID='$TELEGRAM_CHAT_ID' SERVER_NAME='$SERVER_NAME' AGENT_LANG='$AGENT_LANG' RUST_LOG='$RUST_LOG' DEPLOY_MINIMAL='$DEPLOY_MINIMAL' DEPLOY_NGINX_PORT='$DEPLOY_NGINX_PORT' DEPLOY_APP_PORT='$DEPLOY_APP_PORT' DEPLOY_SETUP_NGINX='$DEPLOY_SETUP_NGINX' bash -s" <<'EOF'
set -euo pipefail

if [ -f /tmp/mini-ops-env.new ]; then
  cp /tmp/mini-ops-env.new "$DEPLOY_TARGET_DIR/.env"
  rm -f /tmp/mini-ops-env.new
else
  touch "$DEPLOY_TARGET_DIR/.env"
fi
grep -q '^APP_HOST=' "$DEPLOY_TARGET_DIR/.env" || echo 'APP_HOST=127.0.0.1' >> "$DEPLOY_TARGET_DIR/.env"
grep -q '^APP_PORT=' "$DEPLOY_TARGET_DIR/.env" || echo "APP_PORT=$DEPLOY_APP_PORT" >> "$DEPLOY_TARGET_DIR/.env"
grep -q '^DEPLOY_NGINX_PORT=' "$DEPLOY_TARGET_DIR/.env" || echo "DEPLOY_NGINX_PORT=$DEPLOY_NGINX_PORT" >> "$DEPLOY_TARGET_DIR/.env"
grep -q '^DATABASE_URL=' "$DEPLOY_TARGET_DIR/.env" || echo 'DATABASE_URL=sqlite:mini-ops.db' >> "$DEPLOY_TARGET_DIR/.env"
grep -q '^RUST_LOG=' "$DEPLOY_TARGET_DIR/.env" || echo "RUST_LOG=$RUST_LOG" >> "$DEPLOY_TARGET_DIR/.env"
grep -q '^AGENT_LANG=' "$DEPLOY_TARGET_DIR/.env" || echo "AGENT_LANG=$AGENT_LANG" >> "$DEPLOY_TARGET_DIR/.env"
grep -q '^SERVER_NAME=' "$DEPLOY_TARGET_DIR/.env" || echo "SERVER_NAME=${SERVER_NAME:-$(hostname)}" >> "$DEPLOY_TARGET_DIR/.env"

if [ -n "$AUTH_TOKEN" ]; then
  sed -i '/^AUTH_TOKEN=/d' "$DEPLOY_TARGET_DIR/.env"
  echo "AUTH_TOKEN=$AUTH_TOKEN" >> "$DEPLOY_TARGET_DIR/.env"
fi
if [ -n "$TELEGRAM_BOT_TOKEN" ]; then
  sed -i '/^TELEGRAM_BOT_TOKEN=/d' "$DEPLOY_TARGET_DIR/.env"
  echo "TELEGRAM_BOT_TOKEN=$TELEGRAM_BOT_TOKEN" >> "$DEPLOY_TARGET_DIR/.env"
fi
if [ -n "$TELEGRAM_CHAT_ID" ]; then
  sed -i '/^TELEGRAM_CHAT_ID=/d' "$DEPLOY_TARGET_DIR/.env"
  echo "TELEGRAM_CHAT_ID=$TELEGRAM_CHAT_ID" >> "$DEPLOY_TARGET_DIR/.env"
fi

chown root:"$DEPLOY_APP_USER" "$DEPLOY_TARGET_DIR/.env"
chmod 0640 "$DEPLOY_TARGET_DIR/.env"

if [ "$DEPLOY_MINIMAL" = "1" ]; then
  exit 0
fi

cat > /etc/systemd/system/mini-ops.service <<SERVICE
[Unit]
Description=Mini-Ops Agent
After=network.target docker.service
Wants=network-online.target

[Service]
Type=simple
User=$DEPLOY_APP_USER
Group=$DEPLOY_APP_USER
SupplementaryGroups=docker
WorkingDirectory=$DEPLOY_TARGET_DIR
ExecStart=$DEPLOY_TARGET_DIR/mini-ops
EnvironmentFile=$DEPLOY_TARGET_DIR/.env
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ProtectHome=true
ReadWritePaths=$DEPLOY_TARGET_DIR /tmp

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable mini-ops --now

if [ "$DEPLOY_SETUP_NGINX" = "1" ]; then
  cat > /etc/nginx/sites-available/mini-ops <<NGINX
server {
    listen $DEPLOY_NGINX_PORT;
    server_name _;

    location / {
        proxy_pass http://127.0.0.1:$DEPLOY_APP_PORT;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX
  rm -f /etc/nginx/sites-enabled/default
  ln -sf /etc/nginx/sites-available/mini-ops /etc/nginx/sites-enabled/mini-ops
  nginx -t && systemctl restart nginx
fi
EOF
else
  echo "[6/7] Skipping .env and systemd changes (DEPLOY_MINIMAL=1)"
fi

if [ "$DEPLOY_SYSTEMD_ONLY" = "1" ]; then
  echo "[7/7] Systemd-only mode: skipping firewall and SSH alerts"
elif [ "$DEPLOY_HARDENING" = "1" ] && [ "$DEPLOY_MINIMAL" != "1" ]; then
  echo "[7/7] Applying firewall and optional SSH alerts hook..."
  "${REMOTE_SSH[@]}" "$REMOTE" "$REMOTE_SUDO env DEPLOY_MODE='$DEPLOY_MODE' DEPLOY_ENABLE_SSH_ALERTS='$DEPLOY_ENABLE_SSH_ALERTS' DEPLOY_TARGET_DIR='$DEPLOY_TARGET_DIR' DEPLOY_NGINX_PORT='$DEPLOY_NGINX_PORT' DEPLOY_SETUP_NGINX='$DEPLOY_SETUP_NGINX' bash -s" <<'EOF'
set -euo pipefail

ufw allow OpenSSH
if [ "$DEPLOY_SETUP_NGINX" = "1" ]; then
  ufw allow "$DEPLOY_NGINX_PORT/tcp"
elif [ "$DEPLOY_MODE" = "test" ]; then
  ufw allow 3000/tcp
fi
ufw --force enable

if [ "$DEPLOY_ENABLE_SSH_ALERTS" = "1" ]; then
  bash "$DEPLOY_TARGET_DIR/scripts/setup_ssh_alerts.sh"
fi
EOF
else
  echo "[7/7] Skipping firewall and SSH alerts (DEPLOY_HARDENING=0)"
fi

echo
echo "Bootstrap complete."
echo "Host: $DEPLOY_HOST"
echo "Mode: $DEPLOY_MODE"
if [ "$DEPLOY_SETUP_NGINX" = "1" ]; then
  echo "Dashboard: http://$DEPLOY_HOST:$DEPLOY_NGINX_PORT"
elif [ "$DEPLOY_MODE" = "test" ]; then
  echo "Dashboard: http://$DEPLOY_HOST:3000"
else
  echo "Port 3000 was not opened by this script (production mode)."
fi
echo "Service logs:"
echo "  ssh -p $DEPLOY_SSH_PORT $REMOTE 'sudo journalctl -u mini-ops -f'"
