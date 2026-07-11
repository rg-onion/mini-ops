#!/bin/bash -p
# scripts/setup_ssh_alerts.sh
# Automates the setup of SSH alerts

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

for tool in /usr/bin/curl /usr/bin/dd /usr/bin/setpriv /usr/bin/stat; do
    if [ ! -x "$tool" ]; then
        echo "Required SSH-alert tool is unavailable: $tool" >&2
        exit 1
    fi
done

echo "🔧 Setting up SSH Alerts..."

# Determine script directory to find ssh-alert.sh correctly
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

APP_PORT="${DEPLOY_APP_PORT:-3000}"
TOKEN_FILE="${MINI_OPS_INTERNAL_TOKEN_FILE:-/run/mini-ops/internal.token}"
TOKEN_USER="${MINI_OPS_APP_USER:-${DEPLOY_APP_USER:-miniops}}"

if [[ ! "$APP_PORT" =~ ^[0-9]+$ ]] || (( APP_PORT < 1 || APP_PORT > 65535 )); then
    echo "DEPLOY_APP_PORT must be an integer between 1 and 65535" >&2
    exit 1
fi
if [[ "$TOKEN_FILE" != /* || "$TOKEN_FILE" == *[[:cntrl:]]* ]]; then
    echo "MINI_OPS_INTERNAL_TOKEN_FILE must be an absolute path without control characters" >&2
    exit 1
fi
if [[ ! "$TOKEN_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]] || ! /usr/bin/id "$TOKEN_USER" >/dev/null 2>&1; then
    echo "MINI_OPS_APP_USER must name an existing local service account" >&2
    exit 1
fi
TOKEN_UID="$(/usr/bin/id -u "$TOKEN_USER")"
TOKEN_GID="$(/usr/bin/id -g "$TOKEN_USER")"

# 1. Install the root-owned hook and its non-secret configuration.
if [ ! -f "${SCRIPT_DIR}/ssh-alert.sh" ]; then
    echo "❌ Error: Could not find ${SCRIPT_DIR}/ssh-alert.sh"
    exit 1
fi
install -o root -g root -m 0755 "${SCRIPT_DIR}/ssh-alert.sh" /usr/local/bin/ssh-alert.sh
install -d -o root -g root -m 0755 /etc/mini-ops
CONFIG_TMP="$(mktemp /etc/mini-ops/.ssh-alert.conf.XXXXXX)"
trap 'rm -f "$CONFIG_TMP"' EXIT
printf 'API_URL=http://127.0.0.1:%s/api/internal/ssh-login\n' "$APP_PORT" > "$CONFIG_TMP"
printf 'TOKEN_FILE=%s\n' "$TOKEN_FILE" >> "$CONFIG_TMP"
printf 'TOKEN_USER=%s\n' "$TOKEN_USER" >> "$CONFIG_TMP"
printf 'TOKEN_UID=%s\n' "$TOKEN_UID" >> "$CONFIG_TMP"
printf 'TOKEN_GID=%s\n' "$TOKEN_GID" >> "$CONFIG_TMP"
chown root:root "$CONFIG_TMP"
chmod 0600 "$CONFIG_TMP"
mv -f "$CONFIG_TMP" /etc/mini-ops/ssh-alert.conf
trap - EXIT
echo "✅ Installed /usr/local/bin/ssh-alert.sh for loopback port $APP_PORT"
echo "🔐 Internal token path configured: $TOKEN_FILE"
echo "👤 Internal token owner configured: $TOKEN_USER"

# 2. Configure PAM
PAM_FILE="/etc/pam.d/sshd"

if ! grep -q "ssh-alert.sh" "$PAM_FILE"; then
    # Add to end of file
    echo "" >> "$PAM_FILE"
    echo "# Mini-Ops SSH Alert Hook" >> "$PAM_FILE"
    echo "session optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh" >> "$PAM_FILE"
    echo "✅ Added configuration to $PAM_FILE"
else
    echo "ℹ️  Configuration already exists in $PAM_FILE"
fi

echo "🎉 SSH Alerts setup complete! Try logging in via SSH to test."
