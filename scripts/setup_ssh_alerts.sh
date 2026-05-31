#!/bin/bash
# scripts/setup_ssh_alerts.sh
# Automates the setup of SSH alerts

set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

echo "🔧 Setting up SSH Alerts..."

# Determine script directory to find ssh-alert.sh correctly
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

# 1. Install script
if [ -f "${SCRIPT_DIR}/ssh-alert.sh" ]; then
    cp "${SCRIPT_DIR}/ssh-alert.sh" /usr/local/bin/ssh-alert.sh
    TOKEN_FILE="${MINI_OPS_INTERNAL_TOKEN_FILE:-${DEPLOY_TARGET_DIR:-/opt/mini-ops}/mini-ops-internal.token}"
    sed -i "s#http://127.0.0.1:3000#http://127.0.0.1:${DEPLOY_APP_PORT:-3000}#g" /usr/local/bin/ssh-alert.sh
    sed -i "s#/opt/mini-ops/mini-ops-internal.token#$TOKEN_FILE#g" /usr/local/bin/ssh-alert.sh
    chmod +x /usr/local/bin/ssh-alert.sh
    echo "✅ Copied hook to /usr/local/bin/ssh-alert.sh with port ${DEPLOY_APP_PORT:-3000}"
    echo "🔐 Internal token file: $TOKEN_FILE"
else
    echo "❌ Error: Could not find ${SCRIPT_DIR}/ssh-alert.sh"
    exit 1
fi

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

# 3. Create log file and secure permissions
touch /var/log/ssh-alert.log
chown root:root /var/log/ssh-alert.log
chmod 600 /var/log/ssh-alert.log

echo "🎉 SSH Alerts setup complete! Try logging in via SSH to test."
