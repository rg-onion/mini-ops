#!/bin/bash
# /usr/local/bin/ssh-alert.sh
# Called by PAM on successful login/logout
# To install: 
# 1. Copy to /usr/local/bin/ssh-alert.sh
# 2. chmod +x /usr/local/bin/ssh-alert.sh
# 3. Add to /etc/pam.d/sshd: session optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh

# Only run on open_session (login)
if [ "$PAM_TYPE" != "open_session" ]; then
    exit 0
fi

USER="$PAM_USER"
IP="$PAM_RHOST"
SERVICE="$PAM_SERVICE"
# PAM_TTY might be ssh, but we are in sshd config so it's implied
# Attempt to guess method specifically? 
# PAM doesn't easily give auth method (password vs key) in session phase without complex setup.
# We will send "unknown" or try to infer if possible, but usually it's hard from session hook.
METHOD="ssh" 
TIMESTAMP=$(date +%s)
API_URL="${MINI_OPS_API_URL:-http://127.0.0.1:3000/api/internal/ssh-login}"

# Read internal token
INTERNAL_TOKEN=$(cat /tmp/mini-ops-internal.token 2>/dev/null || echo "")

if [ -z "$INTERNAL_TOKEN" ]; then
    # Silently fail or log to syslog
    # logger -t ssh-alert "mini-ops internal token not found"
    exit 0
fi

# Send to mini-ops API (background, non-blocking)
# We use & to ensure it doesn't block login if API is slow
curl -sS --connect-timeout 1 --max-time 3 -X POST "$API_URL" \
    -H "Authorization: Bearer $INTERNAL_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"user\":\"$USER\",\"ip\":\"$IP\",\"method\":\"$METHOD\",\"timestamp\":$TIMESTAMP}" \
    >> /var/log/ssh-alert.log 2>&1 &

exit 0
