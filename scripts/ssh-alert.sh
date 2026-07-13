#!/bin/bash -p
# Called by pam_exec.so after a successful SSH session opens.

set -u
set +x
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

mini_ops_send_payload() {
    local internal_token="$1"
    local payload="$2"
    local api_url="$3"

    # curl reads the bearer header from bounded stdin config. `env -i`,
    # `--disable`, and `--noproxy` prevent inherited proxy/curlrc behavior.
    (
        printf 'header = "Authorization: Bearer %s"\n' "$internal_token" |
            /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin \
            /usr/bin/curl --disable --config - --noproxy '*' \
                --silent --show-error --fail \
                --connect-timeout 1 --max-time 3 --request POST \
                --header "Content-Type: application/json" \
                --data-binary "$payload" "$api_url" >/dev/null 2>&1
    ) >/dev/null 2>&1
}

# Non-root library mode exists only for the bounded local regression fixture.
# PAM invokes this hook as root, so PAM-controlled environment cannot select it.
if [ "${MINI_OPS_SSH_ALERT_LIBRARY_MODE:-}" = "1" ] && [ "$EUID" -ne 0 ]; then
    return 0 2>/dev/null || exit 0
fi

if [ "${PAM_TYPE:-}" != "open_session" ]; then
    exit 0
fi

CONFIG_FILE="/etc/mini-ops/ssh-alert.conf"
API_URL=""
TOKEN_FILE=""
TOKEN_USER=""
TOKEN_UID=""
TOKEN_GID=""

CONFIG_METADATA="$(/usr/bin/stat -c '%F:%a:%u:%g' -- "$CONFIG_FILE" 2>/dev/null)" || exit 0
if [ "$CONFIG_METADATA" != "regular file:600:0:0" ]; then
    exit 0
fi
while IFS='=' read -r key value; do
    case "$key" in
        API_URL) API_URL="$value" ;;
        TOKEN_FILE) TOKEN_FILE="$value" ;;
        TOKEN_USER) TOKEN_USER="$value" ;;
        TOKEN_UID) TOKEN_UID="$value" ;;
        TOKEN_GID) TOKEN_GID="$value" ;;
    esac
done < "$CONFIG_FILE"

if [[ ! "$API_URL" =~ ^http://127\.0\.0\.1:([0-9]{1,5})/api/internal/ssh-login$ ]]; then
    exit 0
fi
API_PORT="${BASH_REMATCH[1]}"
if (( API_PORT < 1 || API_PORT > 65535 )); then
    exit 0
fi
if [[ "$TOKEN_FILE" != /* || "$TOKEN_FILE" == *[[:cntrl:]]* ]]; then
    exit 0
fi
if [[ ! "$TOKEN_USER" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
    exit 0
fi
if [[ ! "$TOKEN_UID" =~ ^[0-9]+$ || ! "$TOKEN_GID" =~ ^[0-9]+$ ]]; then
    exit 0
fi
TOKEN_METADATA="$(/usr/bin/stat -c '%F:%a:%u:%g' -- "$TOKEN_FILE" 2>/dev/null)" || exit 0
if [ "$TOKEN_METADATA" != "regular file:600:${TOKEN_UID}:${TOKEN_GID}" ]; then
    exit 0
fi

INTERNAL_TOKEN="$(
    /usr/bin/setpriv --reuid="$TOKEN_UID" --regid="$TOKEN_GID" --clear-groups \
        /usr/bin/dd if="$TOKEN_FILE" iflag=nofollow,nonblock,count_bytes \
        count=513 status=none 2>/dev/null
)" || exit 0
if [ -z "$INTERNAL_TOKEN" ] || [ "${#INTERNAL_TOKEN}" -gt 512 ]; then
    exit 0
fi
case "$INTERNAL_TOKEN" in
    *[!A-Za-z0-9._~-]*) exit 0 ;;
esac

json_escape() {
    local value="${1:0:128}"
    value="${value//\\/\\\\}"
    value="${value//\"/\\\"}"
    value="${value//$'\n'/\\n}"
    value="${value//$'\r'/\\r}"
    value="${value//$'\t'/\\t}"
    printf '%s' "$value"
}

USER_JSON="$(json_escape "${PAM_USER:-unknown}")"
IP_JSON="$(json_escape "${PAM_RHOST:-unknown}")"
TIMESTAMP="$(/usr/bin/date +%s)" || exit 0
PAYLOAD="{\"user\":\"$USER_JSON\",\"ip\":\"$IP_JSON\",\"method\":\"ssh\",\"timestamp\":$TIMESTAMP}"

mini_ops_send_payload "$INTERNAL_TOKEN" "$PAYLOAD" "$API_URL" &

unset INTERNAL_TOKEN
exit 0
