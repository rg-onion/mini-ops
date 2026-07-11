#!/bin/bash -p
# scripts/setup_ssh_alerts.sh
# Automates the setup of SSH alerts

set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

APP_PORT="${DEPLOY_APP_PORT:-3000}"
if [[ ! "$APP_PORT" =~ ^[1-9][0-9]{0,4}$ ]] || (( 10#$APP_PORT > 65535 )); then
    echo "DEPLOY_APP_PORT must be an integer between 1 and 65535" >&2
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

for tool in \
    /usr/bin/chmod \
    /usr/bin/chown \
    /usr/bin/cmp \
    /usr/bin/cat \
    /usr/bin/cp \
    /usr/bin/curl \
    /usr/bin/date \
    /usr/bin/dd \
    /usr/bin/find \
    /usr/bin/flock \
    /usr/bin/grep \
    /usr/bin/id \
    /usr/bin/install \
    /usr/bin/mktemp \
    /usr/bin/mv \
    /usr/bin/rm \
    /usr/bin/setpriv \
    /usr/bin/stat \
    /usr/bin/sync; do
    if [ ! -x "$tool" ]; then
        echo "Required SSH-alert tool is unavailable: $tool" >&2
        exit 1
    fi
done

echo "🔧 Setting up SSH Alerts..."

# Determine script directory to find ssh-alert.sh correctly
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

assert_existing_directory_chain() {
    local path="$1"
    local current=""
    local part
    local old_ifs="$IFS"
    local -a parts

    [[ "$path" == /* ]] || return 1
    IFS='/'
    read -r -a parts <<< "${path#/}"
    IFS="$old_ifs"
    for part in "${parts[@]}"; do
        [[ -n "$part" ]] || continue
        current="$current/$part"
        [[ -d "$current" && ! -L "$current" ]] || return 1
    done
}

PAM_FILE="/etc/pam.d/sshd"
PAM_DIR="/etc/pam.d"
HOOK_SOURCE="${SCRIPT_DIR}/ssh-alert.sh"
HOOK_FILE="/usr/local/bin/ssh-alert.sh"
CONFIG_DIR="/etc/mini-ops"
CONFIG_FILE="${CONFIG_DIR}/ssh-alert.conf"
BACKUP_ROOT="/var/backups/mini-ops"
for required_directory in "$SCRIPT_DIR" "$PAM_DIR" /usr/local/bin /var/backups; do
    if ! assert_existing_directory_chain "$required_directory"; then
        echo "SSH-alert path contains a symlink, missing, or non-directory component: $required_directory" >&2
        exit 1
    fi
done

TOKEN_FILE="${MINI_OPS_INTERNAL_TOKEN_FILE:-/run/mini-ops/internal.token}"
TOKEN_USER="${MINI_OPS_APP_USER:-${DEPLOY_APP_USER:-miniops}}"

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

SETUP_LOCK_FILE=/run/mini-ops-ssh-alert-setup.lock
if [ -e "$SETUP_LOCK_FILE" ] || [ -L "$SETUP_LOCK_FILE" ]; then
    if [ ! -f "$SETUP_LOCK_FILE" ] || [ -L "$SETUP_LOCK_FILE" ] ||
        [ "$(/usr/bin/stat -c '%u:%g:%a' "$SETUP_LOCK_FILE")" != "0:0:600" ]; then
        echo "SSH-alert setup lock path is unsafe" >&2
        exit 1
    fi
else
    set -o noclobber
    : > "$SETUP_LOCK_FILE" 2>/dev/null || true
    set +o noclobber
    if [ ! -f "$SETUP_LOCK_FILE" ] || [ -L "$SETUP_LOCK_FILE" ]; then
        echo "SSH-alert setup lock creation failed" >&2
        exit 1
    fi
    chown root:root "$SETUP_LOCK_FILE"
    chmod 0600 "$SETUP_LOCK_FILE"
fi
exec {SETUP_LOCK_FD}> "$SETUP_LOCK_FILE"
if ! /usr/bin/flock --nonblock "$SETUP_LOCK_FD"; then
    echo "Another SSH-alert setup transaction is active" >&2
    exit 1
fi

GLOBAL_LOCK_FILE=/run/mini-ops-bootstrap.deploy.lock
GLOBAL_OWNER_FILE=/run/mini-ops-bootstrap.deploy.owner
BOOTSTRAP_LOCK_OWNER="${MINI_OPS_BOOTSTRAP_LOCK_OWNER:-}"
if [ -n "$BOOTSTRAP_LOCK_OWNER" ]; then
    if [[ ! "$BOOTSTRAP_LOCK_OWNER" =~ ^mini-ops-bootstrap-lock-[A-Za-z0-9]{8}$ ]] ||
        [ ! -f "$GLOBAL_OWNER_FILE" ] || [ -L "$GLOBAL_OWNER_FILE" ] ||
        [ "$(/usr/bin/stat -c '%u:%g:%a' "$GLOBAL_OWNER_FILE")" != "0:0:600" ] ||
        [ "$(/usr/bin/cat "$GLOBAL_OWNER_FILE")" != "$BOOTSTRAP_LOCK_OWNER" ]; then
        echo "Bootstrap deploy lock ownership proof failed" >&2
        exit 1
    fi
    set +e
    /usr/bin/flock --nonblock "$GLOBAL_LOCK_FILE" /bin/true
    GLOBAL_LOCK_STATUS=$?
    set -e
    if [ "$GLOBAL_LOCK_STATUS" -ne 1 ]; then
        echo "Bootstrap deploy lock is not held exclusively" >&2
        exit 1
    fi
else
    if [ -e "$GLOBAL_LOCK_FILE" ] || [ -L "$GLOBAL_LOCK_FILE" ]; then
        if [ ! -f "$GLOBAL_LOCK_FILE" ] || [ -L "$GLOBAL_LOCK_FILE" ] ||
            [ "$(/usr/bin/stat -c '%u:%g:%a' "$GLOBAL_LOCK_FILE")" != "0:0:600" ]; then
            echo "Global deploy lock path is unsafe" >&2
            exit 1
        fi
    else
        set -o noclobber
        : > "$GLOBAL_LOCK_FILE" 2>/dev/null || true
        set +o noclobber
        [ -f "$GLOBAL_LOCK_FILE" ] && [ ! -L "$GLOBAL_LOCK_FILE" ] || exit 1
        chown root:root "$GLOBAL_LOCK_FILE"
        chmod 0600 "$GLOBAL_LOCK_FILE"
    fi
    exec {GLOBAL_LOCK_FD}> "$GLOBAL_LOCK_FILE"
    if ! /usr/bin/flock --nonblock "$GLOBAL_LOCK_FD"; then
        echo "A managed bootstrap transaction is active" >&2
        exit 1
    fi
fi

SNAPSHOT=""
CONFIG_DIR_EXISTED=0
TRANSACTION_ARMED=0

if [ ! -f "$HOOK_SOURCE" ] || [ -L "$HOOK_SOURCE" ]; then
    echo "SSH-alert hook source must be a regular nofollow file" >&2
    exit 1
fi
if [ ! -f "$PAM_FILE" ] || [ -L "$PAM_FILE" ]; then
    echo "PAM sshd policy must be a regular nofollow file" >&2
    exit 1
fi
if [ "$(/usr/bin/stat -c '%u:%g' "$PAM_FILE")" != "0:0" ]; then
    echo "PAM sshd policy must remain root-owned" >&2
    exit 1
fi
PAM_HOOK_COUNT="$(grep -c 'ssh-alert[.]sh' "$PAM_FILE" || true)"
if [ "$PAM_HOOK_COUNT" -gt 1 ]; then
    echo "PAM sshd policy contains duplicate Mini-Ops hooks" >&2
    exit 1
fi
if [ "$PAM_HOOK_COUNT" -eq 1 ]; then
    if ! grep -Fxq "session optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh" "$PAM_FILE"; then
        echo "PAM sshd policy contains an unexpected Mini-Ops hook" >&2
        exit 1
    fi
fi
for destination in "$HOOK_FILE" "$CONFIG_FILE"; do
    if [ -e "$destination" ] || [ -L "$destination" ]; then
        if [ ! -f "$destination" ] || [ -L "$destination" ]; then
            echo "SSH-alert destination must be a regular nofollow file: $destination" >&2
            exit 1
        fi
    fi
done
if [ -e "$CONFIG_DIR" ] || [ -L "$CONFIG_DIR" ]; then
    if [ ! -d "$CONFIG_DIR" ] || [ -L "$CONFIG_DIR" ]; then
        echo "SSH-alert config directory must be a nofollow directory" >&2
        exit 1
    fi
    CONFIG_DIR_EXISTED=1
fi
if [ -e "$BACKUP_ROOT" ] || [ -L "$BACKUP_ROOT" ]; then
    if [ ! -d "$BACKUP_ROOT" ] || [ -L "$BACKUP_ROOT" ] ||
        [ "$(/usr/bin/stat -c '%u:%g:%a' "$BACKUP_ROOT")" != "0:0:700" ]; then
        echo "SSH-alert backup root must be a root-owned 0700 nofollow directory" >&2
        exit 1
    fi
else
    install -d -o root -g root -m 0700 "$BACKUP_ROOT"
fi
assert_existing_directory_chain "$BACKUP_ROOT" || {
    echo "SSH-alert backup path component proof failed" >&2
    exit 1
}

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT="$(mktemp -d "$BACKUP_ROOT/ssh-alert-direct-pre-${TIMESTAMP}.XXXXXX")"
chown root:root "$SNAPSHOT"
chmod 0700 "$SNAPSHOT"
install -d -o root -g root -m 0700 "$SNAPSHOT/files" "$SNAPSHOT/absent"

snapshot_file() {
    local source="$1"
    local key="$2"
    if [ -e "$source" ] || [ -L "$source" ]; then
        if [ ! -f "$source" ] || [ -L "$source" ]; then
            echo "SSH-alert snapshot source became unsafe" >&2
            exit 1
        fi
        cp --preserve=all -- "$source" "$SNAPSHOT/files/$key"
    else
        : > "$SNAPSHOT/absent/$key"
    fi
}

restore_file() {
    local destination="$1"
    local key="$2"
    local source="$SNAPSHOT/files/$key"
    local temporary
    if [ -f "$source" ]; then
        temporary="$(mktemp "$(dirname "$destination")/.ssh-alert-restore.XXXXXX")"
        install \
            -o "$(/usr/bin/stat -c %u "$source")" \
            -g "$(/usr/bin/stat -c %g "$source")" \
            -m "$(/usr/bin/stat -c %a "$source")" \
            "$source" "$temporary"
        /usr/bin/sync -f "$temporary"
        mv -fT "$temporary" "$destination"
        /usr/bin/sync -f "$(dirname "$destination")"
    elif [ -f "$SNAPSHOT/absent/$key" ]; then
        rm -f -- "$destination"
    fi
}

verify_restored_file() {
    local destination="$1"
    local key="$2"
    local source="$SNAPSHOT/files/$key"
    if [ -f "$source" ] && [ ! -L "$source" ]; then
        [ -f "$destination" ] && [ ! -L "$destination" ] || return 1
        cmp -s -- "$source" "$destination" || return 1
        [ "$(/usr/bin/stat -c '%u:%g:%a' "$source")" = "$(/usr/bin/stat -c '%u:%g:%a' "$destination")" ]
    elif [ -f "$SNAPSHOT/absent/$key" ] && [ ! -L "$SNAPSHOT/absent/$key" ]; then
        [ ! -e "$destination" ] && [ ! -L "$destination" ]
    else
        return 1
    fi
}

rollback_transaction() {
    local status=$?
    trap - EXIT
    set +e
    if [ "$status" -ne 0 ] && [ "$TRANSACTION_ARMED" -eq 1 ]; then
        rm -f -- "${HOOK_TMP:-}" "${CONFIG_TMP:-}" "${PAM_TMP:-}"
        restore_file "$PAM_FILE" pam-sshd
        restore_file "$HOOK_FILE" hook
        restore_file "$CONFIG_FILE" config
        if [ "$CONFIG_DIR_EXISTED" -eq 1 ]; then
            read -r config_uid config_gid config_mode < "$SNAPSHOT/config-dir-meta"
            chown "$config_uid:$config_gid" "$CONFIG_DIR"
            chmod "$config_mode" "$CONFIG_DIR"
        else
            rmdir "$CONFIG_DIR" >/dev/null 2>&1 || true
        fi
        rollback_degraded=0
        verify_restored_file "$PAM_FILE" pam-sshd || rollback_degraded=1
        verify_restored_file "$HOOK_FILE" hook || rollback_degraded=1
        verify_restored_file "$CONFIG_FILE" config || rollback_degraded=1
        if [ "$CONFIG_DIR_EXISTED" -eq 1 ]; then
            read -r config_uid config_gid config_mode < "$SNAPSHOT/config-dir-meta"
            [ "$(/usr/bin/stat -c '%u:%g:%a' "$CONFIG_DIR")" = "$config_uid:$config_gid:$config_mode" ] || rollback_degraded=1
        else
            [ ! -e "$CONFIG_DIR" ] && [ ! -L "$CONFIG_DIR" ] || rollback_degraded=1
        fi
        if [ "$rollback_degraded" -eq 1 ]; then
            echo "SSH-alert transaction rollback DEGRADED" >&2
            exit 71
        fi
        echo "SSH-alert transaction rollback VERIFIED" >&2
    fi
    exit "$status"
}

snapshot_file "$PAM_FILE" pam-sshd
snapshot_file "$HOOK_FILE" hook
snapshot_file "$CONFIG_FILE" config
if [ "$CONFIG_DIR_EXISTED" -eq 1 ]; then
    /usr/bin/stat -c '%u %g %a' "$CONFIG_DIR" > "$SNAPSHOT/config-dir-meta"
fi
find "$SNAPSHOT" -type f -exec /usr/bin/sync -f {} +
/usr/bin/sync -f "$SNAPSHOT/files"
/usr/bin/sync -f "$SNAPSHOT"
TRANSACTION_ARMED=1
trap rollback_transaction EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# 1. Install the root-owned hook and its non-secret configuration atomically.
HOOK_TMP="$(mktemp /usr/local/bin/.mini-ops-ssh-alert.XXXXXX)"
install -o root -g root -m 0755 "$HOOK_SOURCE" "$HOOK_TMP"
/usr/bin/sync -f "$HOOK_TMP"
mv -fT "$HOOK_TMP" "$HOOK_FILE"
/usr/bin/sync -f /usr/local/bin

install -d -o root -g root -m 0755 "$CONFIG_DIR"
assert_existing_directory_chain "$CONFIG_DIR" || {
    echo "SSH-alert config path component proof failed" >&2
    exit 1
}
CONFIG_TMP="$(mktemp "$CONFIG_DIR/.ssh-alert.conf.XXXXXX")"
{
    printf 'API_URL=http://127.0.0.1:%s/api/internal/ssh-login\n' "$APP_PORT"
    printf 'TOKEN_FILE=%s\n' "$TOKEN_FILE"
    printf 'TOKEN_USER=%s\n' "$TOKEN_USER"
    printf 'TOKEN_UID=%s\n' "$TOKEN_UID"
    printf 'TOKEN_GID=%s\n' "$TOKEN_GID"
} > "$CONFIG_TMP"
chown root:root "$CONFIG_TMP"
chmod 0600 "$CONFIG_TMP"
/usr/bin/sync -f "$CONFIG_TMP"
mv -fT "$CONFIG_TMP" "$CONFIG_FILE"
/usr/bin/sync -f "$CONFIG_DIR"

# 2. Configure PAM through same-directory atomic replacement.
if [ "$PAM_HOOK_COUNT" -eq 0 ]; then
    PAM_MODE="$(/usr/bin/stat -c '%a' "$PAM_FILE")"
    PAM_TMP="$(mktemp "$PAM_DIR/.mini-ops-sshd.XXXXXX")"
    install -o root -g root -m "$PAM_MODE" "$PAM_FILE" "$PAM_TMP"
    {
        printf '\n'
        printf '# Mini-Ops SSH Alert Hook\n'
        printf 'session optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh\n'
    } >> "$PAM_TMP"
    /usr/bin/sync -f "$PAM_TMP"
    mv -fT "$PAM_TMP" "$PAM_FILE"
    /usr/bin/sync -f "$PAM_DIR"
    echo "✅ Added configuration to $PAM_FILE"
else
    echo "ℹ️  Configuration already exists in $PAM_FILE"
fi

if [ "$(grep -Fxc 'session optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh' "$PAM_FILE")" -ne 1 ]; then
    echo "PAM sshd policy post-write proof failed" >&2
    exit 1
fi

if [ "$(/usr/bin/stat -c '%u:%g:%a' "$HOOK_FILE")" != "0:0:755" ] ||
    [ "$(/usr/bin/stat -c '%u:%g:%a' "$CONFIG_FILE")" != "0:0:600" ]; then
    echo "SSH-alert ownership/mode post-write proof failed" >&2
    exit 1
fi

TRANSACTION_ARMED=0
trap - EXIT INT TERM
echo "✅ Installed /usr/local/bin/ssh-alert.sh for loopback port $APP_PORT"
echo "🔐 Internal token path configured: $TOKEN_FILE"
echo "👤 Internal token owner configured: $TOKEN_USER"

echo "🎉 SSH Alerts setup complete! Try logging in via SSH to test."
