#!/bin/bash
set -euo pipefail

# Managed Mini-Ops bootstrap. Validation and DEPLOY_DRY_RUN complete before any
# build, DNS lookup, SSH connection, package installation, or remote mutation.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# shellcheck source=scripts/lib/deploy_contract.sh
source "$SCRIPT_DIR/lib/deploy_contract.sh"

DEPLOY_HOST="${DEPLOY_HOST:-}"
DEPLOY_SSH_USER="${DEPLOY_SSH_USER:-root}"
DEPLOY_SSH_PORT="${DEPLOY_SSH_PORT:-22}"
DEPLOY_TARGET_DIR="${DEPLOY_TARGET_DIR:-/opt/mini-ops}"
DEPLOY_APP_USER="${DEPLOY_APP_USER:-miniops}"
DEPLOY_MODE="${DEPLOY_MODE:-production}"
DEPLOY_INSTALL_DOCKER="${DEPLOY_INSTALL_DOCKER:-0}"
DEPLOY_ENABLE_DOCKER_INTEGRATION="${DEPLOY_ENABLE_DOCKER_INTEGRATION:-0}"
DEPLOY_SETUP_NGINX="${DEPLOY_SETUP_NGINX:-0}"
DEPLOY_EXPOSE_HTTP="${DEPLOY_EXPOSE_HTTP:-0}"
DEPLOY_NGINX_PORT="${DEPLOY_NGINX_PORT:-8090}"
DEPLOY_NGINX_EXTRA_LISTEN_IP="${DEPLOY_NGINX_EXTRA_LISTEN_IP:-}"
DEPLOY_APP_PORT="${DEPLOY_APP_PORT:-3000}"
DEPLOY_ENABLE_SSH_ALERTS="${DEPLOY_ENABLE_SSH_ALERTS:-0}"
DEPLOY_HARDENING="${DEPLOY_HARDENING:-0}"
DEPLOY_ALLOW_ROOT_SERVICE="${DEPLOY_ALLOW_ROOT_SERVICE:-0}"
DEPLOY_ACCEPT_NEW_HOST_KEY="${DEPLOY_ACCEPT_NEW_HOST_KEY:-0}"
DEPLOY_RUN_LOCAL_BUILD="${DEPLOY_RUN_LOCAL_BUILD:-1}"
DEPLOY_MINIMAL="${DEPLOY_MINIMAL:-0}"
DEPLOY_WRITE_ENV="${DEPLOY_WRITE_ENV:-0}"
DEPLOY_SYSTEMD_ONLY="${DEPLOY_SYSTEMD_ONLY:-0}"
DEPLOY_DRY_RUN="${DEPLOY_DRY_RUN:-0}"
DEPLOY_UFW_ROLLBACK_SECS="${DEPLOY_UFW_ROLLBACK_SECS:-180}"
SSH_KEY_PATH="${SSH_KEY_PATH:-}"

AUTH_TOKEN="${AUTH_TOKEN:-}"
TELEGRAM_BOT_TOKEN="${TELEGRAM_BOT_TOKEN:-}"
TELEGRAM_CHAT_ID="${TELEGRAM_CHAT_ID:-}"
SERVER_NAME="${SERVER_NAME:-}"
AGENT_LANG="${AGENT_LANG:-en}"
RUST_LOG="${RUST_LOG:-info}"

# Secrets are retained only as non-exported shell variables for the private
# staged env file. Build tools and SSH/SCP children must never inherit them.
export -n AUTH_TOKEN TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID

deploy_validate_config
deploy_print_warnings

if [[ "$DEPLOY_DRY_RUN" == "1" ]]; then
    deploy_print_plan
    exit 0
fi

require_command() {
    local command_name="$1"
    if ! command -v "$command_name" >/dev/null 2>&1; then
        deploy_error "required local command is unavailable: $command_name"
    fi
}

normalize_architecture() {
    case "$1" in
        x86_64|amd64) printf '%s\n' 'x86_64' ;;
        aarch64|arm64) printf '%s\n' 'aarch64' ;;
        *) deploy_error "unsupported architecture: $1" ;;
    esac
}

artifact_architecture() {
    local machine
    machine="$(LC_ALL=C readelf -h "$1" | awk -F: '/^[[:space:]]*Machine:/{sub(/^[[:space:]]+/, "", $2); print $2; exit}')"
    case "$machine" in
        *X86-64*|*x86-64*) printf '%s\n' 'x86_64' ;;
        *AArch64*) printf '%s\n' 'aarch64' ;;
        *) deploy_error "unsupported or unreadable artifact architecture" ;;
    esac
}

for required in ssh scp mktemp readelf awk cat chmod; do
    require_command "$required"
done
if [[ "$DEPLOY_RUN_LOCAL_BUILD" == "1" ]]; then
    require_command node
    require_command npm
    require_command cargo
    [[ -f "$PROJECT_ROOT/frontend/package-lock.json" ]] || deploy_error 'frontend/package-lock.json is required'
    [[ -f "$PROJECT_ROOT/Cargo.lock" ]] || deploy_error 'Cargo.lock is required'
    deploy_validate_local_build_toolchain "$(node --version)" "$(npm --version)"
fi

if [[ -n "$SSH_KEY_PATH" ]]; then
    if [[ ! -f "$SSH_KEY_PATH" || -L "$SSH_KEY_PATH" ]]; then
        deploy_error "SSH_KEY_PATH must identify a regular, non-symlink key file"
    fi
fi
for artifact in \
    "$SCRIPT_DIR/mini-ops.service" \
    "$SCRIPT_DIR/lib/filesystem_transaction.sh" \
    "$SCRIPT_DIR/setup_ssh_alerts.sh" \
    "$SCRIPT_DIR/ssh-alert.sh"; do
    if [[ ! -f "$artifact" || -L "$artifact" ]]; then
        deploy_error "required deployment artifact is missing or unsafe: $artifact"
    fi
done

SSH_COMMON=(
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o ServerAliveInterval=5
    -o ServerAliveCountMax=2
)
if [[ "$DEPLOY_ACCEPT_NEW_HOST_KEY" == "1" ]]; then
    SSH_COMMON+=(-o StrictHostKeyChecking=accept-new)
else
    SSH_COMMON+=(-o StrictHostKeyChecking=yes)
fi
if [[ -n "$SSH_KEY_PATH" ]]; then
    SSH_COMMON+=(-i "$SSH_KEY_PATH")
fi
REMOTE_SSH=(ssh "${SSH_COMMON[@]}" -p "$DEPLOY_SSH_PORT")
REMOTE_SCP=(scp "${SSH_COMMON[@]}" -P "$DEPLOY_SSH_PORT")
REMOTE="${DEPLOY_SSH_USER}@${DEPLOY_HOST}"

LOCAL_STAGE=""
REMOTE_STAGE=""
REMOTE_UID=""
REMOTE_LOCK_UNIT=""

cleanup() {
    local status=$?
    trap - EXIT
    if [[ -n "$LOCAL_STAGE" && -d "$LOCAL_STAGE" ]]; then
        rm -rf -- "$LOCAL_STAGE"
    fi
    if [[ -n "$REMOTE_STAGE" && "$REMOTE_STAGE" =~ ^/tmp/mini-ops-deploy\.[A-Za-z0-9]{8}$ ]]; then
        "${REMOTE_SSH[@]}" "$REMOTE" "rm -rf -- '$REMOTE_STAGE'" >/dev/null 2>&1 || true
    fi
    if [[ -n "$REMOTE_LOCK_UNIT" && "$REMOTE_LOCK_UNIT" =~ ^mini-ops-bootstrap-lock-[A-Za-z0-9]{8}$ ]]; then
        release_remote_lock >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup EXIT

remote_root() {
    if [[ "$REMOTE_UID" == "0" ]]; then
        "${REMOTE_SSH[@]}" "$REMOTE" /bin/bash -s -- "$@"
    else
        "${REMOTE_SSH[@]}" "$REMOTE" sudo -n /bin/bash -s -- "$@"
    fi
}

remote_root_with_systemd_probes() {
    {
        deploy_emit_systemd_probe_functions
        cat
    } | remote_root "$@"
}

release_remote_lock() {
    [[ "$REMOTE_LOCK_UNIT" =~ ^mini-ops-bootstrap-lock-[A-Za-z0-9]{8}$ ]] || return 1
    remote_root "$REMOTE_LOCK_UNIT" <<'REMOTE_LOCK_RELEASE'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
UNIT="$1"
LOCK_FILE=/run/mini-ops-bootstrap.deploy.lock
OWNER_FILE=/run/mini-ops-bootstrap.deploy.owner
[[ -f "$OWNER_FILE" && ! -L "$OWNER_FILE" && "$(stat -c %u:%g:%a "$OWNER_FILE")" == 0:0:600 ]]
[[ "$(cat "$OWNER_FILE")" == "$UNIT" ]]
systemctl stop "$UNIT"
systemctl reset-failed "$UNIT" >/dev/null 2>&1 || true
if ! flock --nonblock "$LOCK_FILE" /bin/true; then
    printf 'REMOTE LOCK: lock remains held after transient service stop\n' >&2
    exit 1
fi
if [[ -f "$OWNER_FILE" && ! -L "$OWNER_FILE" && "$(cat "$OWNER_FILE")" == "$UNIT" ]]; then
    rm -f -- "$OWNER_FILE"
fi
REMOTE_LOCK_RELEASE
    REMOTE_LOCK_UNIT=""
}

assert_remote_lock() {
    [[ "$REMOTE_LOCK_UNIT" =~ ^mini-ops-bootstrap-lock-[A-Za-z0-9]{8}$ ]] || return 1
    remote_root "$REMOTE_LOCK_UNIT" <<'REMOTE_LOCK_PROOF'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
UNIT="$1"
LOCK_FILE=/run/mini-ops-bootstrap.deploy.lock
OWNER_FILE=/run/mini-ops-bootstrap.deploy.owner
state="$(timeout 5 systemctl is-active "$UNIT" 2>/dev/null)" || true
[[ "$state" == active ]]
main_pid="$(systemctl show "$UNIT" -p MainPID --value)"
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]]
[[ -f "$OWNER_FILE" && ! -L "$OWNER_FILE" && "$(stat -c %u:%g:%a "$OWNER_FILE")" == 0:0:600 ]]
[[ "$(cat "$OWNER_FILE")" == "$UNIT" ]]
set +e
flock --nonblock "$LOCK_FILE" /bin/true
probe_status=$?
set -e
[[ "$probe_status" == 1 ]]
REMOTE_LOCK_PROOF
}

printf '%s\n' '[1/8] Read-only SSH identity and privilege preflight'
REMOTE_UID="$("${REMOTE_SSH[@]}" "$REMOTE" 'id -u')"
if [[ ! "$REMOTE_UID" =~ ^[0-9]+$ ]]; then
    deploy_error "remote id preflight returned an invalid uid"
fi
if [[ "$REMOTE_UID" != "0" ]]; then
    "${REMOTE_SSH[@]}" "$REMOTE" 'command -v sudo >/dev/null 2>&1 && sudo -n true' ||
        deploy_error "remote user needs non-interactive sudo or root access"
fi

ACTUAL_SSH_PORT=""
if [[ "$DEPLOY_HARDENING" == "1" ]]; then
    # Expand SSH_CONNECTION on the remote shell.
    # shellcheck disable=SC2016
    ssh_connection="$("${REMOTE_SSH[@]}" "$REMOTE" 'printf "%s\n" "$SSH_CONNECTION"')"
    read -r _ _ _ ACTUAL_SSH_PORT extra <<< "$ssh_connection"
    if [[ -n "${extra:-}" || ! "$ACTUAL_SSH_PORT" =~ ^[0-9]+$ ]] ||
        (( 10#$ACTUAL_SSH_PORT < 1 || 10#$ACTUAL_SSH_PORT > 65535 )); then
        deploy_error "remote SSH_CONNECTION is ambiguous; refusing firewall mutation"
    fi
    if [[ "$ACTUAL_SSH_PORT" != "$DEPLOY_SSH_PORT" ]]; then
        deploy_error "SSH transport port does not match DEPLOY_SSH_PORT; NAT/forwarded firewall mutation is unsupported"
    fi
fi

remote_arch="$(remote_root_with_systemd_probes \
    "$DEPLOY_TARGET_DIR" \
    "$DEPLOY_APP_USER" \
    "$DEPLOY_WRITE_ENV" \
    "$DEPLOY_ENABLE_DOCKER_INTEGRATION" \
    "$DEPLOY_INSTALL_DOCKER" \
    "$DEPLOY_SETUP_NGINX" \
    "$DEPLOY_HARDENING" \
    "${ACTUAL_SSH_PORT:-0}" <<'REMOTE_PREFLIGHT'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL

TARGET="$1"
APP_USER="$2"
WRITE_ENV="$3"
DOCKER_INTEGRATION="$4"
INSTALL_DOCKER="$5"
SETUP_NGINX="$6"
HARDENING="$7"
SSH_PORT="$8"
STATE=/var/lib/mini-ops
STATE_QUARANTINE_BASE=/var/lib/mini-ops-bootstrap
STATE_QUARANTINE_ROOT=/var/lib/mini-ops-bootstrap/state-quarantine
UNIT=/etc/systemd/system/mini-ops.service

die() { printf 'REMOTE PREFLIGHT: %s\n' "$*" >&2; exit 1; }
[[ "$(id -u)" == 0 ]] || die 'root privilege was not established'

for tool in awk basename bash cat chmod chown cmp cp curl date df diff dirname find flock getent grep groupdel gpasswd id install ln mktemp mv pgrep python3 readlink rm rmdir sha256sum sleep ss stat sync systemctl systemd-run timeout touch tr uname useradd userdel usermod; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool unavailable: $tool"
done
if [[ "$INSTALL_DOCKER" == 1 || "$SETUP_NGINX" == 1 || "$HARDENING" == 1 ]]; then
    command -v apt-get >/dev/null 2>&1 || die 'apt-get is required by explicitly enabled package mutations'
fi

assert_no_symlink_components() {
    local path="$1"
    local part
    local current=""
    local old_ifs="$IFS"
    IFS='/'
    read -r -a parts <<< "${path#/}"
    IFS="$old_ifs"
    for part in "${parts[@]}"; do
        [[ -n "$part" ]] || continue
        current="${current}/${part}"
        [[ ! -L "$current" ]] || die 'managed path contains a symlink component'
    done
}

for path in "$TARGET" "$STATE" "$STATE_QUARANTINE_BASE" "$STATE_QUARANTINE_ROOT" /run/mini-ops /var/backups/mini-ops "$UNIT"; do
    assert_no_symlink_components "$path"
done
for directory in "$TARGET" "$STATE" /run/mini-ops /var/backups/mini-ops; do
    if [[ -e "$directory" || -L "$directory" ]]; then
        [[ -d "$directory" && ! -L "$directory" ]] || die 'managed directory path is not a nofollow directory'
    fi
done
if [[ -d "$STATE" ]]; then
    if find "$STATE" -xdev -mindepth 1 ! -type f -print -quit | grep -q .; then
        die 'managed state tree contains a symlink, directory, or non-regular object'
    fi
    if [[ "$APP_USER" == root ]]; then
        state_uid=0
        state_gid=0
    else
        id "$APP_USER" >/dev/null 2>&1 || die 'existing managed state requires an existing service account'
        state_uid="$(id -u "$APP_USER")"
        state_gid="$(id -g "$APP_USER")"
    fi
    [[ "$(stat -c %u:%g:%a "$STATE")" == "$state_uid:$state_gid:700" ]] || die 'existing managed state directory metadata is outside the exact app 0700 contract'
    while IFS= read -r state_entry; do
        [[ "$(stat -c %u:%g:%a "$state_entry")" == "$state_uid:$state_gid:600" ]] || die 'existing managed state file metadata is outside the exact app 0600 contract'
    done < <(find "$STATE" -xdev -mindepth 1 -maxdepth 1 -type f -print)
fi
for private_directory in "$STATE_QUARANTINE_BASE" "$STATE_QUARANTINE_ROOT"; do
    if [[ -e "$private_directory" || -L "$private_directory" ]]; then
        [[ -d "$private_directory" && ! -L "$private_directory" ]] || die 'state quarantine path is not a nofollow directory'
        [[ "$(stat -c %u:%g:%a "$private_directory")" == 0:0:700 ]] || die 'state quarantine path is not root:root 0700'
    fi
done
if [[ -d "$STATE_QUARANTINE_ROOT" ]] &&
    find "$STATE_QUARANTINE_ROOT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    die 'stale state quarantine requires operator review'
fi
if [[ -d "$TARGET" ]]; then
    if find "$TARGET" -xdev -type l -print -quit | grep -q .; then
        die 'managed code tree contains a symlink'
    fi
    if find "$TARGET" -xdev ! -type d ! -type f -print -quit | grep -q .; then
        die 'managed code tree contains a non-regular object'
    fi
    shopt -s dotglob nullglob
    for entry in "$TARGET"/*; do
        case "$(basename "$entry")" in
            scripts)
                [[ -d "$entry" && ! -L "$entry" ]] || die 'managed scripts entry is not a nofollow directory'
                ;;
            mini-ops|.env|mini-ops.db|mini-ops.db-wal|mini-ops.db-shm|mini-ops.db-journal|history.json|mini-ops-internal.token|internal.token)
                [[ -f "$entry" && ! -L "$entry" ]] || die 'managed code/state entry is not a regular nofollow file'
                ;;
            *) die 'managed code tree contains an unexpected entry; operator review is required' ;;
        esac
    done
    if [[ -d "$TARGET/scripts" ]]; then
        for entry in "$TARGET/scripts"/*; do
            case "$(basename "$entry")" in
                setup_ssh_alerts.sh|ssh-alert.sh|filesystem_transaction.sh)
                    [[ -f "$entry" && ! -L "$entry" ]] || die 'managed script is not a regular nofollow file'
                    ;;
                *) die 'managed scripts tree contains an unexpected entry; operator review is required' ;;
            esac
        done
    fi
    shopt -u dotglob nullglob
fi
for path in "$UNIT" "$TARGET/.env" "$STATE/mini-ops.db" "$STATE/mini-ops.db-wal" "$STATE/mini-ops.db-shm" "$STATE/mini-ops.db-journal" "$STATE/history.json"; do
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] || die 'managed file path is not regular'
    fi
done

for legacy in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json mini-ops-internal.token internal.token; do
    source_path="$TARGET/$legacy"
    if [[ -e "$source_path" || -L "$source_path" ]]; then
        [[ -f "$source_path" && ! -L "$source_path" ]] || die 'legacy state source is not regular'
    fi
done
if [[ "$SETUP_NGINX" == 1 ]]; then
    for directory in /etc/nginx /etc/nginx/sites-available /etc/nginx/sites-enabled; do
        if [[ -e "$directory" || -L "$directory" ]]; then
            [[ -d "$directory" && ! -L "$directory" ]] || die 'existing Nginx path is not a nofollow directory'
        fi
    done
    nginx_site=/etc/nginx/sites-available/mini-ops
    nginx_enabled=/etc/nginx/sites-enabled/mini-ops
    nginx_default=/etc/nginx/sites-enabled/default
    if [[ -e "$nginx_site" || -L "$nginx_site" ]]; then
        [[ -f "$nginx_site" && ! -L "$nginx_site" ]] || die 'existing Nginx site is not a regular nofollow file'
    fi
    if [[ -e "$nginx_enabled" || -L "$nginx_enabled" ]]; then
        [[ -L "$nginx_enabled" ]] || die 'existing enabled Nginx site is not a symlink'
        case "$(readlink "$nginx_enabled")" in
            /etc/nginx/sites-available/mini-ops|../sites-available/mini-ops) ;;
            *) die 'existing enabled Nginx site points to an unexpected target' ;;
        esac
    fi
    if [[ -e "$nginx_default" || -L "$nginx_default" ]]; then
        [[ -L "$nginx_default" ]] || die 'existing enabled Nginx default site is not a symlink'
        case "$(readlink "$nginx_default")" in
            /etc/nginx/sites-available/default|../sites-available/default) ;;
            *) die 'existing enabled Nginx default site points to an unexpected target' ;;
        esac
    fi
    if command -v nginx >/dev/null 2>&1; then
        set +e
        nginx_active_state="$(timeout 5 systemctl is-active nginx 2>/dev/null)"
        nginx_active_status=$?
        nginx_enabled_state="$(timeout 5 systemctl is-enabled nginx 2>/dev/null)"
        nginx_enabled_status=$?
        set -e
        case "$nginx_active_state:$nginx_active_status" in
            active:0|inactive:3|failed:3) ;;
            *) die 'existing Nginx active state is ambiguous or transitional' ;;
        esac
        case "$nginx_enabled_state:$nginx_enabled_status" in
            enabled:0|disabled:1) ;;
            enabled-runtime:0|static:0|indirect:0)
                die 'existing Nginx enabled state cannot be preserved exactly; normalize it before bootstrap'
                ;;
            masked:1|masked-runtime:1) die 'existing Nginx service is masked; operator choice is required' ;;
            *) die 'existing Nginx enabled state is ambiguous' ;;
        esac
    fi
fi
available_kib="$(df -Pk /var | awk 'NR==2 {print $4}')"
[[ "$available_kib" =~ ^[0-9]+$ ]] || die 'free-space probe was ambiguous'
(( available_kib >= 262144 )) || die 'at least 256 MiB free under /var is required'

service_was_active=-1
deploy_systemd_probe_active mini-ops service_was_active ||
    die 'mini-ops service state probe was ambiguous or transitional'
service_was_enabled=-1
service_enabled_probe_status=0
deploy_systemd_probe_enabled mini-ops service_was_enabled || service_enabled_probe_status=$?
case "$service_enabled_probe_status" in
    0) ;;
    2)
        die 'mini-ops enabled state cannot be preserved exactly; normalize it before bootstrap'
        ;;
    3) die 'mini-ops service is masked; operator choice is required' ;;
    *) die 'mini-ops enabled state probe was ambiguous' ;;
esac
if [[ "$service_was_active" == 0 ]]; then
    set +e
    timeout 5 pgrep -x mini-ops >/dev/null 2>&1
    process_status=$?
    set -e
    case "$process_status" in
        1) ;;
        0) die 'mini-ops process exists outside an active managed unit' ;;
        *) die 'mini-ops process probe was ambiguous' ;;
    esac
fi

DB_BASENAME=mini-ops.db
if [[ "$WRITE_ENV" == 0 ]]; then
    [[ -f "$TARGET/.env" ]] || die 'managed .env is absent; use DEPLOY_WRITE_ENV=1 with a strong AUTH_TOKEN for first install'
    env_size="$(stat -c %s "$TARGET/.env")"
    [[ "$env_size" =~ ^[0-9]+$ && "$env_size" -le 1048576 ]] || die 'existing .env exceeds the 1 MiB bootstrap bound'
    app_host_count="$(awk -F= '$1 == "APP_HOST" {count++} END {print count+0}' "$TARGET/.env")"
    (( app_host_count <= 1 )) || die 'existing APP_HOST is duplicated'
    app_host="$(awk -F= '$1 == "APP_HOST" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
    case "$app_host" in
        ''|127.0.0.1|localhost|::1) ;;
        *) die 'existing APP_HOST is not loopback; managed bootstrap will not preserve public app binding' ;;
    esac
    auth_count="$(awk -F= '$1 == "AUTH_TOKEN" {count++} END {print count+0}' "$TARGET/.env")"
    [[ "$auth_count" == 1 ]] || die 'existing AUTH_TOKEN must occur exactly once'
    auth_token="$(awk -F= '$1 == "AUTH_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
    (( ${#auth_token} >= 32 )) || die 'existing AUTH_TOKEN is absent or shorter than 32 characters'
    [[ "$auth_token" != *[$'\001'-$'\037'$'\177']* ]] || die 'existing AUTH_TOKEN contains control characters'
    [[ "$auth_token" =~ ^[A-Za-z0-9._~+/=-]{32,}$ ]] || die 'existing AUTH_TOKEN uses characters outside the managed dotenv-safe alphabet'
    lowered_token="$(printf '%s' "$auth_token" | tr '[:upper:]' '[:lower:]')"
    case "$lowered_token" in
        your_secret_token_here|your_secret_token|your_strong_token|change-me|change-me-strong-random-token|your-random-secure-string-at-least-32-chars|your_auth_token|auth_token|token)
            die 'existing AUTH_TOKEN is a known placeholder'
            ;;
    esac
    database_count="$(awk -F= '$1 == "DATABASE_URL" {count++} END {print count+0}' "$TARGET/.env")"
    (( database_count <= 1 )) || die 'existing DATABASE_URL is duplicated'
    database_url="$(awk -F= '$1 == "DATABASE_URL" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
    case "$database_url" in
        ''|sqlite:mini-ops.db|sqlite://mini-ops.db|sqlite:///var/lib/mini-ops/mini-ops.db) ;;
        sqlite:///var/lib/mini-ops/*)
            database_name="${database_url#sqlite:///var/lib/mini-ops/}"
            [[ "$database_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die 'custom managed DATABASE_URL must use one normalized filename'
            [[ "$database_name" != *..* ]] || die 'custom managed DATABASE_URL must not contain dot-dot'
            case "$database_name" in
                history.json|internal.token|mini-ops-internal.token|*-wal|*-shm|*-journal)
                    die 'custom managed DATABASE_URL collides with a reserved state filename'
                    ;;
            esac
            DB_BASENAME="$database_name"
            for suffix in '' -wal -shm -journal; do
                custom_path="$STATE/${database_name}${suffix}"
                if [[ -e "$custom_path" || -L "$custom_path" ]]; then
                    [[ -f "$custom_path" && ! -L "$custom_path" ]] || die 'custom managed database file is not regular'
                fi
            done
            for legacy in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json mini-ops-internal.token internal.token; do
                [[ ! -e "$TARGET/$legacy" && ! -L "$TARGET/$legacy" ]] || die 'custom managed DATABASE_URL conflicts with legacy /opt state; operator choice is required'
            done
            ;;
        *) die 'existing DATABASE_URL is outside managed private state or is too complex' ;;
    esac
fi

if [[ "$DB_BASENAME" == mini-ops.db ]]; then
    for sidecar in mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal; do
        if [[ -e "$TARGET/$sidecar" || -L "$TARGET/$sidecar" ]]; then
            [[ -f "$TARGET/mini-ops.db" && ! -L "$TARGET/mini-ops.db" ]] || die 'legacy SQLite sidecar exists without its main database'
        fi
        if [[ -e "$STATE/$sidecar" || -L "$STATE/$sidecar" ]]; then
            [[ -f "$STATE/mini-ops.db" && ! -L "$STATE/mini-ops.db" ]] || die 'managed SQLite sidecar exists without its main database'
        fi
    done
    legacy_state_present=0
    managed_state_present=0
    for name in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json; do
        [[ ! -e "$TARGET/$name" && ! -L "$TARGET/$name" ]] || legacy_state_present=1
        [[ ! -e "$STATE/$name" && ! -L "$STATE/$name" ]] || managed_state_present=1
    done
    [[ "$legacy_state_present" == 0 || "$managed_state_present" == 0 ]] || die 'legacy and managed state sets conflict; refusing overwrite or merge'
fi

if id "$APP_USER" >/dev/null 2>&1 && [[ "$APP_USER" != root ]]; then
    [[ "$(id -gn "$APP_USER")" == "$APP_USER" ]] || die 'existing service account primary group does not match its account name'
    if id -nG "$APP_USER" | tr ' ' '\n' | grep -qx docker && [[ "$DOCKER_INTEGRATION" != 1 ]]; then
        die 'service account already has docker group access; explicit DEPLOY_ENABLE_DOCKER_INTEGRATION=1 is required'
    fi
fi
if [[ "$DOCKER_INTEGRATION" == 1 && "$INSTALL_DOCKER" == 0 ]] && ! getent group docker >/dev/null 2>&1; then
    die 'Docker integration requested but docker group is absent; enable install or provision Docker first'
fi

if [[ "$HARDENING" == 1 ]]; then
    [[ "$SSH_PORT" =~ ^[0-9]+$ && "$SSH_PORT" != 0 ]] || die 'validated SSH transport port is unavailable'
    command -v timeout >/dev/null 2>&1 || die 'timeout is required for bounded listener probe'
    command -v ss >/dev/null 2>&1 || die 'ss is required for firewall listener proof'
    listener_count="$(timeout 5 ss -H -ltn | awk -v wanted="$SSH_PORT" '{local=$4; sub(/^.*:/, "", local); if (local == wanted) count++} END {print count+0}')"
    (( listener_count > 0 )) || die 'no bounded TCP listener proof for the actual SSH port'
    firewalld_is_active=-1
    deploy_systemd_probe_active firewalld firewalld_is_active ||
        die 'firewalld state probe was ambiguous or transitional'
    [[ "$firewalld_is_active" == 0 ]] ||
        die 'firewalld is active; mixed firewall managers are unsupported'
    for directory in /var/lib/mini-ops-bootstrap /var/lib/mini-ops-bootstrap/ufw-rollback; do
        if [[ -e "$directory" || -L "$directory" ]]; then
            [[ -d "$directory" && ! -L "$directory" && "$(stat -c %u:%g:%a "$directory")" == 0:0:700 ]] || die 'existing UFW rollback root is unsafe'
        fi
    done
    if [[ -e /etc/default/ufw || -L /etc/default/ufw ]]; then
        [[ -f /etc/default/ufw && ! -L /etc/default/ufw && "$(stat -c %u:%g /etc/default/ufw)" == 0:0 ]] || die 'existing UFW default file is unsafe'
    fi
fi

uname -m
REMOTE_PREFLIGHT
)"
remote_arch="$(normalize_architecture "$remote_arch")"

printf '%s\n' '[2/8] Locked local build and architecture proof'
if [[ "$DEPLOY_RUN_LOCAL_BUILD" == "1" ]]; then
    npm --prefix "$PROJECT_ROOT/frontend" ci --strict-allow-scripts
    npm --prefix "$PROJECT_ROOT/frontend" run build
    cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" --release --locked
fi
BINARY="$PROJECT_ROOT/target/release/mini-ops"
if [[ ! -f "$BINARY" || -L "$BINARY" || ! -x "$BINARY" ]]; then
    deploy_error "release artifact is missing or unsafe: $BINARY"
fi
artifact_arch="$(artifact_architecture "$BINARY")"
if [[ "$artifact_arch" != "$remote_arch" ]]; then
    deploy_error "artifact architecture $artifact_arch does not match remote architecture $remote_arch"
fi

printf '%s\n' '[3/8] Rendering root-owned managed artifacts'
umask 077
LOCAL_STAGE="$(mktemp -d "${TMPDIR:-/tmp}/mini-ops-local.XXXXXXXX")"
deploy_render_unit "$SCRIPT_DIR/mini-ops.service" "$DEPLOY_APP_USER" \
    "$DEPLOY_ENABLE_DOCKER_INTEGRATION" > "$LOCAL_STAGE/mini-ops.service"
chmod 0600 "$LOCAL_STAGE/mini-ops.service"

if [[ "$DEPLOY_SETUP_NGINX" == "1" ]]; then
    deploy_render_nginx "$DEPLOY_APP_PORT" "$DEPLOY_NGINX_PORT" \
        "$DEPLOY_EXPOSE_HTTP" "$DEPLOY_NGINX_EXTRA_LISTEN_IP" \
        > "$LOCAL_STAGE/mini-ops.nginx"
    chmod 0600 "$LOCAL_STAGE/mini-ops.nginx"
fi

if [[ "$DEPLOY_WRITE_ENV" == "1" ]]; then
    {
        printf 'AUTH_TOKEN=%s\n' "$AUTH_TOKEN"
        printf 'APP_HOST=127.0.0.1\n'
        printf 'APP_PORT=%s\n' "$DEPLOY_APP_PORT"
        printf 'DATABASE_URL=sqlite:///var/lib/mini-ops/mini-ops.db\n'
        printf 'MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token\n'
        printf 'RUST_LOG=%s\n' "$RUST_LOG"
        printf 'AGENT_LANG=%s\n' "$AGENT_LANG"
        [[ -z "$SERVER_NAME" ]] || printf 'SERVER_NAME=%s\n' "$SERVER_NAME"
        [[ -z "$TELEGRAM_BOT_TOKEN" ]] || printf 'TELEGRAM_BOT_TOKEN=%s\n' "$TELEGRAM_BOT_TOKEN"
        [[ -z "$TELEGRAM_CHAT_ID" ]] || printf 'TELEGRAM_CHAT_ID=%s\n' "$TELEGRAM_CHAT_ID"
    } > "$LOCAL_STAGE/mini-ops.env"
    chmod 0600 "$LOCAL_STAGE/mini-ops.env"
fi

printf '%s\n' '[4/8] Creating unpredictable private remote upload directory'
REMOTE_STAGE="$("${REMOTE_SSH[@]}" "$REMOTE" 'umask 077; mktemp -d /tmp/mini-ops-deploy.XXXXXXXX')"
if [[ ! "$REMOTE_STAGE" =~ ^/tmp/mini-ops-deploy\.[A-Za-z0-9]{8}$ ]]; then
    REMOTE_STAGE=""
    deploy_error 'remote mktemp returned an invalid upload path'
fi
"${REMOTE_SCP[@]}" "$BINARY" "$REMOTE:$REMOTE_STAGE/mini-ops"
"${REMOTE_SCP[@]}" "$LOCAL_STAGE/mini-ops.service" "$REMOTE:$REMOTE_STAGE/mini-ops.service"
"${REMOTE_SCP[@]}" "$SCRIPT_DIR/lib/filesystem_transaction.sh" "$REMOTE:$REMOTE_STAGE/filesystem_transaction.sh"
"${REMOTE_SCP[@]}" "$SCRIPT_DIR/setup_ssh_alerts.sh" "$REMOTE:$REMOTE_STAGE/setup_ssh_alerts.sh"
"${REMOTE_SCP[@]}" "$SCRIPT_DIR/ssh-alert.sh" "$REMOTE:$REMOTE_STAGE/ssh-alert.sh"
if [[ "$DEPLOY_SETUP_NGINX" == "1" ]]; then
    "${REMOTE_SCP[@]}" "$LOCAL_STAGE/mini-ops.nginx" "$REMOTE:$REMOTE_STAGE/mini-ops.nginx"
fi
if [[ "$DEPLOY_WRITE_ENV" == "1" ]]; then
    "${REMOTE_SCP[@]}" "$LOCAL_STAGE/mini-ops.env" "$REMOTE:$REMOTE_STAGE/mini-ops.env"
fi

lock_suffix="${REMOTE_STAGE##*.}"
REMOTE_LOCK_UNIT="mini-ops-bootstrap-lock-${lock_suffix}"
printf '%s\n' 'Acquiring exclusive remote deploy lease before the first shared mutation.'
remote_root "$REMOTE_LOCK_UNIT" <<'REMOTE_LOCK_ACQUIRE'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077
UNIT="$1"
LOCK_FILE=/run/mini-ops-bootstrap.deploy.lock
OWNER_FILE=/run/mini-ops-bootstrap.deploy.owner
[[ "$UNIT" =~ ^mini-ops-bootstrap-lock-[A-Za-z0-9]{8}$ ]] || exit 1
if [[ -e "$LOCK_FILE" || -L "$LOCK_FILE" ]]; then
    [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" && "$(stat -c %u:%g:%a "$LOCK_FILE")" == 0:0:600 ]] || {
        printf 'REMOTE LOCK: existing lock path is unsafe\n' >&2
        exit 1
    }
else
    set -o noclobber
    : > "$LOCK_FILE" 2>/dev/null || true
    set +o noclobber
    [[ -f "$LOCK_FILE" && ! -L "$LOCK_FILE" ]] || exit 1
    chown root:root "$LOCK_FILE"
    chmod 0600 "$LOCK_FILE"
fi
if [[ -e "$OWNER_FILE" || -L "$OWNER_FILE" ]]; then
    [[ -f "$OWNER_FILE" && ! -L "$OWNER_FILE" && "$(stat -c %u:%g:%a "$OWNER_FILE")" == 0:0:600 ]] || {
        printf 'REMOTE LOCK: existing owner marker is unsafe\n' >&2
        exit 1
    }
fi

systemd-run \
    --quiet \
    --unit "$UNIT" \
    --property=RuntimeMaxSec=3600 \
    /usr/bin/flock --nonblock "$LOCK_FILE" \
    /bin/bash -c 'umask 077; temporary="${2}.tmp.$$"; printf "%s\n" "$1" > "$temporary"; mv -fT "$temporary" "$2"; sync -f "$2"; exec /bin/sleep 3600' \
    lock-owner "$UNIT" "$OWNER_FILE"
active=0
stable_pid=""
for ((attempt = 0; attempt < 20; attempt++)); do
    set +e
    state="$(timeout 3 systemctl is-active "$UNIT" 2>/dev/null)"
    state_status=$?
    set -e
    case "$state:$state_status" in
        active:0)
            main_pid="$(systemctl show "$UNIT" -p MainPID --value)"
            if [[ "$main_pid" =~ ^[1-9][0-9]*$ && -f "$OWNER_FILE" && ! -L "$OWNER_FILE" && "$(stat -c %u:%g:%a "$OWNER_FILE")" == 0:0:600 && "$(cat "$OWNER_FILE")" == "$UNIT" ]]; then
                if [[ "$stable_pid" == "$main_pid" ]]; then
                    active=1
                    break
                fi
                stable_pid="$main_pid"
            fi
            sleep 0.1
            ;;
        activating:3) sleep 0.1 ;;
        failed:3|inactive:3)
            printf 'REMOTE LOCK: another deployment holds the lease\n' >&2
            exit 1
            ;;
        *) printf 'REMOTE LOCK: transient lease state is ambiguous\n' >&2; exit 1 ;;
    esac
done
[[ "$active" == 1 ]] || exit 1
exec_start="$(systemctl show "$UNIT" -p ExecStart --value)"
[[ "$exec_start" == *'/usr/bin/flock'* && "$exec_start" == *'/run/mini-ops-bootstrap.deploy.lock'* && "$exec_start" == *"$UNIT"* ]] || {
    systemctl stop "$UNIT" >/dev/null 2>&1 || true
    printf 'REMOTE LOCK: transient service command proof failed\n' >&2
    exit 1
}
set +e
flock --nonblock "$LOCK_FILE" /bin/true
lock_probe_status=$?
set -e
[[ "$lock_probe_status" == 1 ]] || {
    systemctl stop "$UNIT" >/dev/null 2>&1 || true
    printf 'REMOTE LOCK: exclusive lease proof failed\n' >&2
    exit 1
}
REMOTE_LOCK_ACQUIRE

printf '%s\n' '[5/8] Installing explicitly requested packages'
if [[ "$DEPLOY_INSTALL_DOCKER" == "1" || "$DEPLOY_SETUP_NGINX" == "1" || "$DEPLOY_HARDENING" == "1" ]]; then
    remote_root \
        "$DEPLOY_INSTALL_DOCKER" \
        "$DEPLOY_SETUP_NGINX" \
        "$DEPLOY_HARDENING" <<'REMOTE_PACKAGES'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
INSTALL_DOCKER="$1"
SETUP_NGINX="$2"
HARDENING="$3"
packages=()
NGINX_RUNTIME_MASKED=0
cleanup_package_guard() {
    status=$?
    trap - EXIT
    if [[ "$status" != 0 && "$NGINX_RUNTIME_MASKED" == 1 ]]; then
        systemctl unmask --runtime nginx.service >/dev/null 2>&1 || true
    fi
    exit "$status"
}
trap cleanup_package_guard EXIT
if [[ "$SETUP_NGINX" == 1 ]] && ! command -v nginx >/dev/null 2>&1; then
    systemctl mask --runtime nginx.service
    NGINX_RUNTIME_MASKED=1
fi
[[ "$INSTALL_DOCKER" == 1 ]] && packages+=(docker.io)
[[ "$SETUP_NGINX" == 1 ]] && packages+=(nginx)
[[ "$HARDENING" == 1 ]] && packages+=(ufw fail2ban)
if (( ${#packages[@]} > 0 )); then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
fi
if [[ "$INSTALL_DOCKER" == 1 ]]; then
    systemctl enable --now docker
fi
if [[ "$NGINX_RUNTIME_MASKED" == 1 ]]; then
    set +e
    nginx_state="$(timeout 5 systemctl is-active nginx 2>/dev/null)"
    nginx_state_status=$?
    set -e
    case "$nginx_state:$nginx_state_status" in
        inactive:3|failed:3) ;;
        *) printf 'REMOTE PACKAGES: Nginx unexpectedly started before managed config\n' >&2; exit 1 ;;
    esac
    systemctl unmask --runtime nginx.service
    NGINX_RUNTIME_MASKED=0
fi
trap - EXIT
REMOTE_PACKAGES
else
    printf '%s\n' 'No package or auxiliary service mutation requested.'
fi

assert_remote_lock || deploy_error 'exclusive deploy lease was lost before the core transaction'

printf '%s\n' '[6/8] Atomic managed install, migration, rollback guard, and health proof'
remote_root_with_systemd_probes \
    "$REMOTE_STAGE" \
    "$REMOTE_UID" \
    "$DEPLOY_APP_USER" \
    "$DEPLOY_APP_PORT" \
    "$DEPLOY_WRITE_ENV" \
    "$DEPLOY_ENABLE_DOCKER_INTEGRATION" \
    "$DEPLOY_SETUP_NGINX" \
    "$DEPLOY_NGINX_PORT" \
    "$DEPLOY_EXPOSE_HTTP" \
    "$DEPLOY_NGINX_EXTRA_LISTEN_IP" <<'REMOTE_INSTALL'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077

STAGE="$1"
UPLOAD_UID="$2"
APP_USER="$3"
APP_PORT="$4"
WRITE_ENV="$5"
DOCKER_INTEGRATION="$6"
SETUP_NGINX="$7"
NGINX_PORT="$8"
EXPOSE_HTTP="$9"
EXTRA_LISTEN_IP="${10:-}"
TARGET=/opt/mini-ops
STATE=/var/lib/mini-ops
STATE_QUARANTINE_BASE=/var/lib/mini-ops-bootstrap
STATE_QUARANTINE_ROOT=/var/lib/mini-ops-bootstrap/state-quarantine
RUNTIME=/run/mini-ops
BACKUPS=/var/backups/mini-ops
UNIT=/etc/systemd/system/mini-ops.service
NGINX_SITE=/etc/nginx/sites-available/mini-ops
NGINX_ENABLED=/etc/nginx/sites-enabled/mini-ops
NGINX_DEFAULT=/etc/nginx/sites-enabled/default
TX_HELPER="$STAGE/filesystem_transaction.sh"
MANAGED_TREE_PROOF_TIMEOUT_SECS=30
SNAPSHOT=""
SERVICE_WAS_ACTIVE=0
SERVICE_WAS_ENABLED=0
ROLLBACK_ARMED=0
STOP_GUARD_ARMED=0
TARGET_WAS_DIR=0
SCRIPTS_WAS_DIR=0
STATE_WAS_DIR=0
RUNTIME_WAS_DIR=0
APP_USER_CREATED=0
APP_GROUP_CREATED=0
APP_HAD_DOCKER=0
DOCKER_MEMBERSHIP_ADDED=0
NGINX_WAS_ACTIVE=0
NGINX_WAS_ENABLED=0
NGINX_DEFAULT_WAS_LINK=0
STATE_ISOLATED=0
STATE_ISOLATION_DIR=""
STATE_ISOLATED_PATH=""
STATE_ROOT_CONTROLLED=0
STATE_SNAPSHOT_SOURCE="$STATE"

die() { printf 'REMOTE INSTALL: %s\n' "$*" >&2; exit 1; }

[[ -f "$TX_HELPER" && ! -L "$TX_HELPER" && "$(stat -c %u "$TX_HELPER")" == "$UPLOAD_UID" ]] || die 'filesystem transaction helper is unsafe'
# shellcheck source=scripts/lib/filesystem_transaction.sh
source "$TX_HELPER"

assert_regular() {
    [[ -f "$1" && ! -L "$1" ]] || die 'required artifact is not a regular nofollow file'
}

assert_staged() {
    assert_regular "$1"
    [[ "$(stat -c %u "$1")" == "$UPLOAD_UID" ]] || die 'staged artifact owner changed after upload'
}

atomic_install() {
    tx_atomic_install "$@" || die 'atomic install failed'
}

atomic_symlink() {
    local target="$1"
    local destination="$2"
    local directory
    local temporary
    directory="$(dirname "$destination")"
    [[ -d "$directory" && ! -L "$directory" ]] || return 1
    temporary="$(mktemp "$directory/.mini-ops-link.XXXXXXXX")"
    rm -f -- "$temporary"
    ln -s -- "$target" "$temporary"
    mv -fT "$temporary" "$destination"
    sync -f "$directory"
}

snapshot_file() {
    tx_snapshot_file "$SNAPSHOT" "$1" "$2" || die 'snapshot source is not a regular nofollow file'
}

snapshot_directory_metadata() {
    tx_snapshot_directory_metadata "$SNAPSHOT" "$1" "$2" || die 'directory metadata snapshot failed'
}

restore_directory_metadata() {
    tx_restore_directory_metadata "$SNAPSHOT" "$1" "$2"
}

probe_active_state() {
    local unit="$1"
    local result_name="$2"
    deploy_systemd_probe_active "$unit" "$result_name" ||
        die "ambiguous or transitional active state for $unit"
}

probe_enabled_state() {
    local unit="$1"
    local result_name="$2"
    local probe_status=0
    deploy_systemd_probe_enabled "$unit" "$result_name" || probe_status=$?
    case "$probe_status" in
        0) ;;
        2)
            die "$unit enabled state cannot be preserved exactly"
            ;;
        3) die "$unit is masked; operator choice is required" ;;
        *) die "ambiguous enabled state for $unit" ;;
    esac
}

restore_file() {
    tx_restore_file "$SNAPSHOT" "$1" "$2"
}

verify_restored_file() {
    tx_verify_restored_file "$SNAPSHOT" "$1" "$2"
}

verify_restored_directory() {
    local uid gid mode
    [[ -f "$SNAPSHOT/directory-$2" ]] || return 1
    read -r uid gid mode < "$SNAPSHOT/directory-$2"
    [[ -d "$1" && ! -L "$1" && "$(stat -c %u:%g:%a "$1")" == "$uid:$gid:$mode" ]]
}

assert_managed_state_tree() {
    local directory="$1"
    local entry
    local name
    local dotglob_was=0
    local nullglob_was=0

    tx_assert_existing_directory_components "$directory" || die 'managed state path has an unsafe directory component'
    shopt -q dotglob && dotglob_was=1
    shopt -q nullglob && nullglob_was=1
    shopt -s dotglob nullglob
    for entry in "$directory"/*; do
        name="$(basename "$entry")"
        case "$name" in
            "$DB_BASENAME"|"$DB_BASENAME-wal"|"$DB_BASENAME-shm"|"$DB_BASENAME-journal"|history.json) ;;
            *) die 'managed state tree contains an unexpected entry' ;;
        esac
        [[ -f "$entry" && ! -L "$entry" ]] || die 'managed state tree contains a symlink or non-regular object'
    done
    [[ "$dotglob_was" == 1 ]] || shopt -u dotglob
    [[ "$nullglob_was" == 1 ]] || shopt -u nullglob
}

assert_existing_state_metadata() {
    local directory="$1"
    local expected_uid
    local expected_gid
    local entry

    if [[ "$APP_USER" == root ]]; then
        expected_uid=0
        expected_gid=0
    else
        id "$APP_USER" >/dev/null 2>&1 || die 'existing managed state requires an existing service account'
        expected_uid="$(id -u "$APP_USER")"
        expected_gid="$(id -g "$APP_USER")"
    fi
    [[ "$(stat -c %u:%g:%a "$directory")" == "$expected_uid:$expected_gid:700" ]] ||
        die 'existing managed state directory metadata changed before quarantine'
    shopt -s dotglob nullglob
    for entry in "$directory"/*; do
        [[ "$(stat -c %u:%g:%a "$entry")" == "$expected_uid:$expected_gid:600" ]] ||
            die 'existing managed state file metadata changed before quarantine'
    done
    shopt -u dotglob nullglob
}

assert_no_open_managed_tree() {
    local directory="$1"
    local label="$2"
    local status

    set +e
    # A complete procfs sweep can exceed five seconds on container hosts, and
    # the helper may take up to three fail-safe snapshots for transient races.
    timeout "$MANAGED_TREE_PROOF_TIMEOUT_SECS" /bin/bash "$TX_HELPER" --assert-no-open-tree "$directory"
    status=$?
    set -e
    case "$status" in
        0) ;;
        42) die "an open descriptor, cwd, or mapping still references the managed $label tree" ;;
        *) die "bounded managed $label tree process proof was ambiguous" ;;
    esac
}

assert_no_service_uid_processes() {
    local app_uid
    local status

    [[ "$APP_USER" != root ]] || return 0
    id "$APP_USER" >/dev/null 2>&1 || return 0
    app_uid="$(id -u "$APP_USER")"
    set +e
    timeout 5 pgrep -u "$app_uid" >/dev/null 2>&1
    status=$?
    set -e
    case "$status" in
        1) ;;
        0) die 'another service-UID process remains after unit stop' ;;
        *) die 'service-UID process proof was ambiguous' ;;
    esac
}

ensure_state_quarantine_root() {
    local directory

    for directory in "$STATE_QUARANTINE_BASE" "$STATE_QUARANTINE_ROOT"; do
        if [[ -e "$directory" || -L "$directory" ]]; then
            [[ -d "$directory" && ! -L "$directory" && "$(stat -c %u:%g:%a "$directory")" == 0:0:700 ]] ||
                die 'state quarantine path is not root:root 0700 nofollow'
        else
            install -d -o root -g root -m 0700 "$directory"
        fi
        tx_assert_existing_directory_components "$directory" || die 'state quarantine path has an unsafe component'
    done
}

isolate_canonical_state() {
    local label="$1"
    local validate_isolated="${2:-1}"

    ensure_state_quarantine_root
    if find "$STATE_QUARANTINE_ROOT" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
        die 'state quarantine is not empty; operator review is required'
    fi
    [[ -d "$STATE" && ! -L "$STATE" ]] || die 'canonical state directory disappeared before quarantine'
    STATE_ISOLATION_DIR="$(mktemp -d "$STATE_QUARANTINE_ROOT/state.XXXXXXXX")"
    chmod 0700 "$STATE_ISOLATION_DIR"
    STATE_ISOLATED_PATH="$STATE_ISOLATION_DIR/$label"
    STATE_ISOLATED=1
    if ! mv -T -- "$STATE" "$STATE_ISOLATED_PATH"; then
        STATE_ISOLATED=0
        die 'atomic state quarantine rename failed'
    fi
    sync -f /var/lib
    sync -f "$STATE_ISOLATION_DIR"
    [[ ! -e "$STATE" && ! -L "$STATE" ]] || die 'canonical state path was recreated during quarantine'
    if [[ "$validate_isolated" == 1 ]]; then
        assert_managed_state_tree "$STATE_ISOLATED_PATH"
        assert_existing_state_metadata "$STATE_ISOLATED_PATH"
        assert_no_open_managed_tree "$STATE_ISOLATED_PATH" state
    fi
}

restore_isolated_state_before_snapshot() {
    local expected_uid
    local expected_gid
    local entry
    local name
    local process_status

    [[ "$STATE_ISOLATED" == 1 ]] || return 0
    [[ -d "$STATE_ISOLATED_PATH" && ! -L "$STATE_ISOLATED_PATH" ]] || return 1
    [[ ! -e "$STATE" && ! -L "$STATE" ]] || return 1
    if [[ "$APP_USER" == root ]]; then
        expected_uid=0
        expected_gid=0
    else
        id "$APP_USER" >/dev/null 2>&1 || return 1
        expected_uid="$(id -u "$APP_USER")"
        expected_gid="$(id -g "$APP_USER")"
    fi
    chown root:root "$STATE_ISOLATED_PATH" || return 1
    chmod 0700 "$STATE_ISOLATED_PATH" || return 1
    if [[ "$APP_USER" != root ]]; then
        timeout 5 pgrep -u "$expected_uid" >/dev/null 2>&1
        process_status=$?
        [[ "$process_status" == 1 ]] || return 1
    fi
    timeout 5 /bin/bash "$TX_HELPER" --assert-no-open-tree "$STATE_ISOLATED_PATH" >/dev/null 2>&1 || return 1
    shopt -s dotglob nullglob
    for entry in "$STATE_ISOLATED_PATH"/*; do
        name="$(basename "$entry")"
        case "$name" in
            "$DB_BASENAME"|"$DB_BASENAME-wal"|"$DB_BASENAME-shm"|"$DB_BASENAME-journal"|history.json) ;;
            *) return 1 ;;
        esac
        [[ -f "$entry" && ! -L "$entry" ]] || return 1
        chown "$expected_uid:$expected_gid" "$entry" || return 1
        chmod 0600 "$entry" || return 1
    done
    shopt -u dotglob nullglob
    chown "$expected_uid:$expected_gid" "$STATE_ISOLATED_PATH" || return 1
    chmod 0700 "$STATE_ISOLATED_PATH" || return 1
    mv -T -- "$STATE_ISOLATED_PATH" "$STATE" || return 1
    sync -f /var/lib || return 1
    rmdir "$STATE_ISOLATION_DIR" || return 1
    STATE_ISOLATED=0
    STATE_ISOLATED_PATH=""
    STATE_ISOLATION_DIR=""
}

return_root_controlled_state() {
    local name

    [[ "$ROLLBACK_ARMED" == 1 && "$STATE_ISOLATED" == 1 ]] || die 'state root-control transition is not rollback-protected'
    chown root:root "$STATE_ISOLATED_PATH"
    chmod 0700 "$STATE_ISOLATED_PATH"
    assert_no_service_uid_processes
    assert_no_open_managed_tree "$STATE_ISOLATED_PATH" state
    assert_managed_state_tree "$STATE_ISOLATED_PATH"
    for name in "${STATE_FILES[@]}"; do
        if [[ -e "$STATE_ISOLATED_PATH/$name" || -L "$STATE_ISOLATED_PATH/$name" ]]; then
            [[ -f "$STATE_ISOLATED_PATH/$name" && ! -L "$STATE_ISOLATED_PATH/$name" ]] || die 'state entry changed during quarantine'
            chown root:root "$STATE_ISOLATED_PATH/$name"
            chmod 0600 "$STATE_ISOLATED_PATH/$name"
        fi
    done
    assert_managed_state_tree "$STATE_ISOLATED_PATH"
    [[ "$(stat -c %u:%g:%a "$STATE_ISOLATED_PATH")" == 0:0:700 ]] || die 'quarantined state root-control proof failed'
    [[ ! -e "$STATE" && ! -L "$STATE" ]] || die 'canonical state path was recreated before return'
    mv -T -- "$STATE_ISOLATED_PATH" "$STATE"
    sync -f /var/lib
    rmdir "$STATE_ISOLATION_DIR"
    STATE_ISOLATED=0
    STATE_ISOLATED_PATH=""
    STATE_ISOLATION_DIR=""
    STATE_ROOT_CONTROLLED=1
    assert_managed_state_tree "$STATE"
    [[ "$(stat -c %u:%g:%a "$STATE")" == 0:0:700 ]] || die 'canonical state is not root-controlled after quarantine'
}

prepare_root_controlled_state_for_rollback() {
    if [[ "$STATE_ISOLATED" != 1 && ( -e "$STATE" || -L "$STATE" ) ]]; then
        isolate_canonical_state rollback-current 0
    fi
    [[ ! -e "$STATE" && ! -L "$STATE" ]] || return 1
    install -d -o root -g root -m 0700 "$STATE" || return 1
    tx_assert_existing_directory_components "$STATE" || return 1
    [[ "$(stat -c %u:%g:%a "$STATE")" == 0:0:700 ]] || return 1
    STATE_ROOT_CONTROLLED=1
}

cleanup_isolated_state() {
    [[ "$STATE_ISOLATED" == 1 ]] || return 0
    [[ -n "$STATE_ISOLATION_DIR" && "$STATE_ISOLATION_DIR" == "$STATE_QUARANTINE_ROOT"/state.* ]] || return 1
    rm -rf --one-file-system -- "$STATE_ISOLATION_DIR" || return 1
    sync -f "$STATE_QUARANTINE_ROOT" || return 1
    STATE_ISOLATED=0
    STATE_ISOLATED_PATH=""
    STATE_ISOLATION_DIR=""
}

rollback_stop_guard() {
    local service_is_active=-1
    local process_status
    local app_uid

    # The unit may legitimately be absent on first-install rollback. The
    # bounded state and process proofs below are authoritative, not stop's
    # unit-not-found exit status.
    timeout 5 systemctl stop mini-ops >/dev/null 2>&1 || true
    deploy_systemd_probe_active mini-ops service_is_active || return 1
    [[ "$service_is_active" == 0 ]] || return 1
    timeout 5 pgrep -x mini-ops >/dev/null 2>&1
    process_status=$?
    [[ "$process_status" == 1 ]] || return 1
    if [[ "$APP_USER" != root ]] && id "$APP_USER" >/dev/null 2>&1; then
        app_uid="$(id -u "$APP_USER")"
        timeout 5 pgrep -u "$app_uid" >/dev/null 2>&1
        process_status=$?
        [[ "$process_status" == 1 ]] || return 1
    fi
    return 0
}

verify_pre_snapshot_service_restore() {
    local restored_host
    local restored_port
    local restored_token
    local restored_database_url
    local restored_database_path
    local restored_database_name
    local api_ready=0
    local attempt

    timeout 5 systemctl start mini-ops >/dev/null 2>&1 || return 1
    timeout 5 systemctl is-active --quiet mini-ops || return 1
    restored_host="$(awk -F= '$1 == "APP_HOST" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
    restored_port="$(awk -F= '$1 == "APP_PORT" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
    restored_token="$(awk -F= '$1 == "AUTH_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
    restored_database_url="$(awk -F= '$1 == "DATABASE_URL" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
    [[ -n "$restored_port" ]] || restored_port=3000
    case "$restored_host" in ''|127.0.0.1|localhost|::1) ;; *) return 1 ;; esac
    [[ "$restored_port" =~ ^[1-9][0-9]{0,4}$ ]] || return 1
    (( 10#$restored_port <= 65535 )) || return 1
    [[ "$restored_token" =~ ^[A-Za-z0-9._~+/=-]{32,}$ ]] || return 1
    ss -H -ltn | awk -v wanted="$restored_port" '
        {
            local=$4
            sub(/^.*:/, "", local)
            if (local != wanted) next
            if ($4 ~ /^127[.]/ || $4 ~ /^\[::1\]:/) loopback=1
            else public=1
        }
        END {exit !(loopback && !public)}
    ' || return 1
    for ((attempt = 0; attempt < 10; attempt++)); do
        if printf 'header = "Authorization: Bearer %s"\n' "$restored_token" | \
            curl --disable --config - --noproxy '*' --fail --silent --show-error --max-time 3 \
            "http://127.0.0.1:${restored_port}/api/version" >/dev/null 2>&1; then
            api_ready=1
            break
        fi
        sleep 1
    done
    [[ "$api_ready" == 1 ]] || return 1
    read -r _ restored_database_name < <(tx_resolve_managed_database_url "$restored_database_url") || return 1
    case "$restored_database_url" in
        ''|sqlite:mini-ops.db|sqlite://mini-ops.db) restored_database_path="$TARGET/mini-ops.db" ;;
        sqlite:///var/lib/mini-ops/*) restored_database_path="$STATE/$restored_database_name" ;;
        *) return 1 ;;
    esac
    [[ -f "$restored_database_path" && ! -L "$restored_database_path" ]] || return 1
    timeout --signal=TERM --kill-after=5s 30s python3 - "$restored_database_path" <<'PRE_SNAPSHOT_ROLLBACK_PY'
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
try:
    result = connection.execute("PRAGMA quick_check").fetchall()
finally:
    connection.close()
if result != [("ok",)]:
    raise SystemExit(1)
PRE_SNAPSHOT_ROLLBACK_PY
}

rollback_on_exit() {
    local status=$?
    trap - EXIT
    set +e
    if [[ "$status" == 0 || "$STOP_GUARD_ARMED" != 1 ]]; then
        exit "$status"
    fi
    if [[ "$ROLLBACK_ARMED" == 1 && -d "$SNAPSHOT" ]]; then
        if ! rollback_stop_guard; then
            printf 'REMOTE INSTALL: ROLLBACK DEGRADED; service/writer stop proof failed before state restore\n' >&2
            exit 70
        fi
        if ! prepare_root_controlled_state_for_rollback; then
            printf 'REMOTE INSTALL: ROLLBACK DEGRADED; state quarantine could not establish root control\n' >&2
            exit 70
        fi
        restore_file "$TARGET/mini-ops" binary
        restore_file "$TARGET/scripts/setup_ssh_alerts.sh" setup-ssh-alerts
        restore_file "$TARGET/scripts/ssh-alert.sh" ssh-alert
        restore_file "$TARGET/scripts/filesystem_transaction.sh" filesystem-transaction
        restore_file "$UNIT" unit
        restore_file "$TARGET/.env" env
        for name in "${STATE_FILES[@]}"; do
            restore_file "$STATE/$name" "state-$name"
        done
        for name in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json; do
            restore_file "$TARGET/$name" "legacy-$name"
        done
        if [[ "$SETUP_NGINX" == 1 ]]; then
            restore_file "$NGINX_SITE" nginx-site
            if [[ -f "$SNAPSHOT/nginx-enabled-target" ]]; then
                atomic_symlink "$(< "$SNAPSHOT/nginx-enabled-target")" "$NGINX_ENABLED"
            else
                rm -f -- "$NGINX_ENABLED"
            fi
            if [[ -f "$SNAPSHOT/nginx-default-target" ]]; then
                atomic_symlink "$(< "$SNAPSHOT/nginx-default-target")" "$NGINX_DEFAULT"
            else
                rm -f -- "$NGINX_DEFAULT"
            fi
            if [[ "$NGINX_WAS_ENABLED" == 1 ]]; then
                systemctl enable nginx >/dev/null 2>&1
            else
                systemctl disable nginx >/dev/null 2>&1
            fi
            if [[ "$NGINX_WAS_ACTIVE" == 1 ]]; then
                nginx -t >/dev/null 2>&1 && systemctl restart nginx >/dev/null 2>&1
            else
                systemctl stop nginx >/dev/null 2>&1
            fi
        fi
        if [[ "$RUNTIME_WAS_DIR" == 0 ]]; then
            rm -rf -- "$RUNTIME"
        else
            restore_directory_metadata "$RUNTIME" runtime
        fi
        if [[ "$SCRIPTS_WAS_DIR" == 0 ]]; then
            rmdir "$TARGET/scripts" >/dev/null 2>&1 || true
        else
            restore_directory_metadata "$TARGET/scripts" scripts
        fi
        if [[ "$TARGET_WAS_DIR" == 0 ]]; then
            rmdir "$TARGET" >/dev/null 2>&1 || true
        else
            restore_directory_metadata "$TARGET" target
        fi
        if [[ "$DOCKER_MEMBERSHIP_ADDED" == 1 && "$APP_USER_CREATED" == 0 ]]; then
            gpasswd -d "$APP_USER" docker >/dev/null 2>&1 || true
        fi
        if [[ "$APP_USER_CREATED" == 1 ]]; then
            userdel "$APP_USER" >/dev/null 2>&1 || true
        fi
        if [[ "$APP_GROUP_CREATED" == 1 ]]; then
            groupdel "$APP_USER" >/dev/null 2>&1 || true
        fi
        rollback_verification_failed=0
        for file_and_key in \
            "$TARGET/mini-ops|binary" \
            "$TARGET/scripts/setup_ssh_alerts.sh|setup-ssh-alerts" \
            "$TARGET/scripts/ssh-alert.sh|ssh-alert" \
            "$TARGET/scripts/filesystem_transaction.sh|filesystem-transaction" \
            "$UNIT|unit" \
            "$TARGET/.env|env"; do
            restore_path="${file_and_key%%|*}"
            restore_key="${file_and_key##*|}"
            verify_restored_file "$restore_path" "$restore_key" || rollback_verification_failed=1
        done
        for name in "${STATE_FILES[@]}"; do
            verify_restored_file "$STATE/$name" "state-$name" || rollback_verification_failed=1
        done
        for name in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json; do
            verify_restored_file "$TARGET/$name" "legacy-$name" || rollback_verification_failed=1
        done
        if [[ "$TARGET_WAS_DIR" == 1 ]]; then
            verify_restored_directory "$TARGET" target || rollback_verification_failed=1
        else
            [[ ! -e "$TARGET" && ! -L "$TARGET" ]] || rollback_verification_failed=1
        fi
        if [[ "$SCRIPTS_WAS_DIR" == 1 ]]; then
            verify_restored_directory "$TARGET/scripts" scripts || rollback_verification_failed=1
        else
            [[ ! -e "$TARGET/scripts" && ! -L "$TARGET/scripts" ]] || rollback_verification_failed=1
        fi
        if [[ "$RUNTIME_WAS_DIR" == 1 ]]; then
            verify_restored_directory "$RUNTIME" runtime || rollback_verification_failed=1
        else
            [[ ! -e "$RUNTIME" && ! -L "$RUNTIME" ]] || rollback_verification_failed=1
        fi
        if [[ "$SETUP_NGINX" == 1 ]]; then
            verify_restored_file "$NGINX_SITE" nginx-site || rollback_verification_failed=1
            if [[ -f "$SNAPSHOT/nginx-enabled-target" ]]; then
                [[ -L "$NGINX_ENABLED" && "$(readlink "$NGINX_ENABLED")" == "$(< "$SNAPSHOT/nginx-enabled-target")" ]] || rollback_verification_failed=1
            else
                [[ ! -e "$NGINX_ENABLED" && ! -L "$NGINX_ENABLED" ]] || rollback_verification_failed=1
            fi
            if [[ -f "$SNAPSHOT/nginx-default-target" ]]; then
                [[ -L "$NGINX_DEFAULT" && "$(readlink "$NGINX_DEFAULT")" == "$(< "$SNAPSHOT/nginx-default-target")" ]] || rollback_verification_failed=1
            else
                [[ ! -e "$NGINX_DEFAULT" && ! -L "$NGINX_DEFAULT" ]] || rollback_verification_failed=1
            fi
            restored_nginx_active=-1
            if ! deploy_systemd_probe_active nginx restored_nginx_active ||
                [[ "$restored_nginx_active" != "$NGINX_WAS_ACTIVE" ]]; then
                rollback_verification_failed=1
            fi
            restored_nginx_enabled=-1
            if ! deploy_systemd_probe_enabled nginx restored_nginx_enabled ||
                [[ "$restored_nginx_enabled" != "$NGINX_WAS_ENABLED" ]]; then
                rollback_verification_failed=1
            fi
        fi
        # STATE remains root-controlled through every privileged restore and
        # byte/metadata proof. Its exact original directory metadata is the
        # final filesystem handoff before an optional old-service restart.
        if ! rollback_stop_guard; then
            printf 'REMOTE INSTALL: ROLLBACK DEGRADED; service/writer state changed before metadata handoff\n' >&2
            exit 70
        fi
        if [[ "$STATE_WAS_DIR" == 1 ]]; then
            restore_directory_metadata "$STATE" state || rollback_verification_failed=1
            verify_restored_directory "$STATE" state || rollback_verification_failed=1
        else
            rmdir "$STATE" >/dev/null 2>&1 || rollback_verification_failed=1
            [[ ! -e "$STATE" && ! -L "$STATE" ]] || rollback_verification_failed=1
        fi
        systemctl daemon-reload >/dev/null 2>&1
        if [[ "$SERVICE_WAS_ENABLED" == 1 ]]; then
            systemctl enable mini-ops >/dev/null 2>&1
        else
            systemctl disable mini-ops >/dev/null 2>&1
        fi
        restored_service_enabled=-1
        if ! deploy_systemd_probe_enabled mini-ops restored_service_enabled ||
            [[ "$restored_service_enabled" != "$SERVICE_WAS_ENABLED" ]]; then
            rollback_verification_failed=1
        fi
        if [[ "$SERVICE_WAS_ACTIVE" == 1 ]]; then
            systemctl start mini-ops >/dev/null 2>&1
            restored_service_state=-1
            if ! deploy_systemd_probe_active mini-ops restored_service_state ||
                [[ "$restored_service_state" != 1 ]]; then
                rollback_verification_failed=1
            fi

            restored_host="$(awk -F= '$1 == "APP_HOST" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
            restored_port="$(awk -F= '$1 == "APP_PORT" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
            restored_token="$(awk -F= '$1 == "AUTH_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
            restored_database_url="$(awk -F= '$1 == "DATABASE_URL" {sub(/^[^=]*=/, ""); print; exit}' "$TARGET/.env")"
            [[ -n "$restored_port" ]] || restored_port=3000
            case "$restored_host" in ''|127.0.0.1|localhost|::1) ;; *) rollback_verification_failed=1 ;; esac
            if [[ "$restored_port" =~ ^[0-9]+$ && "$restored_token" =~ ^[A-Za-z0-9._~+/=-]{32,}$ ]]; then
                rollback_api_ready=0
                for ((rollback_attempt = 0; rollback_attempt < 10; rollback_attempt++)); do
                    if printf 'header = "Authorization: Bearer %s"\n' "$restored_token" | \
                        curl --disable --config - --noproxy '*' --fail --silent --show-error --max-time 3 \
                        "http://127.0.0.1:${restored_port}/api/version" >/dev/null 2>&1; then
                        rollback_api_ready=1
                        break
                    fi
                    sleep 1
                done
                [[ "$rollback_api_ready" == 1 ]] || rollback_verification_failed=1
            else
                rollback_verification_failed=1
            fi
            case "$restored_database_url" in
                ''|sqlite:mini-ops.db|sqlite://mini-ops.db) restored_database_path="$TARGET/mini-ops.db" ;;
                sqlite:///var/lib/mini-ops/*) restored_database_path="${restored_database_url#sqlite://}" ;;
                *) restored_database_path='' ;;
            esac
            if [[ -n "$restored_database_path" && -f "$restored_database_path" && ! -L "$restored_database_path" ]]; then
                timeout --signal=TERM --kill-after=5s 30s python3 - "$restored_database_path" <<'ROLLBACK_PY' || rollback_verification_failed=1
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
try:
    result = connection.execute("PRAGMA quick_check").fetchall()
finally:
    connection.close()
if result != [("ok",)]:
    raise SystemExit(1)
ROLLBACK_PY
            else
                rollback_verification_failed=1
            fi
        else
            restored_service_state=-1
            if ! deploy_systemd_probe_active mini-ops restored_service_state ||
                [[ "$restored_service_state" != 0 ]]; then
                rollback_verification_failed=1
            fi
        fi
        if [[ "$rollback_verification_failed" == 1 ]]; then
            printf 'REMOTE INSTALL: ROLLBACK DEGRADED; exact file/service/API/DB proof failed\n' >&2
            exit 70
        fi
        cleanup_isolated_state || {
            printf 'REMOTE INSTALL: ROLLBACK DEGRADED; isolated failed state cleanup failed\n' >&2
            exit 70
        }
        printf 'REMOTE INSTALL: rollback verified from root-only snapshot\n' >&2
    elif [[ "$STATE_ISOLATED" == 1 ]]; then
        if ! restore_isolated_state_before_snapshot; then
            printf 'REMOTE INSTALL: failed to return pre-snapshot state quarantine\n' >&2
            exit 70
        fi
        if [[ "$SERVICE_WAS_ACTIVE" == 1 ]]; then
            if ! verify_pre_snapshot_service_restore; then
                printf 'REMOTE INSTALL: pre-snapshot service rollback DEGRADED\n' >&2
                exit 70
            fi
        fi
    elif [[ "$SERVICE_WAS_ACTIVE" == 1 ]]; then
        if ! verify_pre_snapshot_service_restore; then
            printf 'REMOTE INSTALL: pre-snapshot service rollback DEGRADED\n' >&2
            exit 70
        fi
    fi
    exit "$status"
}

assert_staged "$STAGE/mini-ops"
assert_staged "$STAGE/mini-ops.service"
assert_staged "$STAGE/filesystem_transaction.sh"
assert_staged "$STAGE/setup_ssh_alerts.sh"
assert_staged "$STAGE/ssh-alert.sh"
[[ "$WRITE_ENV" == 0 ]] || assert_staged "$STAGE/mini-ops.env"
[[ "$SETUP_NGINX" == 0 ]] || assert_staged "$STAGE/mini-ops.nginx"
[[ ! -L "$STAGE" && "$(stat -c %a "$STAGE")" == 700 ]] || die 'remote upload directory is not private'
[[ "$(stat -c %u "$STAGE")" == "$UPLOAD_UID" ]] || die 'remote upload directory owner changed after creation'

for component in /opt "$TARGET" /var /var/lib "$STATE" "$STATE_QUARANTINE_BASE" "$STATE_QUARANTINE_ROOT" /run "$RUNTIME" /var/backups "$BACKUPS" /etc /etc/systemd /etc/systemd/system "$UNIT"; do
    [[ ! -L "$component" ]] || die 'destination path contains a symlink component'
done

ENV_SOURCE="$TARGET/.env"
if [[ "$WRITE_ENV" == 1 ]]; then
    ENV_SOURCE="$STAGE/mini-ops.env"
fi
assert_regular "$ENV_SOURCE"
env_size="$(stat -c %s "$ENV_SOURCE")"
[[ "$env_size" =~ ^[0-9]+$ && "$env_size" -le 1048576 ]] || die 'candidate .env exceeds the 1 MiB bootstrap bound'
auth_count="$(awk -F= '$1 == "AUTH_TOKEN" {count++} END {print count+0}' "$ENV_SOURCE")"
[[ "$auth_count" == 1 ]] || die 'candidate AUTH_TOKEN must occur exactly once'
auth_token="$(awk -F= '$1 == "AUTH_TOKEN" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_SOURCE")"
(( ${#auth_token} >= 32 )) || die 'candidate AUTH_TOKEN is absent or shorter than 32 characters'
[[ "$auth_token" != *[$'\001'-$'\037'$'\177']* ]] || die 'candidate AUTH_TOKEN contains control characters'
[[ "$auth_token" =~ ^[A-Za-z0-9._~+/=-]{32,}$ ]] || die 'candidate AUTH_TOKEN uses characters outside the managed dotenv-safe alphabet'
lowered_token="$(printf '%s' "$auth_token" | tr '[:upper:]' '[:lower:]')"
case "$lowered_token" in
    your_secret_token_here|your_secret_token|your_strong_token|change-me|change-me-strong-random-token|your-random-secure-string-at-least-32-chars|your_auth_token|auth_token|token)
        die 'candidate AUTH_TOKEN is a known placeholder'
        ;;
esac
database_count="$(awk -F= '$1 == "DATABASE_URL" {count++} END {print count+0}' "$ENV_SOURCE")"
(( database_count <= 1 )) || die 'candidate DATABASE_URL is duplicated'
database_url="$(awk -F= '$1 == "DATABASE_URL" {sub(/^[^=]*=/, ""); print; exit}' "$ENV_SOURCE")"
read -r DATABASE_URL_FINAL DB_BASENAME < <(tx_resolve_managed_database_url "$database_url") ||
    die 'candidate DATABASE_URL is outside managed private state, reserved, or too complex'
STATE_FILES=("$DB_BASENAME" "$DB_BASENAME-wal" "$DB_BASENAME-shm" "$DB_BASENAME-journal" history.json)
for name in "${STATE_FILES[@]}"; do
    if [[ -e "$STATE/$name" || -L "$STATE/$name" ]]; then
        [[ -f "$STATE/$name" && ! -L "$STATE/$name" ]] || die 'managed state source is not a regular nofollow file'
    fi
done
for sidecar in "$DB_BASENAME-wal" "$DB_BASENAME-shm" "$DB_BASENAME-journal"; do
    if [[ -e "$STATE/$sidecar" || -L "$STATE/$sidecar" ]]; then
        [[ -f "$STATE/$DB_BASENAME" && ! -L "$STATE/$DB_BASENAME" ]] || die 'managed SQLite sidecar exists without its main database'
    fi
done
if [[ -d "$STATE" ]]; then
    assert_managed_state_tree "$STATE"
    assert_existing_state_metadata "$STATE"
fi
if [[ "$DB_BASENAME" != mini-ops.db ]]; then
    for legacy in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json mini-ops-internal.token internal.token; do
        [[ ! -e "$TARGET/$legacy" ]] || die 'custom managed DATABASE_URL conflicts with legacy /opt state; operator choice is required'
    done
fi

for destination in "$TARGET" "$STATE" "$RUNTIME" "$BACKUPS" "$UNIT"; do
    [[ ! -L "$destination" ]] || die 'destination symlink substitution detected'
done
for directory in "$TARGET" "$STATE" "$RUNTIME" "$BACKUPS"; do
    if [[ -e "$directory" || -L "$directory" ]]; then
        [[ -d "$directory" && ! -L "$directory" ]] || die 'destination directory path is not a nofollow directory'
    fi
done
if [[ -d "$TARGET" ]] && find "$TARGET" -xdev -type l -print -quit | grep -q .; then
    die 'destination code tree contains a symlink'
fi
if [[ -d "$TARGET" ]]; then
    shopt -s dotglob nullglob
    for entry in "$TARGET"/*; do
        case "$(basename "$entry")" in
            scripts)
                [[ -d "$entry" && ! -L "$entry" ]] || die 'destination scripts entry is not a nofollow directory'
                ;;
            mini-ops|.env|mini-ops.db|mini-ops.db-wal|mini-ops.db-shm|mini-ops.db-journal|history.json|mini-ops-internal.token|internal.token)
                [[ -f "$entry" && ! -L "$entry" ]] || die 'destination code/state entry is not a regular nofollow file'
                ;;
            *) die 'destination code tree contains an unexpected entry' ;;
        esac
    done
    if [[ -d "$TARGET/scripts" ]]; then
        for entry in "$TARGET/scripts"/*; do
            case "$(basename "$entry")" in
                setup_ssh_alerts.sh|ssh-alert.sh|filesystem_transaction.sh)
                    [[ -f "$entry" && ! -L "$entry" ]] || die 'destination script is not a regular nofollow file'
                    ;;
                *) die 'destination scripts tree contains an unexpected entry' ;;
            esac
        done
    fi
    shopt -u dotglob nullglob
fi
if [[ "$DB_BASENAME" == mini-ops.db ]]; then
    legacy_state_present=0
    managed_state_present=0
    for name in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json; do
        [[ ! -e "$TARGET/$name" && ! -L "$TARGET/$name" ]] || legacy_state_present=1
        [[ ! -e "$STATE/$name" && ! -L "$STATE/$name" ]] || managed_state_present=1
    done
    [[ "$legacy_state_present" == 0 || "$managed_state_present" == 0 ]] || die 'legacy/managed state-set conflict detected'
fi
if [[ "$SETUP_NGINX" == 1 ]]; then
    if [[ -e "$NGINX_SITE" || -L "$NGINX_SITE" ]]; then
        [[ -f "$NGINX_SITE" && ! -L "$NGINX_SITE" ]] || die 'Nginx destination is not a regular nofollow file'
    fi
    if [[ -e "$NGINX_ENABLED" || -L "$NGINX_ENABLED" ]]; then
        [[ -L "$NGINX_ENABLED" ]] || die 'enabled Nginx site path is not a symlink'
        nginx_target="$(readlink "$NGINX_ENABLED")"
        case "$nginx_target" in
            /etc/nginx/sites-available/mini-ops|../sites-available/mini-ops) ;;
            *) die 'enabled Nginx site points to an unexpected target' ;;
        esac
    fi
    if [[ -e "$NGINX_DEFAULT" || -L "$NGINX_DEFAULT" ]]; then
        [[ -L "$NGINX_DEFAULT" ]] || die 'enabled Nginx default site is not a symlink'
        case "$(readlink "$NGINX_DEFAULT")" in
            /etc/nginx/sites-available/default|../sites-available/default) ;;
            *) die 'enabled Nginx default site points to an unexpected target' ;;
        esac
        NGINX_DEFAULT_WAS_LINK=1
    fi
fi

[[ -d "$TARGET" ]] && TARGET_WAS_DIR=1
[[ -d "$TARGET/scripts" ]] && SCRIPTS_WAS_DIR=1
[[ -d "$STATE" ]] && STATE_WAS_DIR=1
[[ -d "$RUNTIME" ]] && RUNTIME_WAS_DIR=1
if [[ -e "$BACKUPS" || -L "$BACKUPS" ]]; then
    [[ -d "$BACKUPS" && ! -L "$BACKUPS" ]] || die 'backup root is not a nofollow directory'
    [[ "$(stat -c %u:%g:%a "$BACKUPS")" == 0:0:700 ]] || die 'existing backup root must already be root:root 0700'
else
    install -d -o root -g root -m 0700 "$BACKUPS"
fi

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT="$(mktemp -d "$BACKUPS/state-pre-v1-${timestamp}.XXXXXXXX")"
chown root:root "$SNAPSHOT"
chmod 0700 "$SNAPSHOT"
install -d -o root -g root -m 0700 "$SNAPSHOT/files" "$SNAPSHOT/absent" "$SNAPSHOT/work"
probe_active_state mini-ops SERVICE_WAS_ACTIVE
probe_enabled_state mini-ops SERVICE_WAS_ENABLED
printf '%s\n' "$SERVICE_WAS_ACTIVE" > "$SNAPSHOT/service-was-active"
printf '%s\n' "$SERVICE_WAS_ENABLED" > "$SNAPSHOT/service-was-enabled"
snapshot_file "$TARGET/mini-ops" binary
if [[ -f "$TARGET/mini-ops" ]]; then
    sha256sum "$TARGET/mini-ops" > "$SNAPSHOT/binary.sha256"
fi
snapshot_file "$TARGET/scripts/setup_ssh_alerts.sh" setup-ssh-alerts
snapshot_file "$TARGET/scripts/ssh-alert.sh" ssh-alert
snapshot_file "$TARGET/scripts/filesystem_transaction.sh" filesystem-transaction
snapshot_file "$UNIT" unit
snapshot_file "$TARGET/.env" env
snapshot_directory_metadata "$TARGET" target
snapshot_directory_metadata "$TARGET/scripts" scripts
snapshot_directory_metadata "$RUNTIME" runtime
if [[ "$SETUP_NGINX" == 1 ]]; then
    probe_active_state nginx NGINX_WAS_ACTIVE
    probe_enabled_state nginx NGINX_WAS_ENABLED
    snapshot_file "$NGINX_SITE" nginx-site
    if [[ -L "$NGINX_ENABLED" ]]; then
        readlink "$NGINX_ENABLED" > "$SNAPSHOT/nginx-enabled-target"
    fi
    if [[ "$NGINX_DEFAULT_WAS_LINK" == 1 ]]; then
        readlink "$NGINX_DEFAULT" > "$SNAPSHOT/nginx-default-target"
    fi
fi
STOP_GUARD_ARMED=1
trap rollback_on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ "$SERVICE_WAS_ACTIVE" == 1 ]]; then
    systemctl stop mini-ops
fi
probe_active_state mini-ops SERVICE_IS_STILL_ACTIVE
[[ "$SERVICE_IS_STILL_ACTIVE" == 0 ]] || die 'service remained active after stop; refusing state snapshot'
set +e
timeout 5 pgrep -x mini-ops >/dev/null 2>&1
process_status=$?
set -e
case "$process_status" in
    1) ;;
    0) die 'mini-ops process remains outside the stopped unit' ;;
    *) die 'post-stop process proof was ambiguous' ;;
esac
assert_no_service_uid_processes
set +e
timeout 5 /bin/bash "$TX_HELPER" --assert-no-open-files \
    "$STATE/$DB_BASENAME" \
    "$STATE/$DB_BASENAME-wal" \
    "$STATE/$DB_BASENAME-shm" \
    "$STATE/$DB_BASENAME-journal" \
    "$STATE/history.json" \
    "$TARGET/mini-ops.db" \
    "$TARGET/mini-ops.db-wal" \
    "$TARGET/mini-ops.db-shm" \
    "$TARGET/mini-ops.db-journal" \
    "$TARGET/history.json"
writer_status=$?
set -e
case "$writer_status" in
    0) ;;
    42) die 'database writer remains after service stop' ;;
    *) die 'bounded database writer proof was ambiguous' ;;
esac
if [[ "$STATE_WAS_DIR" == 1 ]]; then
    assert_no_open_managed_tree "$STATE" state
    isolate_canonical_state original
    STATE_SNAPSHOT_SOURCE="$STATE_ISOLATED_PATH"
    snapshot_directory_metadata "$STATE_SNAPSHOT_SOURCE" state
fi
assert_no_open_managed_tree "$TARGET" legacy-source
for name in "${STATE_FILES[@]}"; do
    snapshot_file "$STATE_SNAPSHOT_SOURCE/$name" "state-$name"
done
for name in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json; do
    snapshot_file "$TARGET/$name" "legacy-$name"
done
tx_sync_snapshot "$SNAPSHOT" || die 'durable snapshot sync failed'
ROLLBACK_ARMED=1
if [[ "$STATE_WAS_DIR" == 1 ]]; then
    return_root_controlled_state
else
    [[ ! -e "$STATE" && ! -L "$STATE" ]] || die 'new canonical state path was substituted'
    install -d -o root -g root -m 0700 "$STATE"
    STATE_ROOT_CONTROLLED=1
    assert_managed_state_tree "$STATE"
    [[ "$(stat -c %u:%g:%a "$STATE")" == 0:0:700 ]] || die 'new canonical state is not root-controlled'
fi

if [[ "$APP_USER" != root ]] && ! id "$APP_USER" >/dev/null 2>&1; then
    if getent group "$APP_USER" >/dev/null 2>&1; then
        useradd --system --gid "$APP_USER" --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
    else
        useradd --system --user-group --home-dir "$STATE" --no-create-home --shell /usr/sbin/nologin "$APP_USER"
        APP_GROUP_CREATED=1
    fi
    APP_USER_CREATED=1
fi
[[ "$(id -gn "$APP_USER")" == "$APP_USER" || "$APP_USER" == root ]] || die 'service account primary group must match DEPLOY_APP_USER'
APP_UID="$(id -u "$APP_USER")"
APP_GID="$(id -g "$APP_USER")"
if [[ "$DOCKER_INTEGRATION" == 1 && "$APP_USER" != root ]]; then
    getent group docker >/dev/null 2>&1 || die 'docker group disappeared after preflight'
    if id -nG "$APP_USER" | tr ' ' '\n' | grep -qx docker; then
        APP_HAD_DOCKER=1
    else
        usermod -aG docker "$APP_USER"
        DOCKER_MEMBERSHIP_ADDED=1
    fi
fi
install -d -o root -g root -m 0755 "$TARGET" "$TARGET/scripts"
install -d -o root -g root -m 0700 "$STATE"
install -d -o "$APP_USER" -g "$APP_USER" -m 0700 "$RUNTIME"

awk '!/^(APP_HOST|APP_PORT|DATABASE_URL|MINI_OPS_INTERNAL_TOKEN_FILE)=/' "$ENV_SOURCE" > "$SNAPSHOT/work/env.candidate"
{
    printf 'APP_HOST=127.0.0.1\n'
    printf 'APP_PORT=%s\n' "$APP_PORT"
    printf 'DATABASE_URL=%s\n' "$DATABASE_URL_FINAL"
    printf 'MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token\n'
} >> "$SNAPSHOT/work/env.candidate"
chmod 0600 "$SNAPSHOT/work/env.candidate"

if [[ "$DB_BASENAME" == mini-ops.db ]]; then
    for name in mini-ops.db mini-ops.db-wal mini-ops.db-shm mini-ops.db-journal history.json; do
        if [[ -f "$TARGET/$name" ]]; then
            temporary="$(mktemp "$STATE/.${name}.migrate.XXXXXXXX")"
            install -o root -g root -m 0600 "$TARGET/$name" "$temporary"
            sync -f "$temporary"
            mv -fT "$temporary" "$STATE/$name"
            sync -f "$STATE"
        fi
    done
fi

atomic_install "$STAGE/mini-ops" "$TARGET/mini-ops" root root 0755
atomic_install "$STAGE/setup_ssh_alerts.sh" "$TARGET/scripts/setup_ssh_alerts.sh" root root 0755
atomic_install "$STAGE/ssh-alert.sh" "$TARGET/scripts/ssh-alert.sh" root root 0755
atomic_install "$STAGE/filesystem_transaction.sh" "$TARGET/scripts/filesystem_transaction.sh" root root 0755
atomic_install "$STAGE/mini-ops.service" "$UNIT" root root 0644
atomic_install "$SNAPSHOT/work/env.candidate" "$TARGET/.env" root root 0600

chown root:root "$TARGET" "$TARGET/scripts"
chmod 0755 "$TARGET" "$TARGET/scripts"

if [[ "$SETUP_NGINX" == 1 ]]; then
    atomic_install "$STAGE/mini-ops.nginx" "$NGINX_SITE" root root 0644
    atomic_symlink /etc/nginx/sites-available/mini-ops "$NGINX_ENABLED"
    rm -f -- "$NGINX_DEFAULT"
    nginx -t
    systemctl enable nginx
    systemctl restart nginx
    systemctl is-active --quiet nginx
    ss -H -ltn | awk -v wanted="$NGINX_PORT" -v expose="$EXPOSE_HTTP" \
        -v extra="$EXTRA_LISTEN_IP" '
        {
            local=$4
            sub(/^.*:/, "", local)
            if (local != wanted) next
            if ($4 == "127.0.0.1:" wanted) loopback=1
            else if (extra != "" && $4 == extra ":" wanted) exact=1
            else unexpected=1
        }
        END {
            if (expose == 1) exit !unexpected
            if (extra != "") exit !(loopback && exact && !unexpected)
            exit !(loopback && !unexpected)
        }
    '
fi

systemctl daemon-reload
systemctl enable mini-ops
[[ "$STATE_ROOT_CONTROLLED" == 1 && "$(stat -c %u:%g:%a "$STATE")" == 0:0:700 ]] || die 'state lost root control before service handoff'
assert_no_service_uid_processes
assert_managed_state_tree "$STATE"
for name in "${STATE_FILES[@]}"; do
    if [[ -e "$STATE/$name" || -L "$STATE/$name" ]]; then
        [[ -f "$STATE/$name" && ! -L "$STATE/$name" ]] || die 'managed state changed before service handoff'
        chown "$APP_USER:$APP_USER" "$STATE/$name"
        chmod 0600 "$STATE/$name"
    fi
done
# The directory handoff is deliberately the final privileged state operation;
# the next command starts the service, and rollback re-quarantines it first.
chown "$APP_USER:$APP_USER" "$STATE"
STATE_ROOT_CONTROLLED=0
systemctl restart mini-ops
systemctl is-active --quiet mini-ops

api_ready=0
for ((attempt = 0; attempt < 20; attempt++)); do
    if printf 'header = "Authorization: Bearer %s"\n' "$auth_token" | \
        curl --disable --config - --noproxy '*' --fail --silent --show-error --max-time 3 \
        "http://127.0.0.1:${APP_PORT}/api/version" >/dev/null; then
        api_ready=1
        break
    fi
    sleep 1
done
[[ "$api_ready" == 1 ]] || die 'loopback authenticated API health proof failed'

[[ "$(grep -Fxc "DATABASE_URL=$DATABASE_URL_FINAL" "$TARGET/.env")" == 1 ]] || die 'managed DATABASE_URL proof failed'
[[ "$(grep -Fxc 'MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token' "$TARGET/.env")" == 1 ]] || die 'managed token path proof failed'
[[ "$(grep -Fxc 'APP_HOST=127.0.0.1' "$TARGET/.env")" == 1 ]] || die 'loopback APP_HOST proof failed'
assert_managed_state_tree "$STATE"
DB_PATH="$STATE/$DB_BASENAME"
[[ -f "$DB_PATH" && ! -L "$DB_PATH" ]] || die 'managed database path proof failed'
timeout --signal=TERM --kill-after=5s 30s python3 - "$DB_PATH" <<'PY'
import sqlite3
import sys

connection = sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True, timeout=5)
try:
    result = connection.execute("PRAGMA quick_check").fetchall()
finally:
    connection.close()
if result != [("ok",)]:
    raise SystemExit("SQLite quick_check failed")
PY

assert_meta() {
    local path="$1"
    local uid="$2"
    local gid="$3"
    local mode="$4"
    [[ "$(stat -c %u:%g:%a "$path")" == "$uid:$gid:$mode" ]] || die 'ownership/mode proof failed'
}
assert_meta "$TARGET" 0 0 755
assert_meta "$TARGET/mini-ops" 0 0 755
assert_meta "$TARGET/scripts" 0 0 755
assert_meta "$TARGET/.env" 0 0 600
assert_meta "$UNIT" 0 0 644
assert_meta "$STATE" "$APP_UID" "$APP_GID" 700
assert_meta "$RUNTIME" "$APP_UID" "$APP_GID" 700
assert_meta "$BACKUPS" 0 0 700
for name in "${STATE_FILES[@]}"; do
    if [[ -e "$STATE/$name" ]]; then
        [[ -f "$STATE/$name" && ! -L "$STATE/$name" ]] || die 'managed state proof found a non-regular file'
        assert_meta "$STATE/$name" "$APP_UID" "$APP_GID" 600
    fi
done
[[ -f "$RUNTIME/internal.token" && ! -L "$RUNTIME/internal.token" ]] || die 'managed internal token path proof failed'
assert_meta "$RUNTIME/internal.token" "$APP_UID" "$APP_GID" 600

# Destructive legacy cleanup is deliberately last, after service, API, DB, and
# exact ownership/mode proof. The root-only snapshot remains the rollback point.
rm -f -- \
    "$TARGET/mini-ops.db" \
    "$TARGET/mini-ops.db-wal" \
    "$TARGET/mini-ops.db-shm" \
    "$TARGET/mini-ops.db-journal" \
    "$TARGET/history.json"

ROLLBACK_ARMED=0
STOP_GUARD_ARMED=0
trap - EXIT INT TERM
printf 'Managed core transaction committed; removing obsolete legacy token files.\n'
rm -f -- "$TARGET/mini-ops-internal.token" "$TARGET/internal.token"
[[ ! -e "$TARGET/mini-ops-internal.token" && ! -L "$TARGET/mini-ops-internal.token" ]]
[[ ! -e "$TARGET/internal.token" && ! -L "$TARGET/internal.token" ]]
printf 'Managed install verified; rollback snapshot retained at %s\n' "$SNAPSHOT"
REMOTE_INSTALL

printf '%s\n' 'Removing private remote upload staging before auxiliary mutations.'
"${REMOTE_SSH[@]}" "$REMOTE" "rm -rf -- '$REMOTE_STAGE' && test ! -e '$REMOTE_STAGE'"
REMOTE_STAGE=""
assert_remote_lock || deploy_error 'exclusive deploy lease was lost after the core transaction'

if [[ "$DEPLOY_ENABLE_SSH_ALERTS" == "1" ]]; then
    printf '%s\n' 'Core install is committed; applying separately requested SSH PAM mutation.'
    remote_root "$DEPLOY_APP_PORT" "$DEPLOY_APP_USER" "$REMOTE_LOCK_UNIT" <<'REMOTE_SSH_ALERTS'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077
APP_PORT="$1"
APP_USER="$2"
BOOTSTRAP_LOCK_OWNER="$3"
PAM_FILE=/etc/pam.d/sshd
HOOK=/usr/local/bin/ssh-alert.sh
CONFIG_DIR=/etc/mini-ops
CONFIG=/etc/mini-ops/ssh-alert.conf
BACKUPS=/var/backups/mini-ops
TX_HELPER=/opt/mini-ops/scripts/filesystem_transaction.sh
SNAPSHOT=""
CONFIG_DIR_EXISTED=0
ARMED=0

die() { printf 'SSH ALERT TRANSACTION: %s\n' "$*" >&2; exit 1; }
[[ -f "$TX_HELPER" && ! -L "$TX_HELPER" && "$(stat -c %u:%g:%a "$TX_HELPER")" == 0:0:755 ]] || die 'transaction helper is not a root-owned nofollow file'
# shellcheck source=scripts/lib/filesystem_transaction.sh
source "$TX_HELPER"
for directory in /opt/mini-ops/scripts /etc/pam.d /usr/local/bin /var/backups "$BACKUPS"; do
    tx_assert_existing_directory_components "$directory" || die 'SSH-alert path contains a symlink, missing, or non-directory component'
done
[[ -f /opt/mini-ops/scripts/setup_ssh_alerts.sh && ! -L /opt/mini-ops/scripts/setup_ssh_alerts.sh ]] || die 'setup script is not a regular nofollow file'
[[ -f /opt/mini-ops/scripts/ssh-alert.sh && ! -L /opt/mini-ops/scripts/ssh-alert.sh ]] || die 'hook source is not a regular nofollow file'
[[ -f "$PAM_FILE" && ! -L "$PAM_FILE" ]] || die 'PAM sshd policy is not a regular nofollow file'
for path in "$HOOK" "$CONFIG"; do
    if [[ -e "$path" || -L "$path" ]]; then
        [[ -f "$path" && ! -L "$path" ]] || die 'managed SSH-alert destination is not regular'
    fi
done
hook_count="$(grep -c 'ssh-alert[.]sh' "$PAM_FILE" || true)"
[[ "$hook_count" =~ ^[0-9]+$ ]] || die 'PAM hook count is ambiguous'
if (( hook_count > 1 )); then
    die 'PAM policy contains duplicate SSH-alert hooks'
fi
if (( hook_count == 1 )) && ! grep -Fxq 'session optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh' "$PAM_FILE"; then
    die 'PAM policy contains an unexpected SSH-alert hook'
fi
[[ -d "$BACKUPS" && ! -L "$BACKUPS" && "$(stat -c %u:%g:%a "$BACKUPS")" == 0:0:700 ]] || die 'backup root lost its private boundary'
if [[ -e "$CONFIG_DIR" || -L "$CONFIG_DIR" ]]; then
    tx_assert_existing_directory_components "$CONFIG_DIR" || die 'SSH-alert config directory is unsafe'
fi
[[ -d "$CONFIG_DIR" ]] && CONFIG_DIR_EXISTED=1

timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT="$(mktemp -d "$BACKUPS/ssh-alert-pre-${timestamp}.XXXXXXXX")"
chmod 0700 "$SNAPSHOT"
install -d -o root -g root -m 0700 "$SNAPSHOT/files" "$SNAPSHOT/absent"

snapshot_file() {
    local source="$1"
    local key="$2"
    if [[ -e "$source" || -L "$source" ]]; then
        [[ -f "$source" && ! -L "$source" ]] || die 'SSH-alert snapshot source is not regular'
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
    if [[ -f "$source" ]]; then
        temporary="$(mktemp "$(dirname "$destination")/.ssh-alert-restore.XXXXXXXX")"
        install -o "$(stat -c %u "$source")" -g "$(stat -c %g "$source")" -m "$(stat -c %a "$source")" "$source" "$temporary"
        sync -f "$temporary"
        mv -fT "$temporary" "$destination"
        sync -f "$(dirname "$destination")"
    elif [[ -f "$SNAPSHOT/absent/$key" ]]; then
        rm -f -- "$destination"
    fi
}
verify_restored_file() {
    local destination="$1"
    local key="$2"
    local source="$SNAPSHOT/files/$key"
    if [[ -f "$source" && ! -L "$source" ]]; then
        [[ -f "$destination" && ! -L "$destination" ]] || return 1
        cmp -s -- "$source" "$destination" || return 1
        [[ "$(stat -c %u:%g:%a "$source")" == "$(stat -c %u:%g:%a "$destination")" ]]
    elif [[ -f "$SNAPSHOT/absent/$key" && ! -L "$SNAPSHOT/absent/$key" ]]; then
        [[ ! -e "$destination" && ! -L "$destination" ]]
    else
        return 1
    fi
}
rollback_pam() {
    local status=$?
    trap - EXIT
    set +e
    if [[ "$status" != 0 && "$ARMED" == 1 ]]; then
        rm -f -- "${pam_tmp:-}"
        restore_file "$PAM_FILE" pam-sshd
        restore_file "$HOOK" hook
        restore_file "$CONFIG" config
        if [[ "$CONFIG_DIR_EXISTED" == 1 ]]; then
            read -r uid gid mode < "$SNAPSHOT/config-dir-meta"
            chown "$uid:$gid" "$CONFIG_DIR"
            chmod "$mode" "$CONFIG_DIR"
        else
            rmdir "$CONFIG_DIR" >/dev/null 2>&1 || true
        fi
        rollback_degraded=0
        verify_restored_file "$PAM_FILE" pam-sshd || rollback_degraded=1
        verify_restored_file "$HOOK" hook || rollback_degraded=1
        verify_restored_file "$CONFIG" config || rollback_degraded=1
        if [[ "$CONFIG_DIR_EXISTED" == 1 ]]; then
            read -r uid gid mode < "$SNAPSHOT/config-dir-meta"
            [[ "$(stat -c %u:%g:%a "$CONFIG_DIR")" == "$uid:$gid:$mode" ]] || rollback_degraded=1
        else
            [[ ! -e "$CONFIG_DIR" && ! -L "$CONFIG_DIR" ]] || rollback_degraded=1
        fi
        if [[ "$rollback_degraded" == 1 ]]; then
            printf 'SSH ALERT TRANSACTION: rollback DEGRADED\n' >&2
            exit 71
        fi
        printf 'SSH ALERT TRANSACTION: rollback VERIFIED\n' >&2
    fi
    exit "$status"
}

snapshot_file "$PAM_FILE" pam-sshd
snapshot_file "$HOOK" hook
snapshot_file "$CONFIG" config
if [[ "$CONFIG_DIR_EXISTED" == 1 ]]; then
    stat -c '%u %g %a' "$CONFIG_DIR" > "$SNAPSHOT/config-dir-meta"
fi
find "$SNAPSHOT" -type f -exec sync -f {} +
sync -f "$SNAPSHOT/files"
sync -f "$SNAPSHOT"
ARMED=1
trap rollback_pam EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Pre-install the exact PAM line through same-directory fsync+rename. The
# privileged setup then sees an idempotent PAM state and cannot append in place.
cp -- "$PAM_FILE" "$SNAPSHOT/pam.candidate"
if (( hook_count == 0 )); then
    {
        printf '\n# Mini-Ops SSH Alert Hook\n'
        printf 'session optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh\n'
    } >> "$SNAPSHOT/pam.candidate"
fi
pam_tmp="$(mktemp /etc/pam.d/.mini-ops-sshd.XXXXXXXX)"
install -o "$(stat -c %u "$PAM_FILE")" -g "$(stat -c %g "$PAM_FILE")" -m "$(stat -c %a "$PAM_FILE")" "$SNAPSHOT/pam.candidate" "$pam_tmp"
sync -f "$pam_tmp"
mv -fT "$pam_tmp" "$PAM_FILE"
sync -f /etc/pam.d

DEPLOY_APP_PORT="$APP_PORT" \
    MINI_OPS_APP_USER="$APP_USER" \
    MINI_OPS_INTERNAL_TOKEN_FILE=/run/mini-ops/internal.token \
    MINI_OPS_BOOTSTRAP_LOCK_OWNER="$BOOTSTRAP_LOCK_OWNER" \
    /bin/bash -p /opt/mini-ops/scripts/setup_ssh_alerts.sh

[[ "$(grep -Fxc 'session optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh' "$PAM_FILE")" == 1 ]] || die 'PAM hook post-proof failed'
[[ "$(stat -c %u:%g:%a "$HOOK")" == 0:0:755 ]] || die 'SSH-alert hook ownership/mode proof failed'
[[ "$(stat -c %u:%g:%a "$CONFIG")" == 0:0:600 ]] || die 'SSH-alert config ownership/mode proof failed'
grep -Fxq "API_URL=http://127.0.0.1:${APP_PORT}/api/internal/ssh-login" "$CONFIG" || die 'SSH-alert loopback API proof failed'
grep -Fxq 'TOKEN_FILE=/run/mini-ops/internal.token' "$CONFIG" || die 'SSH-alert token path proof failed'

ARMED=0
trap - EXIT INT TERM
printf 'SSH-alert transaction verified; rollback snapshot retained at %s\n' "$SNAPSHOT"
REMOTE_SSH_ALERTS
fi

verify_firewall_rollback_connectivity() {
    local rollback_script="$1"
    local initial_active="$2"
    local deadline=$((SECONDS + DEPLOY_UFW_ROLLBACK_SECS + 20))
    local remaining
    local status

    while :; do
        set +e
        remote_root \
            "$rollback_script" \
            "$initial_active" \
            "$DEPLOY_SSH_PORT" <<'REMOTE_UFW_ROLLBACK_PROOF' >/dev/null 2>&1
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
ROLLBACK_SCRIPT="$1"
INITIAL_ACTIVE="$2"
SSH_PORT="$3"
[[ "$ROLLBACK_SCRIPT" =~ ^/var/lib/mini-ops-bootstrap/ufw-rollback/[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{8}/rollback[.]sh$ ]]
[[ -f "$ROLLBACK_SCRIPT" && ! -L "$ROLLBACK_SCRIPT" && "$(stat -c %u:%g:%a "$ROLLBACK_SCRIPT")" == 0:0:700 ]]
SNAPSHOT="$(dirname "$ROLLBACK_SCRIPT")"
[[ -d "$SNAPSHOT/etc-ufw" && ! -L "$SNAPSHOT/etc-ufw" ]]
[[ -f "$SNAPSHOT/default-ufw" && ! -L "$SNAPSHOT/default-ufw" ]]
timeout 10 diff -qr -- "$SNAPSHOT/etc-ufw" /etc/ufw >/dev/null
timeout 5 cmp -s -- "$SNAPSHOT/default-ufw" /etc/default/ufw
status_output="$(timeout 5 ufw status)"
[[ "$(printf '%s\n' "$status_output" | grep -Ec '^Status: (active|inactive)$' || true)" == 1 ]]
if [[ "$INITIAL_ACTIVE" == 1 ]]; then
    printf '%s\n' "$status_output" | grep -q '^Status: active$'
else
    printf '%s\n' "$status_output" | grep -q '^Status: inactive$'
fi
listener_count="$(timeout 5 ss -H -ltn | awk -v wanted="$SSH_PORT" '{local=$4; sub(/^.*:/, "", local); if (local == wanted) count++} END {print count+0}')"
(( listener_count > 0 ))
REMOTE_UFW_ROLLBACK_PROOF
        status=$?
        set -e
        if [[ "$status" == 0 ]]; then
            return 0
        fi
        (( SECONDS < deadline )) || break
        remaining=$((deadline - SECONDS))
        if (( remaining > 5 )); then
            sleep 5
        else
            sleep "$remaining"
        fi
    done
    return 1
}

request_firewall_rollback() {
    local rollback_script="$1"

    remote_root "$rollback_script" <<'REMOTE_UFW_ROLLBACK_NOW' >/dev/null 2>&1
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
ROLLBACK_SCRIPT="$1"
[[ "$ROLLBACK_SCRIPT" =~ ^/var/lib/mini-ops-bootstrap/ufw-rollback/[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{8}/rollback[.]sh$ ]]
[[ -f "$ROLLBACK_SCRIPT" && ! -L "$ROLLBACK_SCRIPT" && "$(stat -c %u:%g:%a "$ROLLBACK_SCRIPT")" == 0:0:700 ]]
/bin/bash "$ROLLBACK_SCRIPT"
REMOTE_UFW_ROLLBACK_NOW
}

verify_firewall_committed_connectivity() {
    local transaction_unit="$1"
    local rollback_script="$2"
    local deadline=$((SECONDS + 30))
    local remaining
    local status

    while :; do
        set +e
        remote_root_with_systemd_probes \
            "$transaction_unit" \
            "$rollback_script" \
            "$DEPLOY_SSH_PORT" \
            "$DEPLOY_SETUP_NGINX" \
            "$DEPLOY_EXPOSE_HTTP" \
            "$DEPLOY_NGINX_PORT" <<'REMOTE_UFW_COMMITTED_PROOF' >/dev/null 2>&1
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
UNIT="$1"
ROLLBACK_SCRIPT="$2"
SSH_PORT="$3"
SETUP_NGINX="$4"
EXPOSE_HTTP="$5"
NGINX_PORT="$6"
TX_HELPER=/opt/mini-ops/scripts/filesystem_transaction.sh
[[ "$UNIT" =~ ^mini-ops-ufw-rollback-[A-Za-z0-9]{8}$ ]]
[[ "$ROLLBACK_SCRIPT" =~ ^/var/lib/mini-ops-bootstrap/ufw-rollback/[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{8}/rollback[.]sh$ ]]
[[ -f "$ROLLBACK_SCRIPT" && ! -L "$ROLLBACK_SCRIPT" && "$(stat -c %u:%g:%a "$ROLLBACK_SCRIPT")" == 0:0:700 ]]
SNAPSHOT="$(dirname "$ROLLBACK_SCRIPT")"
COMMITTED="$SNAPSHOT/committed"
DECISION_LOCK="$SNAPSHOT/decision.lock"
[[ -f "$COMMITTED" && ! -L "$COMMITTED" && "$(stat -c %u:%g:%a "$COMMITTED")" == 0:0:600 ]]
[[ -f "$DECISION_LOCK" && ! -L "$DECISION_LOCK" && "$(stat -c %u:%g:%a "$DECISION_LOCK")" == 0:0:600 ]]
grep -Fq 'if [[ -e "$COMMITTED" || -L "$COMMITTED" ]]; then' "$ROLLBACK_SCRIPT"
flock --nonblock "$DECISION_LOCK" /bin/true
[[ -f "$TX_HELPER" && ! -L "$TX_HELPER" && "$(stat -c %u:%g:%a "$TX_HELPER")" == 0:0:755 ]]
# shellcheck source=scripts/lib/filesystem_transaction.sh
source "$TX_HELPER"
status_output="$(timeout 5 ufw status)"
[[ "$(printf '%s\n' "$status_output" | grep -Ec '^Status: active$' || true)" == 1 ]]
[[ "$(printf '%s\n' "$status_output" | grep -Ec '^Status: (active|inactive)$' || true)" == 1 ]]
printf '%s\n' "$status_output" | tx_ufw_status_allows_port "$SSH_PORT/tcp"
if [[ "$SETUP_NGINX" == 1 && "$EXPOSE_HTTP" == 1 ]]; then
    printf '%s\n' "$status_output" | tx_ufw_status_allows_port "$NGINX_PORT/tcp"
fi
listener_count="$(timeout 5 ss -H -ltn | awk -v wanted="$SSH_PORT" '{local=$4; sub(/^.*:/, "", local); if (local == wanted) count++} END {print count+0}')"
(( listener_count > 0 ))
rollback_service_is_active=-1
deploy_systemd_probe_active "${UNIT}.service" rollback_service_is_active || exit 1
[[ "$rollback_service_is_active" == 0 ]]
REMOTE_UFW_COMMITTED_PROOF
        status=$?
        set -e
        if [[ "$status" == 0 ]]; then
            return 0
        fi
        (( SECONDS < deadline )) || break
        remaining=$((deadline - SECONDS))
        if (( remaining > 2 )); then
            sleep 2
        else
            sleep "$remaining"
        fi
    done
    return 1
}

apply_firewall_transaction() {
    local transaction
    local transaction_status
    local commit_transaction
    local commit_status
    local durable_line
    local commit_ok_line
    local durable_tag
    local durable_unit
    local durable_script
    local durable_extra
    local commit_ok_tag
    local commit_ok_unit
    local commit_ok_script
    local commit_ok_extra
    local meta_line
    local ok_line
    local meta_tag
    local ok_tag
    local ok_unit
    local ok_script
    local ok_initial
    local transaction_unit
    local rollback_script
    local initial_active
    local extra

    set +e
    transaction="$(remote_root_with_systemd_probes \
        "$DEPLOY_SSH_PORT" \
        "$DEPLOY_SETUP_NGINX" \
        "$DEPLOY_EXPOSE_HTTP" \
        "$DEPLOY_NGINX_PORT" \
        "$DEPLOY_UFW_ROLLBACK_SECS" <<'REMOTE_UFW_APPLY'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077

SSH_PORT="$1"
SETUP_NGINX="$2"
EXPOSE_HTTP="$3"
NGINX_PORT="$4"
ROLLBACK_SECS="$5"
ROOT=/var/lib/mini-ops-bootstrap/ufw-rollback
SNAPSHOT=""
ROLLBACK_SCRIPT=""
UNIT=""
INITIAL_ACTIVE=0
MUTATED=0
TX_HELPER=/opt/mini-ops/scripts/filesystem_transaction.sh

die() { printf 'UFW TRANSACTION: %s\n' "$*" >&2; exit 1; }

[[ -f "$TX_HELPER" && ! -L "$TX_HELPER" && "$(stat -c %u:%g:%a "$TX_HELPER")" == 0:0:755 ]] || die 'UFW transaction helper is unsafe'
# shellcheck source=scripts/lib/filesystem_transaction.sh
source "$TX_HELPER"

for tool in awk bash chmod chown cp dirname du find flock grep install mktemp mv rm sort ss stat sync systemctl systemd-run timeout touch ufw wc; do
    command -v "$tool" >/dev/null 2>&1 || die "required tool unavailable: $tool"
done
firewalld_is_active=-1
deploy_systemd_probe_active firewalld firewalld_is_active ||
    die 'firewalld state probe was ambiguous or transitional'
[[ "$firewalld_is_active" == 0 ]] || die 'firewalld is active; refusing mixed firewall managers'
listener_count="$(timeout 5 ss -H -ltn | awk -v wanted="$SSH_PORT" '{local=$4; sub(/^.*:/, "", local); if (local == wanted) count++} END {print count+0}')"
(( listener_count > 0 )) || die 'actual SSH listener disappeared before firewall mutation'

set +e
ufw_status_output="$(ufw status 2>/dev/null)"
ufw_status_code=$?
set -e
[[ "$ufw_status_code" == 0 ]] || die 'UFW status command failed'
ufw_status_count="$(printf '%s\n' "$ufw_status_output" | grep -Ec '^Status: (active|inactive)$' || true)"
[[ "$ufw_status_count" == 1 ]] || die 'UFW status is malformed or ambiguous'
ufw_state="$(printf '%s\n' "$ufw_status_output" | awk '/^Status: /{print $2; exit}')"
case "$ufw_state" in
    active) INITIAL_ACTIVE=1 ;;
    inactive) INITIAL_ACTIVE=0 ;;
    *) die 'UFW status is neither exactly active nor inactive' ;;
esac
if [[ "$INITIAL_ACTIVE" == 0 ]]; then
    input_count="$(grep -Ec '^DEFAULT_INPUT_POLICY=' /etc/default/ufw || true)"
    output_count="$(grep -Ec '^DEFAULT_OUTPUT_POLICY=' /etc/default/ufw || true)"
    [[ "$input_count" == 1 && "$output_count" == 1 ]] || die 'UFW default policy definitions are duplicated or missing'
    incoming="$(awk -F= '/^DEFAULT_INPUT_POLICY=/{gsub(/["[:space:]]/, "", $2); print toupper($2); exit}' /etc/default/ufw)"
    outgoing="$(awk -F= '/^DEFAULT_OUTPUT_POLICY=/{gsub(/["[:space:]]/, "", $2); print toupper($2); exit}' /etc/default/ufw)"
    case "$incoming" in
        DROP|REJECT) ;;
        *) die 'inactive UFW incoming policy is not deny/reject or is ambiguous' ;;
    esac
    case "$outgoing" in
        ACCEPT) ;;
        *) die 'inactive UFW outgoing policy is not allow or is ambiguous' ;;
    esac
fi

# Exact commands are parsed before snapshot/timer and before the first mutation.
ufw --dry-run allow "$SSH_PORT/tcp" >/dev/null
if [[ "$SETUP_NGINX" == 1 && "$EXPOSE_HTTP" == 1 ]]; then
    ufw --dry-run allow "$NGINX_PORT/tcp" >/dev/null
fi

BASE="$(dirname "$ROOT")"
for directory in "$BASE" "$ROOT"; do
    if [[ -e "$directory" || -L "$directory" ]]; then
        [[ -d "$directory" && ! -L "$directory" && "$(stat -c %u:%g:%a "$directory")" == 0:0:700 ]] || die 'UFW rollback root is not a root-owned 0700 nofollow directory'
    else
        install -d -o root -g root -m 0700 "$directory"
    fi
done
[[ -d /etc/ufw && ! -L /etc/ufw ]] || die '/etc/ufw is not a nofollow directory'
if find /etc/ufw -xdev -type l -print -quit | grep -q .; then
    die '/etc/ufw contains a symlink; refusing rollback snapshot'
fi
if find /etc/ufw -xdev ! -type d ! -type f -print -quit | grep -q .; then
    die '/etc/ufw contains a non-regular object; refusing rollback snapshot'
fi
[[ -f /etc/default/ufw && ! -L /etc/default/ufw && "$(stat -c %u:%g /etc/default/ufw)" == 0:0 ]] || die '/etc/default/ufw is not a root-owned nofollow file'

snapshot_count="$(find "$ROOT" -mindepth 1 -maxdepth 1 -type d -printf '.\n' | wc -l)"
while (( snapshot_count >= 3 )); do
    oldest_committed="$(find "$ROOT" -mindepth 2 -maxdepth 2 -type f -name committed -printf '%T@ %h\n' | sort -n | awk 'NR == 1 {sub(/^[^ ]+ /, ""); print}')"
    [[ -n "$oldest_committed" && "$oldest_committed" == "$ROOT"/* ]] || die 'three uncommitted UFW rollback snapshots require operator review'
    rm -rf -- "$oldest_committed"
    snapshot_count=$((snapshot_count - 1))
done
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
SNAPSHOT="$(mktemp -d "$ROOT/${timestamp}.XXXXXXXX")"
chmod 0700 "$SNAPSHOT"
cp -a -- /etc/ufw "$SNAPSHOT/etc-ufw"
cp -a -- /etc/default/ufw "$SNAPSHOT/default-ufw"
printf '%s\n' "$INITIAL_ACTIVE" > "$SNAPSHOT/initial-active"
size="$(du -sb "$SNAPSHOT" | awk '{print $1}')"
[[ "$size" =~ ^[0-9]+$ && "$size" -le 8388608 ]] || {
    rm -rf -- "$SNAPSHOT"
    die 'UFW snapshot exceeds the 8 MiB bound'
}
find "$SNAPSHOT" -type f -exec sync -f {} +
sync -f "$SNAPSHOT"
[[ "$(stat -c %u:%g:%a "$SNAPSHOT")" == 0:0:700 ]] || die 'UFW snapshot ownership/mode proof failed'

random="${SNAPSHOT##*.}"
UNIT="mini-ops-ufw-rollback-${random}"
ROLLBACK_SCRIPT="$SNAPSHOT/rollback.sh"
DECISION_LOCK="$SNAPSHOT/decision.lock"
: > "$DECISION_LOCK"
chmod 0600 "$DECISION_LOCK"
sync -f "$DECISION_LOCK"
cat > "$ROLLBACK_SCRIPT" <<EOF
#!/bin/bash
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
SNAPSHOT='$SNAPSHOT'
DECISION_LOCK='${SNAPSHOT}/decision.lock'
COMMITTED='${SNAPSHOT}/committed'
[[ -f "\$DECISION_LOCK" && ! -L "\$DECISION_LOCK" && "\$(stat -c %u:%g:%a "\$DECISION_LOCK")" == 0:0:600 ]]
exec 9<>"\$DECISION_LOCK"
flock 9
if [[ -e "\$COMMITTED" || -L "\$COMMITTED" ]]; then
    [[ -f "\$COMMITTED" && ! -L "\$COMMITTED" && "\$(stat -c %u:%g:%a "\$COMMITTED")" == 0:0:600 ]]
    exit 0
fi
rm -rf -- /etc/ufw
cp -a -- '$SNAPSHOT/etc-ufw' /etc/ufw
cp -a -- '$SNAPSHOT/default-ufw' /etc/default/ufw
find /etc/ufw -type f -exec sync -f {} +
sync -f /etc/default/ufw
if [[ '$INITIAL_ACTIVE' == 1 ]]; then
    ufw --force enable >/dev/null
    ufw reload >/dev/null
else
    ufw --force disable >/dev/null
fi
status_output="\$(ufw status)"
[[ "\$(printf '%s\n' "\$status_output" | grep -Ec '^Status: (active|inactive)\$' || true)" == 1 ]]
if [[ '$INITIAL_ACTIVE' == 1 ]]; then
    printf '%s\n' "\$status_output" | grep -q '^Status: active\$'
else
    printf '%s\n' "\$status_output" | grep -q '^Status: inactive\$'
fi
listener_count="\$(timeout 5 ss -H -ltn | awk -v wanted='$SSH_PORT' '{local=\$4; sub(/^.*:/, "", local); if (local == wanted) count++} END {print count+0}')"
(( listener_count > 0 ))
EOF
chmod 0700 "$ROLLBACK_SCRIPT"
/bin/bash -n "$ROLLBACK_SCRIPT"
sync -f "$ROLLBACK_SCRIPT"
sync -f "$SNAPSHOT"
size="$(du -sb "$SNAPSHOT" | awk '{print $1}')"
[[ "$size" =~ ^[0-9]+$ && "$size" -le 8372224 ]] || {
    rm -rf -- "$SNAPSHOT"
    die 'complete UFW snapshot exceeds the 8 MiB bound with its 16 KiB durable-marker reserve'
}

rollback_now() {
    local status=$?
    trap - EXIT
    set +e
    if [[ "$status" != 0 && "$MUTATED" == 1 ]]; then
        if [[ -f "$ROLLBACK_SCRIPT" && ! -L "$ROLLBACK_SCRIPT" && "$(stat -c %u:%g:%a "$ROLLBACK_SCRIPT")" == 0:0:700 ]] &&
            /bin/bash "$ROLLBACK_SCRIPT" >/dev/null 2>&1; then
            printf 'UFW TRANSACTION: immediate rollback VERIFIED; timer remains armed\n' >&2
        else
            printf 'UFW TRANSACTION: immediate rollback DEGRADED; timer remains armed\n' >&2
        fi
    fi
    exit "$status"
}
trap rollback_now EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

systemd-run --quiet --unit "$UNIT" --on-active="${ROLLBACK_SECS}s" /bin/bash "$ROLLBACK_SCRIPT"
systemctl is-active --quiet "${UNIT}.timer"
timer_target="$(systemctl show "${UNIT}.timer" -p Unit --value)"
rollback_exec="$(systemctl show "${UNIT}.service" -p ExecStart --value)"
[[ "$timer_target" == "${UNIT}.service" ]] || die 'rollback timer target proof failed'
[[ "$rollback_exec" == *'/bin/bash'* && "$rollback_exec" == *"$ROLLBACK_SCRIPT"* ]] || die 'rollback service command proof failed'
printf 'ROLLBACK_META %s %s %s\n' "$UNIT" "$ROLLBACK_SCRIPT" "$INITIAL_ACTIVE"
MUTATED=1
ufw allow "$SSH_PORT/tcp" >/dev/null
if [[ "$SETUP_NGINX" == 1 && "$EXPOSE_HTTP" == 1 ]]; then
    ufw allow "$NGINX_PORT/tcp" >/dev/null
fi
if [[ "$INITIAL_ACTIVE" == 0 ]]; then
    ufw --force enable >/dev/null
else
    ufw reload >/dev/null
fi
set +e
post_status_output="$(ufw status 2>/dev/null)"
post_status_code=$?
set -e
[[ "$post_status_code" == 0 ]] || die 'post-apply UFW status command failed'
[[ "$(printf '%s\n' "$post_status_output" | grep -Ec '^Status: active$' || true)" == 1 ]] || die 'post-apply UFW state is not exactly active'
[[ "$(printf '%s\n' "$post_status_output" | grep -Ec '^Status: (active|inactive)$' || true)" == 1 ]] || die 'post-apply UFW status is ambiguous'
printf '%s\n' "$post_status_output" | tx_ufw_status_allows_port "$SSH_PORT/tcp" || die 'post-apply SSH rule is not unambiguously ALLOW'
if [[ "$SETUP_NGINX" == 1 && "$EXPOSE_HTTP" == 1 ]]; then
    printf '%s\n' "$post_status_output" | tx_ufw_status_allows_port "$NGINX_PORT/tcp" || die 'post-apply HTTP rule is not unambiguously ALLOW'
fi

printf 'APPLY_OK %s %s %s\n' "$UNIT" "$ROLLBACK_SCRIPT" "$INITIAL_ACTIVE"
trap - EXIT INT TERM
REMOTE_UFW_APPLY
)"
    transaction_status=$?
    set -e
    meta_line="$(printf '%s\n' "$transaction" | awk '$1 == "ROLLBACK_META" {print; exit}')"
    read -r meta_tag transaction_unit rollback_script initial_active extra <<< "$meta_line"
    if [[ "$meta_tag" != ROLLBACK_META || -n "${extra:-}" || ! "$transaction_unit" =~ ^mini-ops-ufw-rollback-[A-Za-z0-9]{8}$ ]] ||
        [[ ! "$rollback_script" =~ ^/var/lib/mini-ops-bootstrap/ufw-rollback/[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{8}/rollback\.sh$ ]] ||
        [[ "$initial_active" != 0 && "$initial_active" != 1 ]]; then
        if [[ "$transaction_status" != 0 ]]; then
            deploy_error 'firewall transaction failed before the first UFW mutation; no rollback metadata was armed'
        fi
        deploy_error 'firewall transaction returned invalid rollback metadata'
    fi
    if [[ "$transaction_status" != 0 ]]; then
        request_firewall_rollback "$rollback_script" || true
        if verify_firewall_rollback_connectivity "$rollback_script" "$initial_active"; then
            deploy_error 'firewall apply failed; a fresh SSH connection verified exact rollback state'
        fi
        deploy_error 'firewall apply failed and fresh-SSH rollback verification remained degraded'
    fi
    ok_line="$(printf '%s\n' "$transaction" | awk '$1 == "APPLY_OK" {print; exit}')"
    read -r ok_tag ok_unit ok_script ok_initial extra <<< "$ok_line"
    if [[ "$ok_tag" != APPLY_OK || "$ok_unit" != "$transaction_unit" || "$ok_script" != "$rollback_script" ]] ||
        [[ "$ok_initial" != "$initial_active" || -n "${extra:-}" ]]; then
        request_firewall_rollback "$rollback_script" || true
        if verify_firewall_rollback_connectivity "$rollback_script" "$initial_active"; then
            deploy_error 'firewall apply success metadata was inconsistent; immediate rollback and a fresh SSH proof succeeded'
        fi
        deploy_error 'firewall apply success metadata was inconsistent and rollback proof remained degraded'
    fi

    # This is intentionally a new SSH process. Only this independently proven
    # path may make the durable commit decision and cancel the rollback timer.
    # The decision lock serializes that point with the timer's rollback script.
    set +e
    commit_transaction="$(remote_root \
        "$transaction_unit" \
        "$rollback_script" \
        "$DEPLOY_SSH_PORT" \
        "$DEPLOY_SETUP_NGINX" \
        "$DEPLOY_EXPOSE_HTTP" \
        "$DEPLOY_NGINX_PORT" <<'REMOTE_UFW_COMMIT'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
umask 077
UNIT="$1"
ROLLBACK_SCRIPT="$2"
SSH_PORT="$3"
SETUP_NGINX="$4"
EXPOSE_HTTP="$5"
NGINX_PORT="$6"
TX_HELPER=/opt/mini-ops/scripts/filesystem_transaction.sh
[[ "$UNIT" =~ ^mini-ops-ufw-rollback-[A-Za-z0-9]{8}$ ]]
[[ "$ROLLBACK_SCRIPT" =~ ^/var/lib/mini-ops-bootstrap/ufw-rollback/[0-9]{8}T[0-9]{6}Z\.[A-Za-z0-9]{8}/rollback[.]sh$ ]]
[[ -f "$ROLLBACK_SCRIPT" && ! -L "$ROLLBACK_SCRIPT" && "$(stat -c %u:%g:%a "$ROLLBACK_SCRIPT")" == 0:0:700 ]]
SNAPSHOT="$(dirname "$ROLLBACK_SCRIPT")"
[[ "$UNIT" == "mini-ops-ufw-rollback-${SNAPSHOT##*.}" ]]
DECISION_LOCK="$SNAPSHOT/decision.lock"
COMMITTED="$SNAPSHOT/committed"
[[ -f "$DECISION_LOCK" && ! -L "$DECISION_LOCK" && "$(stat -c %u:%g:%a "$DECISION_LOCK")" == 0:0:600 ]]
[[ ! -e "$COMMITTED" && ! -L "$COMMITTED" ]]
[[ -f "$TX_HELPER" && ! -L "$TX_HELPER" && "$(stat -c %u:%g:%a "$TX_HELPER")" == 0:0:755 ]]
# shellcheck source=scripts/lib/filesystem_transaction.sh
source "$TX_HELPER"
exec 9<>"$DECISION_LOCK"
flock 9

rollback_and_fail() {
    local status=$?
    trap - EXIT
    set +e
    if [[ "$status" != 0 ]]; then
        if [[ -f "$COMMITTED" && ! -L "$COMMITTED" && "$(stat -c %u:%g:%a "$COMMITTED")" == 0:0:600 ]]; then
            printf 'COMMIT_DURABLE %s %s\n' "$UNIT" "$ROLLBACK_SCRIPT"
            printf 'UFW TRANSACTION: durable commit retained; timer cleanup proof DEGRADED\n' >&2
        else
            flock -u 9 >/dev/null 2>&1 || true
            if /bin/bash "$ROLLBACK_SCRIPT" >/dev/null 2>&1; then
                printf 'UFW TRANSACTION: verification/commit failed; immediate rollback VERIFIED; timer remains fail-safe\n' >&2
            else
                printf 'UFW TRANSACTION: verification/commit failed; immediate rollback DEGRADED; timer remains fail-safe\n' >&2
            fi
            exit "$status"
        fi
    fi
    flock -u 9 >/dev/null 2>&1 || true
    exit "$status"
}
trap rollback_and_fail EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

set +e
verified_status="$(ufw status 2>/dev/null)"
verified_status_code=$?
set -e
[[ "$verified_status_code" == 0 ]] || exit 1
[[ "$(printf '%s\n' "$verified_status" | grep -Ec '^Status: active$' || true)" == 1 ]] || exit 1
[[ "$(printf '%s\n' "$verified_status" | grep -Ec '^Status: (active|inactive)$' || true)" == 1 ]] || exit 1
printf '%s\n' "$verified_status" | tx_ufw_status_allows_port "$SSH_PORT/tcp"
if [[ "$SETUP_NGINX" == 1 && "$EXPOSE_HTTP" == 1 ]]; then
    printf '%s\n' "$verified_status" | tx_ufw_status_allows_port "$NGINX_PORT/tcp"
fi

# Prove the rollback timer is still armed and has not fired while holding the
# same lock that its rollback script must acquire.
set +e
timer_before="$(timeout 5 systemctl is-active "${UNIT}.timer" 2>/dev/null)"
timer_before_status=$?
rollback_service_state="$(timeout 5 systemctl is-active "${UNIT}.service" 2>/dev/null)"
rollback_service_status=$?
rollback_started="$(systemctl show "${UNIT}.service" -p ExecMainStartTimestampMonotonic --value 2>/dev/null)"
rollback_started_status=$?
set -e
[[ "$timer_before:$timer_before_status" == active:0 ]]
case "$rollback_service_state:$rollback_service_status" in inactive:3|unknown:4) ;; *) exit 1 ;; esac
[[ "$rollback_started_status" == 0 && "$rollback_started" == 0 ]]
timer_target="$(systemctl show "${UNIT}.timer" -p Unit --value)"
rollback_exec="$(systemctl show "${UNIT}.service" -p ExecStart --value)"
[[ "$timer_target" == "${UNIT}.service" ]]
[[ "$rollback_exec" == *'/bin/bash'* && "$rollback_exec" == *"$ROLLBACK_SCRIPT"* ]]

# This durable marker is the commit point. The timer's script checks it under
# DECISION_LOCK, so a timer racing with cancellation can no longer undo a
# connectivity-verified firewall state.
commit_source="$(mktemp "$SNAPSHOT/.committed.XXXXXXXX")"
printf '%s\n' 'connectivity-verified' > "$commit_source"
tx_atomic_install "$commit_source" "$COMMITTED" 0 0 0600
rm -f -- "$commit_source"
sync -f "$SNAPSHOT"
[[ -f "$COMMITTED" && ! -L "$COMMITTED" && "$(stat -c %u:%g:%a "$COMMITTED")" == 0:0:600 ]]
printf 'COMMIT_DURABLE %s %s\n' "$UNIT" "$ROLLBACK_SCRIPT"
# No rollback-required work exists after the durable decision. A later cleanup
# failure leaves the marker in place, so the timer can only exit harmlessly.
trap - EXIT INT TERM

systemctl stop "${UNIT}.timer"
set +e
timer_state="$(timeout 5 systemctl is-active "${UNIT}.timer" 2>/dev/null)"
timer_state_status=$?
rollback_service_state="$(timeout 5 systemctl is-active "${UNIT}.service" 2>/dev/null)"
rollback_service_status=$?
rollback_started="$(systemctl show "${UNIT}.service" -p ExecMainStartTimestampMonotonic --value 2>/dev/null)"
rollback_started_status=$?
set -e
case "$timer_state:$timer_state_status" in inactive:3|unknown:4) ;; *) exit 1 ;; esac
case "$rollback_service_state:$rollback_service_status" in inactive:3|unknown:4) ;; *) exit 1 ;; esac
[[ "$rollback_started_status" == 0 && "$rollback_started" == 0 ]]
post_cancel_status="$(ufw status)"
[[ "$(printf '%s\n' "$post_cancel_status" | grep -Ec '^Status: active$' || true)" == 1 ]]
[[ "$(printf '%s\n' "$post_cancel_status" | grep -Ec '^Status: (active|inactive)$' || true)" == 1 ]]
printf '%s\n' "$post_cancel_status" | tx_ufw_status_allows_port "$SSH_PORT/tcp"
if [[ "$SETUP_NGINX" == 1 && "$EXPOSE_HTTP" == 1 ]]; then
    printf '%s\n' "$post_cancel_status" | tx_ufw_status_allows_port "$NGINX_PORT/tcp"
fi
systemctl reset-failed "${UNIT}.service" >/dev/null 2>&1 || true
flock -u 9 || true
printf 'COMMIT_OK %s %s\n' "$UNIT" "$ROLLBACK_SCRIPT"
REMOTE_UFW_COMMIT
    )"
    commit_status=$?
    set -e
    durable_line="$(printf '%s\n' "$commit_transaction" | awk '$1 == "COMMIT_DURABLE" {print; exit}')"
    read -r durable_tag durable_unit durable_script durable_extra <<< "$durable_line"
    commit_ok_line="$(printf '%s\n' "$commit_transaction" | awk '$1 == "COMMIT_OK" {print; exit}')"
    read -r commit_ok_tag commit_ok_unit commit_ok_script commit_ok_extra <<< "$commit_ok_line"

    if [[ "$commit_status" != 0 ]]; then
        if [[ "$durable_tag" == COMMIT_DURABLE && "$durable_unit" == "$transaction_unit" ]] &&
            [[ "$durable_script" == "$rollback_script" && -z "${durable_extra:-}" ]]; then
            if verify_firewall_committed_connectivity "$transaction_unit" "$rollback_script"; then
                deploy_error 'firewall commit is durable and connectivity-verified, but rollback-timer cleanup proof failed'
            fi
            deploy_error 'firewall commit reported durable state, but fresh-SSH committed-state proof was degraded'
        fi
        if verify_firewall_committed_connectivity "$transaction_unit" "$rollback_script"; then
            deploy_error 'firewall commit metadata was interrupted after its durable point; fresh SSH verified the committed state'
        fi
        if verify_firewall_rollback_connectivity "$rollback_script" "$initial_active"; then
            deploy_error 'independent SSH firewall commit failed; a subsequent fresh SSH connection verified exact rollback state'
        fi
        deploy_error 'independent SSH firewall commit failed and subsequent rollback verification remained degraded'
    fi
    if [[ "$durable_tag" != COMMIT_DURABLE || "$durable_unit" != "$transaction_unit" ]] ||
        [[ "$durable_script" != "$rollback_script" || -n "${durable_extra:-}" || "$commit_ok_tag" != COMMIT_OK ]] ||
        [[ "$commit_ok_unit" != "$transaction_unit" || "$commit_ok_script" != "$rollback_script" || -n "${commit_ok_extra:-}" ]]; then
        if verify_firewall_committed_connectivity "$transaction_unit" "$rollback_script"; then
            deploy_error 'firewall commit protocol metadata was inconsistent after a fresh committed-state proof'
        fi
        request_firewall_rollback "$rollback_script" || true
        if verify_firewall_rollback_connectivity "$rollback_script" "$initial_active"; then
            deploy_error 'firewall commit metadata was inconsistent; exact rollback was freshly verified'
        fi
        deploy_error 'firewall commit metadata was inconsistent and neither committed nor rollback state could be proved'
    fi
}

printf '%s\n' '[7/8] Optional UFW rollback transaction and Fail2Ban enablement'
assert_remote_lock || deploy_error 'exclusive deploy lease was lost before hardening'
if [[ "$DEPLOY_HARDENING" == "1" ]]; then
    remote_root <<'REMOTE_FAIL2BAN'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
systemctl enable --now fail2ban
systemctl is-active --quiet fail2ban
REMOTE_FAIL2BAN
    apply_firewall_transaction
else
    printf '%s\n' 'Firewall and Fail2Ban unchanged.'
fi

printf '%s\n' '[8/8] Final independent service verification'
assert_remote_lock || deploy_error 'exclusive deploy lease was lost before final verification'
remote_root "$DEPLOY_APP_PORT" <<'REMOTE_FINAL'
set -euo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
APP_PORT="$1"
systemctl is-active --quiet mini-ops
ss -H -ltn | awk -v wanted="$APP_PORT" '
    {
        local=$4
        sub(/^.*:/, "", local)
        if (local == wanted && ($4 ~ /^127[.]/ || $4 ~ /^\[::1\]:/)) found=1
        if (local == wanted && !($4 ~ /^127[.]/ || $4 ~ /^\[::1\]:/)) public=1
    }
    END {exit !(found && !public)}
'
REMOTE_FINAL

printf '%s\n' 'Releasing exclusive remote deploy lease after all post-change proofs.'
release_remote_lock

printf 'Bootstrap complete: %s@%s:%s, service user %s, loopback port %s.\n' \
    "$DEPLOY_SSH_USER" "$DEPLOY_HOST" "$DEPLOY_SSH_PORT" "$DEPLOY_APP_USER" "$DEPLOY_APP_PORT"
