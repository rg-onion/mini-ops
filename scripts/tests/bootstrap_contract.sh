#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
BOOTSTRAP="$PROJECT_ROOT/scripts/bootstrap_server.sh"
CONTRACT="$PROJECT_ROOT/scripts/lib/deploy_contract.sh"
UNIT_TEMPLATE="$PROJECT_ROOT/scripts/mini-ops.service"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/mini-ops-bootstrap-test.XXXXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local file="$1"
    local expected="$2"
    grep -Fq -- "$expected" "$file" || fail "$file does not contain: $expected"
}

assert_not_contains() {
    local file="$1"
    local unexpected="$2"
    if grep -Fq -- "$unexpected" "$file"; then
        fail "$file unexpectedly contains: $unexpected"
    fi
}

FAKE_BIN="$TMP_ROOT/fake-bin"
NETWORK_MARKER="$TMP_ROOT/network-or-build-called"
mkdir -p "$FAKE_BIN"
for command_name in ssh scp cargo npm; do
    {
        printf '#!/bin/bash\n'
        printf 'printf called > %q\n' "$NETWORK_MARKER"
        printf 'exit 97\n'
    } > "$FAKE_BIN/$command_name"
    chmod 0755 "$FAKE_BIN/$command_name"
done

run_dry() {
    local name="$1"
    shift
    env -i \
        PATH="$FAKE_BIN:/usr/sbin:/usr/bin:/sbin:/bin" \
        DEPLOY_HOST=192.0.2.10 \
        DEPLOY_DRY_RUN=1 \
        "$@" \
        /bin/bash "$BOOTSTRAP" > "$TMP_ROOT/$name.out" 2> "$TMP_ROOT/$name.err"
}

run_invalid() {
    local name="$1"
    shift
    if env -i \
        PATH="$FAKE_BIN:/usr/sbin:/usr/bin:/sbin:/bin" \
        DEPLOY_HOST=192.0.2.10 \
        DEPLOY_DRY_RUN=1 \
        "$@" \
        /bin/bash "$BOOTSTRAP" > "$TMP_ROOT/$name.out" 2> "$TMP_ROOT/$name.err"; then
        fail "$name unexpectedly passed validation"
    fi
    [[ ! -e "$NETWORK_MARKER" ]] || fail "$name reached a network/build command"
}

run_dry default
run_dry default-repeat
cmp -s "$TMP_ROOT/default.out" "$TMP_ROOT/default-repeat.out" || fail 'default dry-run is not deterministic'
cmp -s "$TMP_ROOT/default.err" "$TMP_ROOT/default-repeat.err" || fail 'default dry-run warnings are not deterministic'
assert_contains "$TMP_ROOT/default.out" 'mode=production target=/opt/mini-ops app-user=miniops app-bind=127.0.0.1:3000'
assert_contains "$TMP_ROOT/default.out" 'host-key=strict-existing-key'
assert_contains "$TMP_ROOT/default.out" 'build=frontend:npm-ci backend:cargo-release-locked architecture=artifact-vs-remote'
assert_contains "$TMP_ROOT/default.out" 'upload=private-unpredictable:/tmp/mini-ops-deploy.XXXXXXXX:0700'
assert_contains "$TMP_ROOT/default.out" 'code=/opt/mini-ops:root:root:0755 env=root:root:0600 unit=root:root:0644'
assert_contains "$TMP_ROOT/default.out" 'state=/var/lib/mini-ops:miniops:miniops:0700 files:0600 runtime=/run/mini-ops:0700'
assert_contains "$TMP_ROOT/default.out" 'docker=unchanged nginx=disabled firewall=unchanged ssh-alerts=disabled'
assert_contains "$TMP_ROOT/default.out" 'network=not-executed build=not-executed mutation=not-executed'
[[ ! -s "$TMP_ROOT/default.err" ]] || fail 'safe default emitted a warning'
[[ ! -e "$NETWORK_MARKER" ]] || fail 'default dry-run reached a network/build command'

run_dry no-local-build DEPLOY_RUN_LOCAL_BUILD=0
assert_contains "$TMP_ROOT/no-local-build.out" 'build=existing-release-artifact:no-local-build'
assert_not_contains "$TMP_ROOT/no-local-build.out" 'build=frontend:npm-ci'

run_dry nonstandard DEPLOY_SSH_PORT=2222 DEPLOY_HARDENING=1 DEPLOY_UFW_ROLLBACK_SECS=240
assert_contains "$TMP_ROOT/nonstandard.out" 'remote=root@192.0.2.10:2222'
assert_contains "$TMP_ROOT/nonstandard.out" 'firewall=ufw-transaction:ss-port=2222,rollback=240s,fail2ban=enable'
assert_contains "$TMP_ROOT/nonstandard.err" 'bounded rollback transaction is mandatory'
assert_not_contains "$TMP_ROOT/nonstandard.out" 'OpenSSH'

run_dry root-service DEPLOY_APP_USER=root DEPLOY_ALLOW_ROOT_SERVICE=1
assert_contains "$TMP_ROOT/root-service.err" 'root service explicitly enabled'

secret='0123456789abcdef0123456789abcdef'
run_dry env-write DEPLOY_WRITE_ENV=1 AUTH_TOKEN="$secret" TELEGRAM_BOT_TOKEN='bot-token-redacted'
assert_contains "$TMP_ROOT/env-write.out" 'env=replace-from-redacted-local-input secrets=redacted'
assert_not_contains "$TMP_ROOT/env-write.out" "$secret"
assert_not_contains "$TMP_ROOT/env-write.err" "$secret"

run_invalid invalid-host DEPLOY_HOST='bad;host'
assert_contains "$TMP_ROOT/invalid-host.err" 'DEPLOY_HOST must be an IPv4 address or DNS hostname'
run_invalid overflow-ipv4 DEPLOY_HOST=18446744073709551617.0.0.1
assert_contains "$TMP_ROOT/overflow-ipv4.err" 'invalid IPv4 octet'
run_invalid noncanonical-ipv4 DEPLOY_HOST=192.000.2.10
assert_contains "$TMP_ROOT/noncanonical-ipv4.err" 'invalid IPv4 octet'
run_invalid invalid-port DEPLOY_SSH_PORT=0
assert_contains "$TMP_ROOT/invalid-port.err" 'DEPLOY_SSH_PORT must be an integer between 1 and 65535'
run_invalid overflow-ssh-port DEPLOY_SSH_PORT=18446744073709551638
assert_contains "$TMP_ROOT/overflow-ssh-port.err" 'DEPLOY_SSH_PORT must be an integer between 1 and 65535'
run_invalid overflow-app-port DEPLOY_APP_PORT=18446744073709551638
assert_contains "$TMP_ROOT/overflow-app-port.err" 'DEPLOY_APP_PORT must be an integer between 1 and 65535'
run_invalid overflow-nginx-port DEPLOY_NGINX_PORT=18446744073709551638
assert_contains "$TMP_ROOT/overflow-nginx-port.err" 'DEPLOY_NGINX_PORT must be an integer between 1 and 65535'
run_invalid noncanonical-port DEPLOY_APP_PORT=03000
assert_contains "$TMP_ROOT/noncanonical-port.err" 'DEPLOY_APP_PORT must be an integer between 1 and 65535'
run_invalid invalid-user DEPLOY_APP_USER='miniops;id'
assert_contains "$TMP_ROOT/invalid-user.err" 'DEPLOY_APP_USER must be a valid local account name'
run_invalid oversized-user DEPLOY_APP_USER=miniops_user_name_over_linux_limit_33
assert_contains "$TMP_ROOT/oversized-user.err" 'DEPLOY_APP_USER must be a valid local account name'
run_invalid invalid-target DEPLOY_TARGET_DIR=/tmp/mini-ops
assert_contains "$TMP_ROOT/invalid-target.err" 'normalized managed path /opt/mini-ops'
run_invalid direct-exposure DEPLOY_EXPOSE_HTTP=1
assert_contains "$TMP_ROOT/direct-exposure.err" 'requires DEPLOY_SETUP_NGINX=1'
run_invalid extra-listener-without-nginx DEPLOY_NGINX_EXTRA_LISTEN_IP=172.17.0.1
assert_contains "$TMP_ROOT/extra-listener-without-nginx.err" 'requires DEPLOY_SETUP_NGINX=1'
run_invalid invalid-extra-listener DEPLOY_SETUP_NGINX=1 DEPLOY_NGINX_EXTRA_LISTEN_IP=172.017.0.1
assert_contains "$TMP_ROOT/invalid-extra-listener.err" 'must be a canonical IPv4 address'
run_invalid wildcard-extra-listener DEPLOY_SETUP_NGINX=1 DEPLOY_NGINX_EXTRA_LISTEN_IP=0.0.0.0
assert_contains "$TMP_ROOT/wildcard-extra-listener.err" 'must be a non-wildcard unicast address outside loopback'
run_invalid conflicting-extra-listener DEPLOY_SETUP_NGINX=1 DEPLOY_EXPOSE_HTTP=1 DEPLOY_NGINX_EXTRA_LISTEN_IP=172.17.0.1
assert_contains "$TMP_ROOT/conflicting-extra-listener.err" 'cannot be combined with DEPLOY_EXPOSE_HTTP=1'
run_invalid root-without-override DEPLOY_APP_USER=root
assert_contains "$TMP_ROOT/root-without-override.err" 'requires DEPLOY_ALLOW_ROOT_SERVICE=1'
run_invalid unsafe-rollback DEPLOY_UFW_ROLLBACK_SECS=0
assert_contains "$TMP_ROOT/unsafe-rollback.err" 'must be between 60 and 600'
run_invalid overflow-rollback DEPLOY_UFW_ROLLBACK_SECS=18446744073709551856
assert_contains "$TMP_ROOT/overflow-rollback.err" 'must be between 60 and 600'
run_invalid noncanonical-rollback DEPLOY_UFW_ROLLBACK_SECS=060
assert_contains "$TMP_ROOT/noncanonical-rollback.err" 'must be between 60 and 600'

for standalone_port in 18446744073709551638 03000; do
    if DEPLOY_APP_PORT="$standalone_port" /bin/bash "$PROJECT_ROOT/scripts/setup_ssh_alerts.sh" \
        > "$TMP_ROOT/setup-port-$standalone_port.out" 2> "$TMP_ROOT/setup-port-$standalone_port.err"; then
        fail "standalone SSH-alert setup accepted unsafe port: $standalone_port"
    fi
    assert_contains "$TMP_ROOT/setup-port-$standalone_port.err" 'DEPLOY_APP_PORT must be an integer between 1 and 65535'
    assert_not_contains "$TMP_ROOT/setup-port-$standalone_port.err" 'Please run as root'
done

SECRET_BIN="$TMP_ROOT/secret-bin"
SECRET_MARKER="$TMP_ROOT/secret-child-result"
mkdir -p "$SECRET_BIN"
{
    printf '#!/bin/bash\n'
    # Emit literal variable checks into the fake child.
    # shellcheck disable=SC2016
    printf 'if [[ -n "${AUTH_TOKEN+x}" || -n "${TELEGRAM_BOT_TOKEN+x}" || -n "${TELEGRAM_CHAT_ID+x}" ]]; then\n'
    printf '  printf leaked > %q\n' "$SECRET_MARKER"
    printf 'else\n'
    printf '  printf clean > %q\n' "$SECRET_MARKER"
    printf 'fi\n'
    printf 'exit 97\n'
} > "$SECRET_BIN/ssh"
chmod 0755 "$SECRET_BIN/ssh"
if env -i \
    PATH="$SECRET_BIN:/usr/sbin:/usr/bin:/sbin:/bin" \
    DEPLOY_HOST=192.0.2.10 \
    DEPLOY_WRITE_ENV=1 \
    DEPLOY_RUN_LOCAL_BUILD=0 \
    AUTH_TOKEN="$secret" \
    TELEGRAM_BOT_TOKEN=telegram-secret-sentinel \
    TELEGRAM_CHAT_ID=-1001234567890 \
    /bin/bash "$BOOTSTRAP" > "$TMP_ROOT/secret-child.out" 2> "$TMP_ROOT/secret-child.err"; then
    fail 'fake SSH boundary unexpectedly succeeded'
fi
[[ "$(< "$SECRET_MARKER")" == clean ]] || fail 'deployment secret leaked into SSH child environment'
assert_not_contains "$TMP_ROOT/secret-child.out" "$secret"
assert_not_contains "$TMP_ROOT/secret-child.err" "$secret"
assert_contains "$BOOTSTRAP" "curl --disable --config - --noproxy '*'"
assert_not_contains "$BOOTSTRAP" 'api-header.'
assert_not_contains "$BOOTSTRAP" 'rollback-api-header.'
assert_not_contains "$BOOTSTRAP" 'pre-snapshot-header.'
assert_not_contains "$BOOTSTRAP" '--header "@'

# shellcheck source=scripts/lib/deploy_contract.sh
source "$CONTRACT"
deploy_render_unit "$UNIT_TEMPLATE" miniops 0 > "$TMP_ROOT/default.service"
assert_contains "$TMP_ROOT/default.service" 'User=miniops'
assert_contains "$TMP_ROOT/default.service" 'Group=miniops'
assert_contains "$TMP_ROOT/default.service" 'ProtectSystem=strict'
assert_contains "$TMP_ROOT/default.service" 'ProtectHome=true'
assert_contains "$TMP_ROOT/default.service" 'ReadWritePaths=/var/lib/mini-ops /run/mini-ops'
assert_not_contains "$TMP_ROOT/default.service" 'SupplementaryGroups=docker'
assert_not_contains "$TMP_ROOT/default.service" 'ReadWritePaths=/opt/mini-ops'

deploy_render_unit "$UNIT_TEMPLATE" miniops 1 > "$TMP_ROOT/docker.service"
assert_contains "$TMP_ROOT/docker.service" 'SupplementaryGroups=docker'

deploy_render_nginx 3000 8090 0 '' > "$TMP_ROOT/loopback.nginx"
assert_contains "$TMP_ROOT/loopback.nginx" 'listen 127.0.0.1:8090;'
assert_contains "$TMP_ROOT/loopback.nginx" 'proxy_pass http://127.0.0.1:3000;'
assert_contains "$TMP_ROOT/loopback.nginx" 'server_tokens off;'
assert_contains "$TMP_ROOT/loopback.nginx" "frame-ancestors 'none'"
assert_contains "$TMP_ROOT/loopback.nginx" 'add_header X-Content-Type-Options "nosniff" always;'
assert_contains "$TMP_ROOT/loopback.nginx" 'add_header X-Frame-Options "DENY" always;'
assert_contains "$TMP_ROOT/loopback.nginx" 'add_header Referrer-Policy "no-referrer" always;'
assert_contains "$TMP_ROOT/loopback.nginx" 'add_header Permissions-Policy "camera=(), geolocation=(), microphone=(), payment=(), usb=()" always;'
assert_contains "$TMP_ROOT/loopback.nginx" 'add_header Cross-Origin-Opener-Policy "same-origin" always;'
assert_contains "$TMP_ROOT/loopback.nginx" 'add_header Cross-Origin-Resource-Policy "same-origin" always;'
assert_not_contains "$TMP_ROOT/loopback.nginx" 'Strict-Transport-Security'
deploy_render_nginx 3000 8090 1 '' > "$TMP_ROOT/public.nginx"
assert_contains "$TMP_ROOT/public.nginx" 'listen 8090;'
assert_not_contains "$TMP_ROOT/public.nginx" 'listen 127.0.0.1:8090;'
assert_contains "$TMP_ROOT/public.nginx" "frame-ancestors 'none'"
assert_contains "$TMP_ROOT/public.nginx" 'add_header X-Frame-Options "DENY" always;'
assert_not_contains "$TMP_ROOT/public.nginx" 'Strict-Transport-Security'

deploy_render_nginx 3000 8090 0 172.17.0.1 > "$TMP_ROOT/edge.nginx"
assert_contains "$TMP_ROOT/edge.nginx" 'listen 127.0.0.1:8090;'
assert_contains "$TMP_ROOT/edge.nginx" 'listen 172.17.0.1:8090;'
assert_not_contains "$TMP_ROOT/edge.nginx" 'listen 8090;'

if command -v systemd-analyze >/dev/null 2>&1; then
    sed \
        -e 's#^User=.*#User=root#' \
        -e 's#^Group=.*#Group=root#' \
        -e 's#^WorkingDirectory=.*#WorkingDirectory=/tmp#' \
        -e 's#^ExecStart=.*#ExecStart=/bin/true#' \
        -e 's#^EnvironmentFile=.*#EnvironmentFile=-/dev/null#' \
        "$TMP_ROOT/default.service" > "$TMP_ROOT/parser.service"
    systemd-analyze verify "$TMP_ROOT/parser.service" > "$TMP_ROOT/systemd-parser.out" 2>&1 ||
        fail 'systemd parser rejected the rendered unit'
fi

if command -v nginx >/dev/null 2>&1; then
    mkdir -p "$TMP_ROOT/nginx-prefix/logs"
    {
        printf 'pid %s/nginx.pid;\n' "$TMP_ROOT/nginx-prefix"
        printf 'error_log %s/logs/error.log;\n' "$TMP_ROOT/nginx-prefix"
        printf 'events {}\n'
        printf 'http {\n'
        printf '  access_log off;\n'
        sed 's/^/  /' "$TMP_ROOT/loopback.nginx"
        printf '}\n'
    } > "$TMP_ROOT/nginx.conf"
    nginx -t -p "$TMP_ROOT/nginx-prefix" -c "$TMP_ROOT/nginx.conf" > "$TMP_ROOT/nginx-parser.out" 2>&1 ||
        fail 'Nginx parser rejected the rendered loopback site'
fi

# Regression proof for the critical shell semantic: `exit` bypasses ERR but is
# caught by the same armed EXIT pattern used by app and UFW transactions.
EXIT_MARKER="$TMP_ROOT/exit-rollback-called"
if EXIT_MARKER="$EXIT_MARKER" /bin/bash -c '
    set -euo pipefail
    armed=1
    rollback_on_exit() {
        status=$?
        trap - EXIT
        if [[ "$status" != 0 && "$armed" == 1 ]]; then
            printf called > "$EXIT_MARKER"
        fi
        exit "$status"
    }
    trap rollback_on_exit EXIT
    exit 23
'; then
    fail 'fault fixture unexpectedly succeeded'
fi
[[ -f "$EXIT_MARKER" ]] || fail 'armed EXIT rollback did not run for explicit exit'
assert_contains "$BOOTSTRAP" 'trap rollback_on_exit EXIT'
assert_contains "$BOOTSTRAP" 'trap rollback_now EXIT'
assert_contains "$BOOTSTRAP" 'trap rollback_and_fail EXIT'
assert_not_contains "$BOOTSTRAP" 'trap rollback ERR'
assert_not_contains "$BOOTSTRAP" 'trap rollback_now ERR'

for legacy in deploy.sh provision.sh; do
    if /bin/bash "$PROJECT_ROOT/scripts/$legacy" > "$TMP_ROOT/$legacy.out" 2> "$TMP_ROOT/$legacy.err"; then
        fail "$legacy unexpectedly succeeded"
    fi
    [[ ! -s "$TMP_ROOT/$legacy.out" ]] || fail "$legacy wrote to stdout"
    assert_contains "$TMP_ROOT/$legacy.err" 'disabled before build/network activity'
    assert_contains "$TMP_ROOT/$legacy.err" 'scripts/bootstrap_server.sh'
done

printf '%s\n' 'bootstrap contract fixtures: PASS'
