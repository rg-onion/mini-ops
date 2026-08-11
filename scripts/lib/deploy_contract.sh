#!/bin/bash

# Shared validation and deterministic render helpers for the managed bootstrap.
# This file is sourced; the caller owns `set -euo pipefail` and lifecycle traps.

deploy_error() {
    printf 'ERROR: %s\n' "$*" >&2
    return 1
}

deploy_warning() {
    printf 'WARNING: %s\n' "$*" >&2
}

deploy_validate_boolean() {
    local name="$1"
    local value="$2"

    case "$value" in
        0|1) ;;
        *) deploy_error "$name must be 0 or 1" ;;
    esac
}

deploy_validate_local_build_toolchain() {
    local node_version="$1"
    local npm_version="$2"

    if [[ ! "$node_version" =~ ^v24\.17\.[0-9]+$ ]]; then
        deploy_error "local Node.js must match v24.17.x for a managed source build"
        return 1
    fi
    if [[ ! "$npm_version" =~ ^12\.0\.[0-9]+$ ]]; then
        deploy_error "local npm must match 12.0.x for a managed source build"
        return 1
    fi
}

deploy_validate_port() {
    local name="$1"
    local value="$2"

    if [[ ! "$value" =~ ^[1-9][0-9]{0,4}$ ]] || (( 10#$value > 65535 )); then
        deploy_error "$name must be an integer between 1 and 65535"
    fi
}

deploy_validate_extra_listen_ip() {
    local value="$1"
    local octet
    local -a octets

    [[ -z "$value" ]] && return 0
    if [[ ! "$value" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        deploy_error "DEPLOY_NGINX_EXTRA_LISTEN_IP must be a canonical IPv4 address"
    fi
    IFS='.' read -r -a octets <<< "$value"
    for octet in "${octets[@]}"; do
        if [[ ! "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || (( 10#$octet > 255 )); then
            deploy_error "DEPLOY_NGINX_EXTRA_LISTEN_IP must be a canonical IPv4 address"
        fi
    done
    if (( 10#${octets[0]} == 0 || 10#${octets[0]} == 127 || 10#${octets[0]} >= 224 )); then
        deploy_error "DEPLOY_NGINX_EXTRA_LISTEN_IP must be a non-wildcard unicast address outside loopback"
    fi
}

deploy_validate_user() {
    local name="$1"
    local value="$2"

    if (( ${#value} > 32 )) || [[ ! "$value" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
        deploy_error "$name must be a valid local account name"
    fi
}

deploy_validate_host() {
    local host="$1"
    local label
    local octet
    local -a labels
    local -a octets

    if [[ "$host" =~ ^[0-9]+(\.[0-9]+){3}$ ]]; then
        IFS='.' read -r -a octets <<< "$host"
        for octet in "${octets[@]}"; do
            if [[ ! "$octet" =~ ^(0|[1-9][0-9]{0,2})$ ]] || (( 10#$octet > 255 )); then
                deploy_error "DEPLOY_HOST contains an invalid IPv4 octet"
            fi
        done
        return 0
    fi

    if (( ${#host} > 253 )) ||
        [[ ! "$host" =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] ||
        [[ "$host" == *..* ]] || [[ "$host" == *.-* ]] || [[ "$host" == *-.* ]]; then
        deploy_error "DEPLOY_HOST must be an IPv4 address or DNS hostname"
    fi
    IFS='.' read -r -a labels <<< "$host"
    for label in "${labels[@]}"; do
        if (( ${#label} < 1 || ${#label} > 63 )); then
            deploy_error "DEPLOY_HOST contains an invalid DNS label length"
        fi
    done
}

deploy_validate_no_control() {
    local name="$1"
    local value="$2"

    if [[ "$value" == *[$'\001'-$'\037'$'\177']* ]]; then
        deploy_error "$name must not contain control characters"
    fi
}

deploy_validate_auth_token() {
    local token="$1"
    local lowered

    deploy_validate_no_control "AUTH_TOKEN" "$token"
    lowered="${token,,}"
    case "$lowered" in
        your_secret_token_here|your_secret_token|your_strong_token|change-me|\
        change-me-strong-random-token|your-random-secure-string-at-least-32-chars|\
        your_auth_token|auth_token|token)
            deploy_error "AUTH_TOKEN must not be a known placeholder"
            ;;
    esac
    if (( ${#token} < 32 )); then
        deploy_error "AUTH_TOKEN must contain at least 32 characters"
    fi
    if [[ ! "$token" =~ ^[A-Za-z0-9._~+/=-]{32,}$ ]]; then
        deploy_error "AUTH_TOKEN must use a dotenv-safe ASCII token alphabet"
    fi
}

deploy_validate_config() {
    local bool_name

    if [[ -z "$DEPLOY_HOST" ]]; then
        deploy_error "DEPLOY_HOST is required"
    fi
    deploy_validate_host "$DEPLOY_HOST"
    deploy_validate_user "DEPLOY_SSH_USER" "$DEPLOY_SSH_USER"
    deploy_validate_user "DEPLOY_APP_USER" "$DEPLOY_APP_USER"
    deploy_validate_port "DEPLOY_SSH_PORT" "$DEPLOY_SSH_PORT"
    deploy_validate_port "DEPLOY_APP_PORT" "$DEPLOY_APP_PORT"
    deploy_validate_port "DEPLOY_NGINX_PORT" "$DEPLOY_NGINX_PORT"
    deploy_validate_extra_listen_ip "$DEPLOY_NGINX_EXTRA_LISTEN_IP"
    deploy_validate_no_control "DEPLOY_TARGET_DIR" "$DEPLOY_TARGET_DIR"

    case "$DEPLOY_MODE" in
        production|test) ;;
        *) deploy_error "DEPLOY_MODE must be production or test" ;;
    esac

    # The managed unit and runtime boundary intentionally have one canonical
    # code root. Accepting arbitrary paths would silently escape its sandbox.
    if [[ "$DEPLOY_TARGET_DIR" != "/opt/mini-ops" ]]; then
        deploy_error "DEPLOY_TARGET_DIR must be the normalized managed path /opt/mini-ops"
    fi

    for bool_name in \
        DEPLOY_INSTALL_DOCKER \
        DEPLOY_ENABLE_DOCKER_INTEGRATION \
        DEPLOY_SETUP_NGINX \
        DEPLOY_EXPOSE_HTTP \
        DEPLOY_ENABLE_SSH_ALERTS \
        DEPLOY_HARDENING \
        DEPLOY_ALLOW_ROOT_SERVICE \
        DEPLOY_ACCEPT_NEW_HOST_KEY \
        DEPLOY_RUN_LOCAL_BUILD \
        DEPLOY_MINIMAL \
        DEPLOY_WRITE_ENV \
        DEPLOY_SYSTEMD_ONLY \
        DEPLOY_DRY_RUN; do
        deploy_validate_boolean "$bool_name" "${!bool_name}"
    done

    if [[ ! "$DEPLOY_UFW_ROLLBACK_SECS" =~ ^[1-9][0-9]{1,2}$ ]] ||
        (( 10#$DEPLOY_UFW_ROLLBACK_SECS < 60 || 10#$DEPLOY_UFW_ROLLBACK_SECS > 600 )); then
        deploy_error "DEPLOY_UFW_ROLLBACK_SECS must be between 60 and 600"
    fi

    if [[ "$DEPLOY_APP_USER" == "root" && "$DEPLOY_ALLOW_ROOT_SERVICE" != "1" ]]; then
        deploy_error "DEPLOY_APP_USER=root requires DEPLOY_ALLOW_ROOT_SERVICE=1"
    fi
    if [[ "$DEPLOY_EXPOSE_HTTP" == "1" && "$DEPLOY_SETUP_NGINX" != "1" ]]; then
        deploy_error "DEPLOY_EXPOSE_HTTP=1 requires DEPLOY_SETUP_NGINX=1; direct app exposure is unsupported"
    fi
    if [[ -n "$DEPLOY_NGINX_EXTRA_LISTEN_IP" && "$DEPLOY_SETUP_NGINX" != "1" ]]; then
        deploy_error "DEPLOY_NGINX_EXTRA_LISTEN_IP requires DEPLOY_SETUP_NGINX=1"
    fi
    if [[ -n "$DEPLOY_NGINX_EXTRA_LISTEN_IP" && "$DEPLOY_EXPOSE_HTTP" == "1" ]]; then
        deploy_error "DEPLOY_NGINX_EXTRA_LISTEN_IP cannot be combined with DEPLOY_EXPOSE_HTTP=1"
    fi
    if [[ "$DEPLOY_SETUP_NGINX" == "1" && "$DEPLOY_APP_PORT" == "$DEPLOY_NGINX_PORT" ]]; then
        deploy_error "DEPLOY_NGINX_PORT must differ from DEPLOY_APP_PORT"
    fi
    if [[ "$DEPLOY_MINIMAL" == "1" || "$DEPLOY_SYSTEMD_ONLY" == "1" ]]; then
        deploy_error "legacy partial deployment modes are disabled because they cannot provide paired rollback"
    fi
    if [[ "$DEPLOY_WRITE_ENV" == "1" ]]; then
        deploy_validate_auth_token "$AUTH_TOKEN"
        deploy_validate_no_control "TELEGRAM_BOT_TOKEN" "$TELEGRAM_BOT_TOKEN"
        deploy_validate_no_control "TELEGRAM_CHAT_ID" "$TELEGRAM_CHAT_ID"
        deploy_validate_no_control "SERVER_NAME" "$SERVER_NAME"
        deploy_validate_no_control "AGENT_LANG" "$AGENT_LANG"
        deploy_validate_no_control "RUST_LOG" "$RUST_LOG"
        if [[ -n "$TELEGRAM_BOT_TOKEN" && ! "$TELEGRAM_BOT_TOKEN" =~ ^[A-Za-z0-9:_-]+$ ]]; then
            deploy_error "TELEGRAM_BOT_TOKEN contains unsupported dotenv characters"
        fi
        if [[ -n "$TELEGRAM_CHAT_ID" && ! "$TELEGRAM_CHAT_ID" =~ ^-?[0-9]+$ ]]; then
            deploy_error "TELEGRAM_CHAT_ID must be numeric"
        fi
    fi
    if [[ -n "$SSH_KEY_PATH" ]]; then
        deploy_validate_no_control "SSH_KEY_PATH" "$SSH_KEY_PATH"
        if [[ "$SSH_KEY_PATH" != /* ]]; then
            deploy_error "SSH_KEY_PATH must be absolute"
        fi
    fi
}

deploy_print_warnings() {
    if [[ "$DEPLOY_APP_USER" == "root" ]]; then
        deploy_warning "root service explicitly enabled; this removes the managed privilege boundary"
    fi
    if [[ "$DEPLOY_ENABLE_DOCKER_INTEGRATION" == "1" ]]; then
        deploy_warning "Docker group integration explicitly enabled; docker group access is root-equivalent"
    fi
    if [[ "$DEPLOY_ACCEPT_NEW_HOST_KEY" == "1" ]]; then
        deploy_warning "accept-new host-key policy explicitly enabled; verify the learned fingerprint out of band"
    fi
    if [[ "$DEPLOY_EXPOSE_HTTP" == "1" ]]; then
        deploy_warning "public wildcard plain-HTTP Nginx listener explicitly enabled"
    fi
    if [[ -n "$DEPLOY_NGINX_EXTRA_LISTEN_IP" ]]; then
        deploy_warning "additional exact plain-HTTP Nginx listener explicitly enabled at ${DEPLOY_NGINX_EXTRA_LISTEN_IP}:${DEPLOY_NGINX_PORT}"
    fi
    if [[ "$DEPLOY_HARDENING" == "1" ]]; then
        deploy_warning "UFW/Fail2Ban mutation explicitly enabled; the bounded rollback transaction is mandatory"
    fi
    if [[ "$DEPLOY_INSTALL_DOCKER" == "1" ]]; then
        deploy_warning "Docker package installation and service enablement explicitly enabled"
    fi
    if [[ "$DEPLOY_ENABLE_SSH_ALERTS" == "1" ]]; then
        deploy_warning "SSH PAM hook mutation explicitly enabled"
    fi
}

deploy_render_unit() {
    local template="$1"
    local app_user="$2"
    local docker_integration="$3"
    local line

    while IFS= read -r line || [[ -n "$line" ]]; do
        case "$line" in
            User=*) printf 'User=%s\n' "$app_user" ;;
            Group=*)
                printf 'Group=%s\n' "$app_user"
                if [[ "$docker_integration" == "1" ]]; then
                    printf 'SupplementaryGroups=docker\n'
                fi
                ;;
            *) printf '%s\n' "$line" ;;
        esac
    done < "$template"
}

deploy_render_nginx() {
    local app_port="$1"
    local nginx_port="$2"
    local expose_http="$3"
    local extra_listen_ip="${4:-}"
    local listen_directives="    listen 127.0.0.1:${nginx_port};"

    if [[ "$expose_http" == "1" ]]; then
        listen_directives="    listen ${nginx_port};"
    elif [[ -n "$extra_listen_ip" ]]; then
        printf -v listen_directives '%s\n    listen %s:%s;' \
            "$listen_directives" "$extra_listen_ip" "$nginx_port"
    fi

    cat <<EOF
server {
${listen_directives}
    server_name _;
    server_tokens off;

    add_header Content-Security-Policy "default-src 'self'; base-uri 'none'; connect-src 'self'; font-src 'self' data:; form-action 'self'; frame-ancestors 'none'; frame-src 'none'; img-src 'self' data:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; worker-src 'none'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    add_header Referrer-Policy "no-referrer" always;
    add_header Permissions-Policy "camera=(), geolocation=(), microphone=(), payment=(), usb=()" always;
    add_header Cross-Origin-Opener-Policy "same-origin" always;
    add_header Cross-Origin-Resource-Policy "same-origin" always;

    location /api/internal/ {
        return 404;
    }

    location / {
        proxy_pass http://127.0.0.1:${app_port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
}

deploy_print_plan() {
    local build_plan="existing-release-artifact:no-local-build"
    local firewall_plan="unchanged"
    local nginx_plan="disabled"
    local docker_plan="unchanged"
    local ssh_alert_plan="disabled"
    local host_key_plan="strict-existing-key"
    local env_plan="preserve-and-normalize-existing"

    if [[ "$DEPLOY_HARDENING" == "1" ]]; then
        firewall_plan="ufw-transaction:ss-port=${DEPLOY_SSH_PORT},rollback=${DEPLOY_UFW_ROLLBACK_SECS}s,fail2ban=enable"
    fi
    if [[ "$DEPLOY_SETUP_NGINX" == "1" ]]; then
        if [[ "$DEPLOY_EXPOSE_HTTP" == "1" ]]; then
            nginx_plan="wildcard-plain-http:${DEPLOY_NGINX_PORT}"
        elif [[ -n "$DEPLOY_NGINX_EXTRA_LISTEN_IP" ]]; then
            nginx_plan="loopback+exact:127.0.0.1:${DEPLOY_NGINX_PORT},${DEPLOY_NGINX_EXTRA_LISTEN_IP}:${DEPLOY_NGINX_PORT}"
        else
            nginx_plan="loopback-only:127.0.0.1:${DEPLOY_NGINX_PORT}"
        fi
    fi
    if [[ "$DEPLOY_INSTALL_DOCKER" == "1" ]]; then
        docker_plan="install-and-enable"
    fi
    if [[ "$DEPLOY_ENABLE_DOCKER_INTEGRATION" == "1" ]]; then
        docker_plan="${docker_plan}+root-equivalent-group-integration"
    fi
    if [[ "$DEPLOY_ENABLE_SSH_ALERTS" == "1" ]]; then
        ssh_alert_plan="explicit-pam-mutation"
    fi
    if [[ "$DEPLOY_ACCEPT_NEW_HOST_KEY" == "1" ]]; then
        host_key_plan="accept-new-explicit"
    fi
    if [[ "$DEPLOY_WRITE_ENV" == "1" ]]; then
        env_plan="replace-from-redacted-local-input"
    fi
    if [[ "$DEPLOY_RUN_LOCAL_BUILD" == "1" ]]; then
        build_plan="frontend:npm-ci-strict(node=24.17.x,npm=12.0.x) backend:cargo-release-locked architecture=artifact-vs-remote"
    fi

    printf '%s\n' 'Mini-Ops managed bootstrap dry-run'
    printf 'remote=%s@%s:%s host-key=%s\n' "$DEPLOY_SSH_USER" "$DEPLOY_HOST" "$DEPLOY_SSH_PORT" "$host_key_plan"
    printf 'mode=%s target=%s app-user=%s app-bind=127.0.0.1:%s\n' \
        "$DEPLOY_MODE" "$DEPLOY_TARGET_DIR" "$DEPLOY_APP_USER" "$DEPLOY_APP_PORT"
    printf 'build=%s\n' "$build_plan"
    printf 'upload=private-unpredictable:/tmp/mini-ops-deploy.XXXXXXXX:0700\n'
    printf 'code=/opt/mini-ops:root:root:0755 env=root:root:0600 unit=root:root:0644\n'
    printf 'state=/var/lib/mini-ops:%s:%s:0700 files:0600 runtime=/run/mini-ops:0700\n' \
        "$DEPLOY_APP_USER" "$DEPLOY_APP_USER"
    printf 'backup=/var/backups/mini-ops:root:root:0700\n'
    printf 'replace=staged-fsync-atomic backup=paired-binary-unit-env-state rollback=automatic-before-health\n'
    printf 'migration=stopped-writer+nofollow+conflict-hard-stop+sqlite-quick-check+legacy-delete-after-health\n'
    printf 'env=%s secrets=redacted managed-db=/var/lib/mini-ops/<validated-single-file> managed-token=/run/mini-ops/internal.token\n' "$env_plan"
    printf 'docker=%s nginx=%s firewall=%s ssh-alerts=%s\n' \
        "$docker_plan" "$nginx_plan" "$firewall_plan" "$ssh_alert_plan"
    printf '%s\n' 'network=not-executed build=not-executed mutation=not-executed'
}
