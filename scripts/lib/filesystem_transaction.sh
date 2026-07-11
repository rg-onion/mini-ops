#!/bin/bash

# Rootless-testable filesystem primitives used by the privileged deploy
# transaction. Callers provide lifecycle/EXIT traps and a private snapshot root.

tx_safe_key() {
    [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]
}

tx_assert_regular_nofollow() {
    [[ -f "$1" && ! -L "$1" ]]
}

tx_assert_no_symlink_components() {
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
        [[ ! -L "$current" ]] || return 1
    done
}

tx_assert_existing_directory_components() {
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

tx_atomic_install() {
    local source="$1"
    local destination="$2"
    local owner="$3"
    local group="$4"
    local mode="$5"
    local directory
    local temporary

    tx_assert_no_symlink_components "$source" || return 1
    tx_assert_regular_nofollow "$source" || return 1
    directory="$(dirname "$destination")"
    tx_assert_no_symlink_components "$destination" || return 1
    tx_assert_existing_directory_components "$directory" || return 1
    [[ ! -L "$destination" ]] || return 1
    temporary="$(mktemp "$directory/.mini-ops-install.XXXXXXXX")" || return 1
    if ! install -o "$owner" -g "$group" -m "$mode" "$source" "$temporary"; then
        rm -f -- "$temporary"
        return 1
    fi
    sync -f "$temporary" || {
        rm -f -- "$temporary"
        return 1
    }
    mv -fT "$temporary" "$destination" || {
        rm -f -- "$temporary"
        return 1
    }
    sync -f "$directory"
}

tx_snapshot_file() {
    local snapshot="$1"
    local source="$2"
    local key="$3"

    tx_safe_key "$key" || return 1
    [[ -d "$snapshot/files" && ! -L "$snapshot/files" ]] || return 1
    [[ -d "$snapshot/absent" && ! -L "$snapshot/absent" ]] || return 1
    if [[ -e "$source" || -L "$source" ]]; then
        tx_assert_no_symlink_components "$source" || return 1
        tx_assert_regular_nofollow "$source" || return 1
        cp --preserve=all -- "$source" "$snapshot/files/$key"
    else
        : > "$snapshot/absent/$key"
    fi
}

tx_restore_file() {
    local snapshot="$1"
    local destination="$2"
    local key="$3"
    local source="$snapshot/files/$key"

    tx_safe_key "$key" || return 1
    if [[ -f "$source" && ! -L "$source" ]]; then
        tx_atomic_install \
            "$source" \
            "$destination" \
            "$(stat -c %u "$source")" \
            "$(stat -c %g "$source")" \
            "$(stat -c %a "$source")"
    elif [[ -f "$snapshot/absent/$key" && ! -L "$snapshot/absent/$key" ]]; then
        [[ ! -L "$destination" ]] || return 1
        rm -f -- "$destination"
    else
        return 1
    fi
}

tx_verify_restored_file() {
    local snapshot="$1"
    local destination="$2"
    local key="$3"
    local source="$snapshot/files/$key"

    tx_safe_key "$key" || return 1
    if [[ -f "$source" && ! -L "$source" ]]; then
        tx_assert_regular_nofollow "$destination" || return 1
        cmp -s -- "$source" "$destination" || return 1
        [[ "$(stat -c %u:%g:%a "$destination")" == "$(stat -c %u:%g:%a "$source")" ]]
    elif [[ -f "$snapshot/absent/$key" && ! -L "$snapshot/absent/$key" ]]; then
        [[ ! -e "$destination" && ! -L "$destination" ]]
    else
        return 1
    fi
}

tx_snapshot_directory_metadata() {
    local snapshot="$1"
    local directory="$2"
    local key="$3"

    tx_safe_key "$key" || return 1
    if [[ -e "$directory" || -L "$directory" ]]; then
        tx_assert_existing_directory_components "$directory" || return 1
        stat -c '%u %g %a' "$directory" > "$snapshot/directory-$key"
    fi
}

tx_restore_directory_metadata() {
    local snapshot="$1"
    local directory="$2"
    local key="$3"
    local uid
    local gid
    local mode

    tx_safe_key "$key" || return 1
    [[ -f "$snapshot/directory-$key" && ! -L "$snapshot/directory-$key" ]] || return 1
    tx_assert_existing_directory_components "$directory" || return 1
    read -r uid gid mode < "$snapshot/directory-$key"
    [[ "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ && "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
    chown "$uid:$gid" "$directory"
    chmod "$mode" "$directory"
}

tx_sync_snapshot() {
    local snapshot="$1"

    [[ -d "$snapshot" && ! -L "$snapshot" ]] || return 1
    find "$snapshot" -type f -exec sync -f {} +
    sync -f "$snapshot/files"
    sync -f "$snapshot/absent"
    sync -f "$snapshot"
}

tx_assert_no_open_files() {
    local opened
    local path
    local fd
    local -a watched=("$@")

    shopt -s nullglob
    for fd in /proc/[0-9]*/fd/*; do
        opened="$(readlink "$fd" 2>/dev/null)" || continue
        for path in "${watched[@]}"; do
            if [[ "$opened" == "$path" || "$opened" == "$path (deleted)" ]]; then
                return 42
            fi
        done
    done
    return 0
}

tx_assert_no_open_tree() {
    local root="${1%/}"
    local wanted_uid="$2"
    local proc_root="${3:-/proc}"
    local process
    local process_pid
    local process_uid
    local process_status
    local selector_pid=""
    local selector_uid=""
    local selector_seen=0
    local opened
    local fd_directory
    local fd
    local maps
    local line
    local _range _perms _offset _device _inode mapped

    [[ -n "$root" && "$root" == /* ]] || return 2
    case "$wanted_uid" in
        all) ;;
        pid:[0-9]*:[0-9]*)
            selector_pid="${wanted_uid#pid:}"
            selector_uid="${selector_pid#*:}"
            selector_pid="${selector_pid%%:*}"
            [[ "$selector_pid" =~ ^[1-9][0-9]*$ && "$selector_uid" =~ ^[0-9]+$ ]] || return 2
            ;;
        *) [[ "$wanted_uid" =~ ^[0-9]+$ ]] || return 2 ;;
    esac
    [[ "$proc_root" == /* && -d "$proc_root" && ! -L "$proc_root" ]] || return 2
    shopt -s nullglob
    for process in "$proc_root"/[0-9]*; do
        [[ -d "$process" ]] || continue
        if [[ -n "$selector_pid" && "${process##*/}" != "$selector_pid" ]]; then
            continue
        fi
        [[ -z "$selector_pid" ]] || selector_seen=1
        process_status="$process/status"
        if [[ ! -r "$process_status" ]]; then
            [[ ! -d "$process" ]] && continue
            return 43
        fi
        process_uid="$(awk '/^Uid:/{print $5; exit}' "$process_status" 2>/dev/null)" || {
            [[ ! -d "$process" ]] && continue
            return 43
        }
        if [[ ! "$process_uid" =~ ^[0-9]+$ ]]; then
            [[ ! -d "$process" ]] && continue
            return 43
        fi
        if [[ -n "$selector_pid" ]]; then
            process_pid="$(awk '/^Pid:/{print $2; exit}' "$process_status" 2>/dev/null)"
            [[ "$process_pid" == "$selector_pid" && "$process_uid" == "$selector_uid" ]] || return 43
        fi
        # Kernel threads have no userspace cwd, fd table, or file-backed maps.
        grep -Eq '^Kthread:[[:space:]]*1$' "$process_status" 2>/dev/null && continue
        if [[ "$wanted_uid" != all && -z "$selector_pid" ]]; then
            [[ "$process_uid" == "$wanted_uid" ]] || continue
        fi

        fd_directory="$process/fd"
        if [[ ! -d "$fd_directory" || ! -r "$fd_directory" || ! -x "$fd_directory" ]]; then
            grep -Eq '^State:[[:space:]]*Z' "$process_status" 2>/dev/null && continue
            [[ ! -d "$process" ]] && continue
            return 43
        fi
        for fd in "$fd_directory"/*; do
            if ! opened="$(readlink "$fd" 2>/dev/null)"; then
                [[ ! -e "$fd" && ! -L "$fd" ]] && continue
                [[ ! -d "$process" ]] && break
                return 43
            fi
            opened="${opened% (deleted)}"
            if [[ "$opened" == "$root" || "$opened" == "$root/"* ]]; then
                return 42
            fi
        done

        if ! opened="$(readlink "$process/cwd" 2>/dev/null)"; then
            grep -Eq '^State:[[:space:]]*Z' "$process_status" 2>/dev/null && continue
            [[ ! -d "$process" ]] && continue
            return 43
        fi
        opened="${opened% (deleted)}"
        if [[ "$opened" == "$root" || "$opened" == "$root/"* ]]; then
            return 42
        fi

        maps="$process/maps"
        if [[ ! -r "$maps" ]]; then
            [[ ! -d "$process" ]] && continue
            return 43
        fi
        if ! while IFS= read -r line; do
            mapped=""
            read -r _range _perms _offset _device _inode mapped _ <<< "$line"
            [[ -n "$mapped" && "$mapped" == /* ]] || continue
            mapped="${mapped% (deleted)}"
            if [[ "$mapped" == "$root" || "$mapped" == "$root/"* ]]; then
                return 42
            fi
        done 2>/dev/null < "$maps"; then
            [[ ! -d "$process" ]] && continue
            return 43
        fi
    done
    [[ -z "$selector_pid" || "$selector_seen" == 1 ]] || return 43
    return 0
}

tx_resolve_managed_database_url() {
    local configured="$1"
    local basename

    case "$configured" in
        ''|sqlite:mini-ops.db|sqlite://mini-ops.db|sqlite:///var/lib/mini-ops/mini-ops.db)
            printf '%s %s\n' 'sqlite:///var/lib/mini-ops/mini-ops.db' 'mini-ops.db'
            ;;
        sqlite:///var/lib/mini-ops/*)
            basename="${configured#sqlite:///var/lib/mini-ops/}"
            [[ "$basename" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || return 1
            [[ "$basename" != *..* ]] || return 1
            case "$basename" in
                history.json|internal.token|mini-ops-internal.token|*-wal|*-shm|*-journal) return 1 ;;
            esac
            printf '%s %s\n' "$configured" "$basename"
            ;;
        *) return 1 ;;
    esac
}

tx_ufw_status_allows_port() {
    local wanted="$1"

    awk -v wanted="$wanted" '
        $1 == wanted {
            action=$2
            if (action == "(v6)") action=$3
            if (action == "ALLOW") allow++
            else bad++
        }
        END {exit !(allow > 0 && bad == 0)}
    '
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    case "${1:-}" in
        --assert-no-open-files)
            shift
            (( $# > 0 )) || exit 2
            tx_assert_no_open_files "$@"
            ;;
        --assert-no-open-tree)
            shift
            (( $# == 1 )) || exit 2
            # The privileged installer requires a stable stopped-writer view,
            # so even trusted root maintenance processes are scanned strictly.
            tx_assert_no_open_tree "$1" all
            ;;
        --assert-no-open-tree-for-uid)
            shift
            (( $# == 2 )) || exit 2
            tx_assert_no_open_tree "$1" "$2"
            ;;
        --assert-no-open-tree-for-pid)
            shift
            (( $# == 3 )) || exit 2
            tx_assert_no_open_tree "$1" "pid:$2:$3"
            ;;
        *)
            printf 'usage: %s {--assert-no-open-files PATH...|--assert-no-open-tree PATH|--assert-no-open-tree-for-uid PATH UID|--assert-no-open-tree-for-pid PATH PID UID}\n' "$0" >&2
            exit 2
            ;;
    esac
fi
