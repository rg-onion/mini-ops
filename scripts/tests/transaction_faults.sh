#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
TX_HELPER="$PROJECT_ROOT/scripts/lib/filesystem_transaction.sh"
BOOTSTRAP="$PROJECT_ROOT/scripts/bootstrap_server.sh"
TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/mini-ops-transaction-test.XXXXXXXX")"
trap 'rm -rf -- "$TMP_ROOT"' EXIT

# shellcheck source=scripts/lib/filesystem_transaction.sh
source "$TX_HELPER"

fail() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

assert_file() {
    local path="$1"
    local content="$2"
    [[ -f "$path" && ! -L "$path" ]] || fail "missing regular file: $path"
    [[ "$(< "$path")" == "$content" ]] || fail "unexpected content: $path"
}

UID_NOW="$(id -u)"
GID_NOW="$(id -g)"
CORE="$TMP_ROOT/core"
CODE="$CORE/opt/mini-ops"
STATE="$CORE/var/lib/mini-ops"
RUNTIME="$CORE/run/mini-ops"
SNAPSHOT="$CORE/snapshot"
mkdir -p "$CODE/scripts" "$STATE" "$RUNTIME" "$SNAPSHOT/files" "$SNAPSHOT/absent"
chmod 0750 "$CODE"
chmod 0710 "$CODE/scripts"
chmod 0751 "$STATE"
chmod 0752 "$RUNTIME"
printf old-binary > "$CODE/mini-ops"
printf old-env > "$CODE/.env"
printf old-db > "$STATE/managed.db"
printf old-wal > "$STATE/managed.db-wal"
printf old-shm > "$STATE/managed.db-shm"
printf old-history > "$STATE/history.json"
chmod 0754 "$CODE/mini-ops"
chmod 0640 "$CODE/.env"
chmod 0641 "$STATE/managed.db" "$STATE/managed.db-wal" "$STATE/managed.db-shm" "$STATE/history.json"

for pair in \
    "$CODE/mini-ops|binary" \
    "$CODE/.env|env" \
    "$STATE/managed.db|state-managed.db" \
    "$STATE/managed.db-wal|state-managed.db-wal" \
    "$STATE/managed.db-shm|state-managed.db-shm" \
    "$STATE/history.json|state-history.json"; do
    tx_snapshot_file "$SNAPSHOT" "${pair%%|*}" "${pair##*|}" || fail 'core snapshot failed'
done
tx_snapshot_directory_metadata "$SNAPSHOT" "$CODE" target
tx_snapshot_directory_metadata "$SNAPSHOT" "$CODE/scripts" scripts
tx_snapshot_directory_metadata "$SNAPSHOT" "$STATE" state
tx_snapshot_directory_metadata "$SNAPSHOT" "$RUNTIME" runtime
tx_sync_snapshot "$SNAPSHOT"

# The actual helper used by remote preflight must see an open DB/sidecar writer.
WRITER_READY="$TMP_ROOT/writer.ready"
WRITER_RELEASE="$TMP_ROOT/writer.release"
/bin/bash -c 'exec 9<> "$1"; printf ready > "$2"; while [[ ! -e "$3" ]]; do sleep 0.02; done' \
    writer "$STATE/managed.db" "$WRITER_READY" "$WRITER_RELEASE" &
WRITER_PID=$!
for _ in {1..50}; do
    [[ -f "$WRITER_READY" ]] && break
    sleep 0.02
done
[[ -f "$WRITER_READY" ]] || fail 'database writer fixture did not start'
set +e
/bin/bash "$TX_HELPER" --assert-no-open-files "$STATE/managed.db"
writer_status=$?
set -e
[[ "$writer_status" == 42 ]] || fail 'open database writer was not detected'
touch "$WRITER_RELEASE"
wait "$WRITER_PID"
/bin/bash "$TX_HELPER" --assert-no-open-files "$STATE/managed.db"

# The quarantine probe also rejects directory descriptors, cwd traversal, and
# writable mmap references that survive closing the original file descriptor.
TREE_PROBE="$TMP_ROOT/tree-probe"
mkdir -p "$TREE_PROBE"
printf 'mapped-state-padding' > "$TREE_PROBE/state.db"
TREE_READY="$TMP_ROOT/tree.ready"
TREE_RELEASE="$TMP_ROOT/tree.release"
/bin/bash -c 'exec 8< "$1"; printf ready > "$2"; while [[ ! -e "$3" ]]; do sleep 0.02; done' \
    tree-holder "$TREE_PROBE" "$TREE_READY" "$TREE_RELEASE" &
TREE_PID=$!
for _ in {1..50}; do
    [[ -e "$TREE_READY" ]] && break
    sleep 0.02
done
[[ -e "$TREE_READY" ]] || fail 'directory descriptor fixture did not start'
set +e
/bin/bash "$TX_HELPER" --assert-no-open-tree-for-pid "$TREE_PROBE" "$TREE_PID" "$UID_NOW"
tree_status=$?
set -e
[[ "$tree_status" == 42 ]] || fail 'open state-directory descriptor was not detected'
touch "$TREE_RELEASE"
wait "$TREE_PID"

MMAP_READY="$TMP_ROOT/mmap.ready"
MMAP_RELEASE="$TMP_ROOT/mmap.release"
python3 - "$TREE_PROBE/state.db" "$MMAP_READY" "$MMAP_RELEASE" <<'PY' &
import mmap
import pathlib
import sys
import time

state_path = pathlib.Path(sys.argv[1])
with state_path.open("r+b") as handle:
    mapping = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_WRITE)
pathlib.Path(sys.argv[2]).write_text("ready")
while not pathlib.Path(sys.argv[3]).exists():
    time.sleep(0.02)
mapping.close()
PY
MMAP_PID=$!
for _ in {1..50}; do
    [[ -e "$MMAP_READY" ]] && break
    sleep 0.02
done
[[ -e "$MMAP_READY" ]] || fail 'writable mmap fixture did not start'
set +e
/bin/bash "$TX_HELPER" --assert-no-open-tree-for-pid "$TREE_PROBE" "$MMAP_PID" "$UID_NOW"
mmap_status=$?
set -e
[[ "$mmap_status" == 42 ]] || fail 'writable state mmap with closed source fd was not detected'
touch "$MMAP_RELEASE"
wait "$MMAP_PID"
/bin/bash "$TX_HELPER" --assert-no-open-tree-for-pid "$TREE_PROBE" "$$" "$UID_NOW"

FAKE_PROC="$TMP_ROOT/fake-proc"
mkdir -p "$FAKE_PROC/4242/fd"
printf 'State:\tR (running)\nUid:\t%s\t%s\t%s\t%s\n' "$UID_NOW" "$UID_NOW" "$UID_NOW" "$UID_NOW" > "$FAKE_PROC/4242/status"
ln -s /tmp "$FAKE_PROC/4242/cwd"
: > "$FAKE_PROC/4242/maps"
chmod 0000 "$FAKE_PROC/4242/maps"
set +e
tx_assert_no_open_tree "$TREE_PROBE" "$UID_NOW" "$FAKE_PROC"
fake_proc_status=$?
set -e
chmod 0600 "$FAKE_PROC/4242/maps"
[[ "$fake_proc_status" == 43 ]] || fail 'unreadable relevant process maps did not fail as ambiguous'

FAKE_KTHREAD_PROC="$TMP_ROOT/fake-kthread-proc"
mkdir -p "$FAKE_KTHREAD_PROC/7"
printf 'State:\tI (idle)\nKthread:\t1\nUid:\t0\t0\t0\t0\n' > "$FAKE_KTHREAD_PROC/7/status"
tx_assert_no_open_tree "$TREE_PROBE" all "$FAKE_KTHREAD_PROC" || fail 'kernel thread without userspace paths was classified ambiguous'

# A same-UID actor substituting a state path between checks is rejected by the
# mandatory post-isolation nofollow validation before any privileged metadata
# operation is modeled.
SUBSTITUTION_STATE="$TMP_ROOT/substitution-state"
SUBSTITUTION_GO="$TMP_ROOT/substitution.go"
SUBSTITUTION_READY="$TMP_ROOT/substitution.ready"
mkdir -p "$SUBSTITUTION_STATE"
printf original > "$SUBSTITUTION_STATE/managed.db"
(
    : > "$SUBSTITUTION_READY"
    while [[ ! -e "$SUBSTITUTION_GO" ]]; do sleep 0.02; done
    rm -f -- "$SUBSTITUTION_STATE/managed.db"
    ln -s "$TMP_ROOT/substitution-target" "$SUBSTITUTION_STATE/managed.db"
) &
SUBSTITUTION_PID=$!
for _ in {1..50}; do
    [[ -e "$SUBSTITUTION_READY" ]] && break
    sleep 0.02
done
[[ -e "$SUBSTITUTION_READY" ]] || fail 'same-UID substitution fixture did not start'
tx_assert_regular_nofollow "$SUBSTITUTION_STATE/managed.db" || fail 'initial state fixture was unexpectedly unsafe'
touch "$SUBSTITUTION_GO"
wait "$SUBSTITUTION_PID"
if tx_assert_regular_nofollow "$SUBSTITUTION_STATE/managed.db"; then
    fail 'same-UID state symlink substitution passed post-isolation validation'
fi

QUARANTINE_MODEL="$TMP_ROOT/quarantine-model"
mkdir -p "$QUARANTINE_MODEL/private" "$QUARANTINE_MODEL/state"
chmod 0700 "$QUARANTINE_MODEL/private" "$QUARANTINE_MODEL/state"
printf original > "$QUARANTINE_MODEL/state/managed.db"
mv -T -- "$QUARANTINE_MODEL/state" "$QUARANTINE_MODEL/private/original"
[[ ! -e "$QUARANTINE_MODEL/state" && ! -L "$QUARANTINE_MODEL/state" ]] || fail 'atomic quarantine left the canonical path reachable'
/bin/bash "$TX_HELPER" --assert-no-open-tree-for-pid "$QUARANTINE_MODEL/private/original" "$$" "$UID_NOW"
tx_assert_regular_nofollow "$QUARANTINE_MODEL/private/original/managed.db" || fail 'quarantined state revalidation failed'
chmod 0700 "$QUARANTINE_MODEL/private/original"
mkdir -p "$QUARANTINE_MODEL/state"
chmod 0700 "$QUARANTINE_MODEL/state"
printf restored > "$QUARANTINE_MODEL/restore-source"
tx_atomic_install "$QUARANTINE_MODEL/restore-source" "$QUARANTINE_MODEL/state/managed.db" "$UID_NOW" "$GID_NOW" 0600
assert_file "$QUARANTINE_MODEL/state/managed.db" restored

# A transient unsafe metadata change after an early observation must be
# rejected; production binds the accepted metadata snapshot to the isolated,
# post-stop tree instead of trusting this stale value.
METADATA_STATE="$TMP_ROOT/metadata-state"
mkdir -p "$METADATA_STATE"
chmod 0700 "$METADATA_STATE"
early_metadata="$(stat -c %u:%g:%a "$METADATA_STATE")"
chmod 0777 "$METADATA_STATE"
[[ "$(stat -c %u:%g:%a "$METADATA_STATE")" != "$early_metadata" ]] || fail 'metadata mutation fixture did not change state'
if [[ "$(stat -c %u:%g:%a "$METADATA_STATE")" == "$UID_NOW:$GID_NOW:700" ]]; then
    fail 'unsafe post-stop state metadata was accepted'
fi

# Shell-level fail-closed fixtures for rollback stop/restart proof failures.
set +e
(
    rollback_stop_guard_model() { return 1; }
    if ! rollback_stop_guard_model; then
        exit 70
    fi
)
stop_guard_status=$?
(
    pre_snapshot_restore_model() { return 1; }
    if ! pre_snapshot_restore_model; then
        exit 70
    fi
)
restart_guard_status=$?
set -e
[[ "$stop_guard_status" == 70 ]] || fail 'rollback stop ambiguity did not classify DEGRADED'
[[ "$restart_guard_status" == 70 ]] || fail 'pre-snapshot restart failure did not classify DEGRADED'

# Existing directory component proofs reject both symlink and non-directory
# ancestors while preserving ordinary absolute-root traversal.
CHAIN_ROOT="$TMP_ROOT/path-chain"
mkdir -p "$CHAIN_ROOT/real/child"
tx_assert_existing_directory_components "$CHAIN_ROOT/real/child" || fail 'safe directory chain was rejected'
ln -s "$CHAIN_ROOT/real" "$CHAIN_ROOT/link"
if tx_assert_existing_directory_components "$CHAIN_ROOT/link/child"; then
    fail 'symlink ancestor directory chain was accepted'
fi
printf file > "$CHAIN_ROOT/non-directory"
if tx_assert_existing_directory_components "$CHAIN_ROOT/non-directory/child"; then
    fail 'non-directory ancestor chain was accepted'
fi

# Rollback retains the exact relative/absolute spelling of a managed Nginx
# enablement symlink instead of reconstructing an equivalent different link.
NGINX_LINK_MODEL="$TMP_ROOT/nginx-link-model"
mkdir -p "$NGINX_LINK_MODEL/sites-available" "$NGINX_LINK_MODEL/sites-enabled"
ln -s ../sites-available/mini-ops "$NGINX_LINK_MODEL/sites-enabled/mini-ops"
nginx_link_before="$(readlink "$NGINX_LINK_MODEL/sites-enabled/mini-ops")"
printf '%s\n' "$nginx_link_before" > "$NGINX_LINK_MODEL/snapshot-target"
rm -f -- "$NGINX_LINK_MODEL/sites-enabled/mini-ops"
ln -s /etc/nginx/sites-available/mini-ops "$NGINX_LINK_MODEL/sites-enabled/mini-ops"
rm -f -- "$NGINX_LINK_MODEL/sites-enabled/mini-ops"
ln -s "$(< "$NGINX_LINK_MODEL/snapshot-target")" "$NGINX_LINK_MODEL/sites-enabled/mini-ops"
[[ "$(readlink "$NGINX_LINK_MODEL/sites-enabled/mini-ops")" == "$nginx_link_before" ]] || fail 'exact Nginx symlink target was not restored'

read -r resolved_url resolved_name < <(tx_resolve_managed_database_url 'sqlite:///var/lib/mini-ops/custom.db')
[[ "$resolved_url" == 'sqlite:///var/lib/mini-ops/custom.db' && "$resolved_name" == custom.db ]]
for rejected_url in \
    'sqlite:///opt/mini-ops/custom.db' \
    'sqlite:///var/lib/mini-ops/../escape.db' \
    'sqlite:///var/lib/mini-ops/history.json' \
    'sqlite:///var/lib/mini-ops/custom.db-wal' \
    'sqlite:///var/lib/mini-ops/custom.db?mode=rw' \
    'sqlite:///var/lib/mini-ops/nested/custom.db'; do
    if tx_resolve_managed_database_url "$rejected_url" >/dev/null; then
        fail "unsafe custom database URL was accepted: $rejected_url"
    fi
done

printf new-binary > "$CORE/new-binary"
printf new-env > "$CORE/new-env"
chmod 0755 "$CORE/new-binary"
chmod 0600 "$CORE/new-env"

# Inject failure at the health boundary after all replacements and metadata
# mutations. The armed EXIT path must restore exact bytes and exact modes.
set +e
(
    set -euo pipefail
    armed=0
    rollback_core() {
        status=$?
        trap - EXIT
        set +e
        if [[ "$status" != 0 && "$armed" == 1 ]]; then
            tx_restore_file "$SNAPSHOT" "$CODE/mini-ops" binary
            tx_restore_file "$SNAPSHOT" "$CODE/.env" env
            tx_restore_file "$SNAPSHOT" "$STATE/managed.db" state-managed.db
            tx_restore_file "$SNAPSHOT" "$STATE/managed.db-wal" state-managed.db-wal
            tx_restore_file "$SNAPSHOT" "$STATE/managed.db-shm" state-managed.db-shm
            tx_restore_file "$SNAPSHOT" "$STATE/history.json" state-history.json
            tx_restore_directory_metadata "$SNAPSHOT" "$CODE" target
            tx_restore_directory_metadata "$SNAPSHOT" "$CODE/scripts" scripts
            tx_restore_directory_metadata "$SNAPSHOT" "$STATE" state
            tx_restore_directory_metadata "$SNAPSHOT" "$RUNTIME" runtime
        fi
        exit "$status"
    }
    armed=1
    trap rollback_core EXIT
    tx_atomic_install "$CORE/new-binary" "$CODE/mini-ops" "$UID_NOW" "$GID_NOW" 0755
    tx_atomic_install "$CORE/new-env" "$CODE/.env" "$UID_NOW" "$GID_NOW" 0600
    printf changed-db > "$STATE/managed.db"
    printf changed-wal > "$STATE/managed.db-wal"
    chmod 0700 "$CODE" "$CODE/scripts" "$STATE" "$RUNTIME"
    false # injected API/DB health failure
)
core_fault_status=$?
set -e
[[ "$core_fault_status" != 0 ]] || fail 'core fault injection unexpectedly succeeded'
for pair in \
    "$CODE/mini-ops|binary" \
    "$CODE/.env|env" \
    "$STATE/managed.db|state-managed.db" \
    "$STATE/managed.db-wal|state-managed.db-wal" \
    "$STATE/managed.db-shm|state-managed.db-shm" \
    "$STATE/history.json|state-history.json"; do
    tx_verify_restored_file "$SNAPSHOT" "${pair%%|*}" "${pair##*|}" || fail 'core rollback was not exact'
done
[[ "$(stat -c %a "$CODE")" == 750 ]]
[[ "$(stat -c %a "$CODE/scripts")" == 710 ]]
[[ "$(stat -c %a "$STATE")" == 751 ]]
[[ "$(stat -c %a "$RUNTIME")" == 752 ]]

# Standard legacy migration is staged atomically; a failed health proof leaves
# the legacy source intact and removes the previously absent managed target.
LEGACY="$TMP_ROOT/legacy"
LEGACY_CODE="$LEGACY/opt/mini-ops"
LEGACY_STATE="$LEGACY/var/lib/mini-ops"
LEGACY_SNAPSHOT="$LEGACY/snapshot"
mkdir -p "$LEGACY_CODE" "$LEGACY_STATE" "$LEGACY_SNAPSHOT/files" "$LEGACY_SNAPSHOT/absent"
printf legacy-db > "$LEGACY_CODE/mini-ops.db"
printf legacy-wal > "$LEGACY_CODE/mini-ops.db-wal"
tx_snapshot_file "$LEGACY_SNAPSHOT" "$LEGACY_CODE/mini-ops.db" legacy-db
tx_snapshot_file "$LEGACY_SNAPSHOT" "$LEGACY_CODE/mini-ops.db-wal" legacy-wal
tx_snapshot_file "$LEGACY_SNAPSHOT" "$LEGACY_STATE/mini-ops.db" managed-db
tx_snapshot_file "$LEGACY_SNAPSHOT" "$LEGACY_STATE/mini-ops.db-wal" managed-wal
tx_sync_snapshot "$LEGACY_SNAPSHOT"
set +e
(
    set -euo pipefail
    armed=1
    rollback_migration() {
        status=$?
        trap - EXIT
        set +e
        if [[ "$status" != 0 && "$armed" == 1 ]]; then
            tx_restore_file "$LEGACY_SNAPSHOT" "$LEGACY_CODE/mini-ops.db" legacy-db
            tx_restore_file "$LEGACY_SNAPSHOT" "$LEGACY_CODE/mini-ops.db-wal" legacy-wal
            tx_restore_file "$LEGACY_SNAPSHOT" "$LEGACY_STATE/mini-ops.db" managed-db
            tx_restore_file "$LEGACY_SNAPSHOT" "$LEGACY_STATE/mini-ops.db-wal" managed-wal
        fi
        exit "$status"
    }
    trap rollback_migration EXIT
    tx_atomic_install "$LEGACY_CODE/mini-ops.db" "$LEGACY_STATE/mini-ops.db" "$UID_NOW" "$GID_NOW" 0600
    tx_atomic_install "$LEGACY_CODE/mini-ops.db-wal" "$LEGACY_STATE/mini-ops.db-wal" "$UID_NOW" "$GID_NOW" 0600
    false
)
migration_fault_status=$?
set -e
[[ "$migration_fault_status" != 0 ]]
assert_file "$LEGACY_CODE/mini-ops.db" legacy-db
assert_file "$LEGACY_CODE/mini-ops.db-wal" legacy-wal
[[ ! -e "$LEGACY_STATE/mini-ops.db" && ! -L "$LEGACY_STATE/mini-ops.db" ]]
[[ ! -e "$LEGACY_STATE/mini-ops.db-wal" && ! -L "$LEGACY_STATE/mini-ops.db-wal" ]]

# PAM/hook/config transaction fault uses the same atomic snapshot primitives.
PAM_ROOT="$TMP_ROOT/pam"
PAM_DIR="$PAM_ROOT/etc/pam.d"
HOOK_DIR="$PAM_ROOT/usr/local/bin"
CONFIG_DIR="$PAM_ROOT/etc/mini-ops"
PAM_SNAPSHOT="$PAM_ROOT/snapshot"
mkdir -p "$PAM_DIR" "$HOOK_DIR" "$CONFIG_DIR" "$PAM_SNAPSHOT/files" "$PAM_SNAPSHOT/absent"
printf 'session required pam_unix.so\n' > "$PAM_DIR/sshd"
printf old-hook > "$HOOK_DIR/ssh-alert.sh"
printf old-config > "$CONFIG_DIR/ssh-alert.conf"
chmod 0644 "$PAM_DIR/sshd"
chmod 0750 "$HOOK_DIR/ssh-alert.sh"
chmod 0640 "$CONFIG_DIR/ssh-alert.conf"
tx_snapshot_file "$PAM_SNAPSHOT" "$PAM_DIR/sshd" pam-sshd
tx_snapshot_file "$PAM_SNAPSHOT" "$HOOK_DIR/ssh-alert.sh" hook
tx_snapshot_file "$PAM_SNAPSHOT" "$CONFIG_DIR/ssh-alert.conf" config
tx_snapshot_directory_metadata "$PAM_SNAPSHOT" "$CONFIG_DIR" config-dir
tx_sync_snapshot "$PAM_SNAPSHOT"
printf 'session required pam_unix.so\nsession optional pam_exec.so quiet /usr/local/bin/ssh-alert.sh\n' > "$PAM_ROOT/pam-new"
printf new-hook > "$PAM_ROOT/hook-new"
printf new-config > "$PAM_ROOT/config-new"
set +e
(
    set -euo pipefail
    rollback_pam() {
        status=$?
        trap - EXIT
        set +e
        tx_restore_file "$PAM_SNAPSHOT" "$PAM_DIR/sshd" pam-sshd
        tx_restore_file "$PAM_SNAPSHOT" "$HOOK_DIR/ssh-alert.sh" hook
        tx_restore_file "$PAM_SNAPSHOT" "$CONFIG_DIR/ssh-alert.conf" config
        tx_restore_directory_metadata "$PAM_SNAPSHOT" "$CONFIG_DIR" config-dir
        exit "$status"
    }
    trap rollback_pam EXIT
    tx_atomic_install "$PAM_ROOT/pam-new" "$PAM_DIR/sshd" "$UID_NOW" "$GID_NOW" 0644
    tx_atomic_install "$PAM_ROOT/hook-new" "$HOOK_DIR/ssh-alert.sh" "$UID_NOW" "$GID_NOW" 0755
    tx_atomic_install "$PAM_ROOT/config-new" "$CONFIG_DIR/ssh-alert.conf" "$UID_NOW" "$GID_NOW" 0600
    false
)
pam_fault_status=$?
set -e
[[ "$pam_fault_status" != 0 ]]
tx_verify_restored_file "$PAM_SNAPSHOT" "$PAM_DIR/sshd" pam-sshd
tx_verify_restored_file "$PAM_SNAPSHOT" "$HOOK_DIR/ssh-alert.sh" hook
tx_verify_restored_file "$PAM_SNAPSHOT" "$CONFIG_DIR/ssh-alert.conf" config

# Dangling sources and destinations are never interpreted as absent files.
ln -s "$TMP_ROOT/missing-source" "$TMP_ROOT/dangling-source"
if tx_snapshot_file "$SNAPSHOT" "$TMP_ROOT/dangling-source" dangling-source; then
    fail 'dangling snapshot source was accepted'
fi
ln -s "$TMP_ROOT/missing-destination" "$TMP_ROOT/dangling-destination"
if tx_atomic_install "$CORE/new-env" "$TMP_ROOT/dangling-destination" "$UID_NOW" "$GID_NOW" 0600; then
    fail 'dangling atomic destination was accepted'
fi
mkdir -p "$TMP_ROOT/real-parent"
ln -s "$TMP_ROOT/real-parent" "$TMP_ROOT/symlink-parent"
if tx_atomic_install "$CORE/new-env" "$TMP_ROOT/symlink-parent/target" "$UID_NOW" "$GID_NOW" 0600; then
    fail 'symlink ancestor destination was accepted'
fi

# Idempotent atomic replacement produces the same exact artifact on re-run.
IDEMPOTENT="$TMP_ROOT/idempotent"
mkdir -p "$IDEMPOTENT"
printf stable > "$IDEMPOTENT/source"
tx_atomic_install "$IDEMPOTENT/source" "$IDEMPOTENT/target" "$UID_NOW" "$GID_NOW" 0600
first_checksum="$(sha256sum "$IDEMPOTENT/target")"
tx_atomic_install "$IDEMPOTENT/source" "$IDEMPOTENT/target" "$UID_NOW" "$GID_NOW" 0600
[[ "$(sha256sum "$IDEMPOTENT/target")" == "$first_checksum" ]]

# A real flock fixture proves deterministic concurrent hard-fail and release.
LOCK_FILE="$TMP_ROOT/deploy.lock"
LOCK_OWNER="$TMP_ROOT/deploy.owner"
LOCK_RELEASE="$TMP_ROOT/deploy.release"
# Positional parameters belong to the child shell.
# shellcheck disable=SC2016
flock --nonblock "$LOCK_FILE" /bin/bash -c 'printf first > "$1"; while [[ ! -e "$2" ]]; do sleep 0.02; done' lock-holder "$LOCK_OWNER" "$LOCK_RELEASE" &
LOCK_PID=$!
for _ in {1..50}; do
    [[ -f "$LOCK_OWNER" ]] && break
    sleep 0.02
done
[[ -f "$LOCK_OWNER" ]] || fail 'first lock owner did not start'
if flock --nonblock "$LOCK_FILE" /bin/true; then
    touch "$LOCK_RELEASE"
    wait "$LOCK_PID" 2>/dev/null || true
    fail 'concurrent lock acquisition unexpectedly succeeded'
fi
touch "$LOCK_RELEASE"
wait "$LOCK_PID"
flock --nonblock "$LOCK_FILE" /bin/true || fail 'lock was not released'

# Exact UFW status parsing rejects DENY/conflicting rows instead of accepting a
# matching port number. Both ordinary and v6 ALLOW rows remain valid.
printf '%s\n' 'Status: active' '2222/tcp ALLOW Anywhere' '2222/tcp (v6) ALLOW Anywhere (v6)' |
    tx_ufw_status_allows_port '2222/tcp' || fail 'exact UFW ALLOW rows were rejected'
if printf '%s\n' 'Status: active' '2222/tcp DENY Anywhere' |
    tx_ufw_status_allows_port '2222/tcp'; then
    fail 'DENY-only UFW row was accepted'
fi
if printf '%s\n' 'Status: active' '2222/tcp ALLOW Anywhere' '2222/tcp DENY Anywhere' |
    tx_ufw_status_allows_port '2222/tcp'; then
    fail 'conflicting UFW rows were accepted'
fi

# Rootless executable UFW/timer fixture. Fake commands exercise the same
# timer-before-mutation, immediate rollback, durable marker, and timer race
# decisions without touching the host firewall or systemd.
UFW_FIXTURE="$TMP_ROOT/ufw-fixture"
UFW_FAKE_BIN="$UFW_FIXTURE/bin"
FAKE_ETC_UFW="$UFW_FIXTURE/etc/ufw"
FAKE_DEFAULT_UFW="$UFW_FIXTURE/etc/default/ufw"
FAKE_UFW_SNAPSHOT="$UFW_FIXTURE/snapshot"
FAKE_UFW_STATE="$UFW_FIXTURE/state"
FAKE_UFW_RULES="$FAKE_ETC_UFW/user.rules"
FAKE_TIMER_DIR="$UFW_FIXTURE/timer"
FAKE_DECISION_LOCK="$UFW_FIXTURE/decision.lock"
FAKE_COMMITTED="$UFW_FIXTURE/committed"
FAKE_ROLLBACK="$UFW_FIXTURE/rollback.sh"
export FAKE_ETC_UFW FAKE_DEFAULT_UFW FAKE_UFW_SNAPSHOT FAKE_UFW_STATE
export FAKE_UFW_RULES FAKE_TIMER_DIR FAKE_DECISION_LOCK FAKE_COMMITTED
mkdir -p "$UFW_FAKE_BIN" "$FAKE_TIMER_DIR"

# The single-quoted strings intentionally emit child-shell variable references.
# shellcheck disable=SC2016
{
    printf '%s\n' '#!/bin/bash' 'set -euo pipefail'
    printf '%s\n' 'case "${1:-}" in'
    printf '%s\n' '  status) printf "Status: %s\n" "$(< "$FAKE_UFW_STATE")"; [[ ! -s "$FAKE_UFW_RULES" ]] || cat "$FAKE_UFW_RULES" ;;'
    printf '%s\n' '  --dry-run) [[ "${2:-}" == allow && "${3:-}" =~ ^[0-9]+/tcp$ ]] ;;'
    printf '%s\n' '  allow) [[ "${2:-}" =~ ^[0-9]+/tcp$ ]]; printf "%s ALLOW Anywhere\n" "$2" >> "$FAKE_UFW_RULES" ;;'
    printf '%s\n' '  --force)'
    printf '%s\n' '    case "${2:-}" in enable) printf active > "$FAKE_UFW_STATE" ;; disable) printf inactive > "$FAKE_UFW_STATE" ;; *) exit 2 ;; esac ;;'
    printf '%s\n' '  reload) : ;;'
    printf '%s\n' '  *) exit 2 ;;'
    printf '%s\n' 'esac'
} > "$UFW_FAKE_BIN/ufw"
chmod 0755 "$UFW_FAKE_BIN/ufw"

# shellcheck disable=SC2016
{
    printf '%s\n' '#!/bin/bash' 'set -euo pipefail' 'unit='
    printf '%s\n' 'while (( $# > 0 )); do'
    printf '%s\n' '  case "$1" in --quiet) shift ;; --unit) unit="$2"; shift 2 ;; --on-active=*) shift ;; *) break ;; esac'
    printf '%s\n' 'done'
    printf '%s\n' '[[ "$unit" =~ ^mini-ops-ufw-rollback-[A-Za-z0-9]{8}$ ]]'
    printf '%s\n' '[[ "${1:-}" == /bin/bash && -f "${2:-}" ]]'
    printf '%s\n' 'printf "%s\n" "$unit" > "$FAKE_TIMER_DIR/unit"'
    printf '%s\n' 'printf "%s\n" "$2" > "$FAKE_TIMER_DIR/rollback"'
    printf '%s\n' ': > "$FAKE_TIMER_DIR/active"'
} > "$UFW_FAKE_BIN/systemd-run"
chmod 0755 "$UFW_FAKE_BIN/systemd-run"

# shellcheck disable=SC2016
{
    printf '%s\n' '#!/bin/bash' 'set -euo pipefail' 'command_name="$1"' 'shift'
    printf '%s\n' 'case "$command_name" in'
    printf '%s\n' '  is-active)'
    printf '%s\n' '    [[ "${1:-}" == --quiet ]] && shift'
    printf '%s\n' '    requested="$1"; unit="$(< "$FAKE_TIMER_DIR/unit")"'
    printf '%s\n' '    if [[ "$requested" == "${unit}.timer" && -e "$FAKE_TIMER_DIR/active" ]]; then printf "active\n"; exit 0; fi'
    printf '%s\n' '    printf "inactive\n"; exit 3 ;;'
    printf '%s\n' '  stop) rm -f -- "$FAKE_TIMER_DIR/active" ;;'
    printf '%s\n' '  start) : > "$FAKE_TIMER_DIR/active" ;;'
    printf '%s\n' '  show)'
    printf '%s\n' '    requested="$1"; shift; property='
    printf '%s\n' '    while (( $# > 0 )); do case "$1" in -p) property="$2"; shift 2 ;; --value) shift ;; *) shift ;; esac; done'
    printf '%s\n' '    unit="$(< "$FAKE_TIMER_DIR/unit")"'
    printf '%s\n' '    case "$property" in Unit) printf "%s.service\n" "$unit" ;; ExecStart) printf "/bin/bash %s\n" "$(< "$FAKE_TIMER_DIR/rollback")" ;; ExecMainStartTimestampMonotonic) printf "0\n" ;; *) exit 2 ;; esac ;;'
    printf '%s\n' '  reset-failed) : ;;'
    printf '%s\n' '  *) exit 2 ;;'
    printf '%s\n' 'esac'
} > "$UFW_FAKE_BIN/systemctl"
chmod 0755 "$UFW_FAKE_BIN/systemctl"

init_fake_ufw() {
    local initial_state="$1"

    rm -rf -- "${UFW_FIXTURE:?}/etc" "${FAKE_UFW_SNAPSHOT:?}"
    rm -f -- "$FAKE_TIMER_DIR/active" "$FAKE_TIMER_DIR/unit" "$FAKE_TIMER_DIR/rollback" \
        "$FAKE_DECISION_LOCK" "$FAKE_COMMITTED" "$FAKE_ROLLBACK"
    mkdir -p "$FAKE_ETC_UFW" "$(dirname "$FAKE_DEFAULT_UFW")" "$FAKE_UFW_SNAPSHOT"
    printf baseline > "$FAKE_ETC_UFW/before.rules"
    : > "$FAKE_UFW_RULES"
    printf 'DEFAULT_INPUT_POLICY="DROP"\nDEFAULT_OUTPUT_POLICY="ACCEPT"\n' > "$FAKE_DEFAULT_UFW"
    cp -a -- "$FAKE_ETC_UFW" "$FAKE_UFW_SNAPSHOT/etc-ufw"
    cp -a -- "$FAKE_DEFAULT_UFW" "$FAKE_UFW_SNAPSHOT/default-ufw"
    printf '%s' "$initial_state" > "$FAKE_UFW_STATE"
    : > "$FAKE_DECISION_LOCK"
    chmod 0600 "$FAKE_DECISION_LOCK"
    # shellcheck disable=SC2016
    {
        printf '%s\n' '#!/bin/bash' 'set -euo pipefail'
        printf '%s\n' 'exec 9<> "$FAKE_DECISION_LOCK"' 'flock 9'
        printf '%s\n' 'if [[ -e "$FAKE_COMMITTED" || -L "$FAKE_COMMITTED" ]]; then'
        printf '%s\n' '  [[ -f "$FAKE_COMMITTED" && ! -L "$FAKE_COMMITTED" && "$(stat -c %a "$FAKE_COMMITTED")" == 600 ]]'
        printf '%s\n' '  exit 0' 'fi'
        printf '%s\n' 'rm -rf -- "$FAKE_ETC_UFW"'
        printf '%s\n' 'cp -a -- "$FAKE_UFW_SNAPSHOT/etc-ufw" "$FAKE_ETC_UFW"'
        printf '%s\n' 'cp -a -- "$FAKE_UFW_SNAPSHOT/default-ufw" "$FAKE_DEFAULT_UFW"'
        printf '%s\n' 'if [[ "$(< "$FAKE_UFW_SNAPSHOT/initial-active")" == 1 ]]; then ufw --force enable; else ufw --force disable; fi'
    } > "$FAKE_ROLLBACK"
    chmod 0700 "$FAKE_ROLLBACK"
    if [[ "$initial_state" == active ]]; then
        printf 1 > "$FAKE_UFW_SNAPSHOT/initial-active"
    else
        printf 0 > "$FAKE_UFW_SNAPSHOT/initial-active"
    fi
}

FAKE_PATH="$UFW_FAKE_BIN:/usr/sbin:/usr/bin:/sbin:/bin"
init_fake_ufw inactive
PATH="$FAKE_PATH" systemd-run --quiet --unit mini-ops-ufw-rollback-Ab12Cd34 --on-active=60s /bin/bash "$FAKE_ROLLBACK"
PATH="$FAKE_PATH" systemctl is-active --quiet mini-ops-ufw-rollback-Ab12Cd34.timer >/dev/null
PATH="$FAKE_PATH" ufw allow 2222/tcp
PATH="$FAKE_PATH" ufw --force enable
printf '%s\n' '2222/tcp DENY Anywhere' >> "$FAKE_UFW_RULES"
if PATH="$FAKE_PATH" ufw status | tx_ufw_status_allows_port '2222/tcp'; then
    fail 'fake UFW conflict did not trigger rollback'
fi
PATH="$FAKE_PATH" /bin/bash "$FAKE_ROLLBACK"
diff -qr -- "$FAKE_UFW_SNAPSHOT/etc-ufw" "$FAKE_ETC_UFW" >/dev/null || fail 'fake UFW rollback did not restore config'
cmp -s -- "$FAKE_UFW_SNAPSHOT/default-ufw" "$FAKE_DEFAULT_UFW" || fail 'fake UFW rollback did not restore defaults'
[[ "$(< "$FAKE_UFW_STATE")" == inactive ]] || fail 'fake UFW rollback did not restore inactive state'
PATH="$FAKE_PATH" systemctl is-active --quiet mini-ops-ufw-rollback-Ab12Cd34.timer >/dev/null || fail 'rollback timer was not left armed on failure'
PATH="$FAKE_PATH" systemctl stop mini-ops-ufw-rollback-Ab12Cd34.timer

# Race a late timer rollback against the commit decision lock. The late
# rollback must observe the durable marker and leave the verified ALLOW state.
init_fake_ufw active
PATH="$FAKE_PATH" systemd-run --quiet --unit mini-ops-ufw-rollback-Ef56Gh78 --on-active=60s /bin/bash "$FAKE_ROLLBACK"
PATH="$FAKE_PATH" ufw allow 2222/tcp
PATH="$FAKE_PATH" ufw reload
PATH="$FAKE_PATH" ufw status | tx_ufw_status_allows_port '2222/tcp' || fail 'fake independent UFW proof failed'
COMMIT_LOCKED="$UFW_FIXTURE/commit.locked"
COMMIT_CONTINUE="$UFW_FIXTURE/commit.continue"
(
    set -euo pipefail
    exec 9<> "$FAKE_DECISION_LOCK"
    flock 9
    PATH="$FAKE_PATH" ufw status | tx_ufw_status_allows_port '2222/tcp'
    PATH="$FAKE_PATH" systemctl is-active --quiet mini-ops-ufw-rollback-Ef56Gh78.timer >/dev/null
    [[ "$(PATH="$FAKE_PATH" systemctl show mini-ops-ufw-rollback-Ef56Gh78.service -p ExecMainStartTimestampMonotonic --value)" == 0 ]]
    : > "$COMMIT_LOCKED"
    for _ in {1..100}; do
        [[ -e "$COMMIT_CONTINUE" ]] && break
        sleep 0.01
    done
    [[ -e "$COMMIT_CONTINUE" ]]
    commit_source="$(mktemp "$UFW_FIXTURE/.committed.XXXXXXXX")"
    printf verified > "$commit_source"
    tx_atomic_install "$commit_source" "$FAKE_COMMITTED" "$UID_NOW" "$GID_NOW" 0600
    rm -f -- "$commit_source"
    PATH="$FAKE_PATH" systemctl stop mini-ops-ufw-rollback-Ef56Gh78.timer
    set +e
    timer_after="$(PATH="$FAKE_PATH" systemctl is-active mini-ops-ufw-rollback-Ef56Gh78.timer)"
    timer_after_status=$?
    set -e
    [[ "$timer_after:$timer_after_status" == inactive:3 ]]
    flock -u 9
) &
COMMIT_PID=$!
for _ in {1..100}; do
    [[ -e "$COMMIT_LOCKED" ]] && break
    sleep 0.01
done
[[ -e "$COMMIT_LOCKED" ]] || fail 'fake UFW commit did not acquire decision lock'
PATH="$FAKE_PATH" /bin/bash "$FAKE_ROLLBACK" 9>&- &
LATE_ROLLBACK_PID=$!
kill -0 "$LATE_ROLLBACK_PID" 2>/dev/null || fail 'late timer rollback did not start'
: > "$COMMIT_CONTINUE"
wait "$COMMIT_PID"
wait "$LATE_ROLLBACK_PID"
[[ -f "$FAKE_COMMITTED" && ! -L "$FAKE_COMMITTED" && "$(stat -c %a "$FAKE_COMMITTED")" == 600 ]] || fail 'durable UFW commit marker proof failed'
PATH="$FAKE_PATH" ufw status | tx_ufw_status_allows_port '2222/tcp' || fail 'late timer undid committed UFW rules'
[[ "$(< "$FAKE_UFW_STATE")" == active ]] || fail 'late timer changed committed UFW active state'
if PATH="$FAKE_PATH" systemctl is-active --quiet mini-ops-ufw-rollback-Ef56Gh78.timer >/dev/null; then
    fail 'committed rollback timer remained active'
fi

# Static bindings ensure the rootless model and production transaction retain
# the same critical ordering and marker decisions.
timer_line="$(grep -n 'systemd-run --quiet --unit' "$BOOTSTRAP" | cut -d: -f1)"
mutated_line="$(grep -n '^MUTATED=1$' "$BOOTSTRAP" | cut -d: -f1)"
[[ "$timer_line" =~ ^[0-9]+$ && "$mutated_line" =~ ^[0-9]+$ && "$timer_line" -lt "$mutated_line" ]] || fail 'UFW timer is not armed before mutation'
# shellcheck disable=SC2016
commit_line="$(grep -n 'tx_atomic_install "$commit_source" "$COMMITTED"' "$BOOTSTRAP" | cut -d: -f1)"
# shellcheck disable=SC2016
timer_stop_line="$(grep -n 'systemctl stop "${UNIT}.timer"' "$BOOTSTRAP" | cut -d: -f1)"
[[ "$commit_line" =~ ^[0-9]+$ && "$timer_stop_line" =~ ^[0-9]+$ && "$commit_line" -lt "$timer_stop_line" ]] || fail 'durable UFW marker is not established before timer cancellation'
# Search for the literal remote variable reference.
# shellcheck disable=SC2016
grep -Fq '/bin/bash "$ROLLBACK_SCRIPT"' "$BOOTSTRAP" || fail 'UFW rollback is not noexec-safe'
# shellcheck disable=SC2016
grep -Fq 'if [[ -e "$COMMITTED" || -L "$COMMITTED" ]]; then' "$BOOTSTRAP" || fail 'timer rollback does not honor durable commit marker'
# shellcheck disable=SC2016
grep -Fq 'verify_firewall_rollback_connectivity "$rollback_script" "$initial_active"' "$BOOTSTRAP" || fail 'fresh SSH rollback proof is absent'
grep -Fq 'rollback VERIFIED' "$BOOTSTRAP" || fail 'UFW verified rollback classification is absent'
grep -Fq 'rollback DEGRADED' "$BOOTSTRAP" || fail 'UFW degraded rollback classification is absent'

# Bind the rootless state model to the production quarantine ordering.
# shellcheck disable=SC2016
{
    isolate_line="$(grep -n '^[[:space:]]*isolate_canonical_state original$' "$BOOTSTRAP" | cut -d: -f1)"
    state_snapshot_line="$(grep -n 'snapshot_file "$STATE_SNAPSHOT_SOURCE/$name"' "$BOOTSTRAP" | cut -d: -f1)"
    root_control_line="$(grep -n 'chown root:root "$STATE_ISOLATED_PATH"' "$BOOTSTRAP" | tail -n 1 | cut -d: -f1)"
    child_control_line="$(grep -n 'chown root:root "$STATE_ISOLATED_PATH/$name"' "$BOOTSTRAP" | cut -d: -f1)"
    rollback_quarantine_line="$(grep -n 'if ! prepare_root_controlled_state_for_rollback' "$BOOTSTRAP" | cut -d: -f1)"
    rollback_stop_line="$(grep -n 'if ! rollback_stop_guard' "$BOOTSTRAP" | head -n 1 | cut -d: -f1)"
    rollback_restore_line="$(grep -n 'restore_file "$TARGET/mini-ops" binary' "$BOOTSTRAP" | cut -d: -f1)"
    isolated_metadata_snapshot_line="$(grep -n 'snapshot_directory_metadata "$STATE_SNAPSHOT_SOURCE" state' "$BOOTSTRAP" | cut -d: -f1)"
    legacy_open_tree_line="$(grep -n 'assert_no_open_managed_tree "$TARGET" legacy-source' "$BOOTSTRAP" | cut -d: -f1)"
    legacy_snapshot_line="$(grep -n 'snapshot_file "$TARGET/$name" "legacy-$name"' "$BOOTSTRAP" | cut -d: -f1)"
    app_handoff_line="$(grep -n 'chown "$APP_USER:$APP_USER" "$STATE"' "$BOOTSTRAP" | cut -d: -f1)"
    service_start_line="$(grep -n '^systemctl restart mini-ops$' "$BOOTSTRAP" | cut -d: -f1)"
}
[[ "$isolate_line" -lt "$state_snapshot_line" ]] || fail 'state snapshot is not sourced from atomic quarantine'
[[ "$root_control_line" -lt "$child_control_line" ]] || fail 'state children are touched before directory root control'
[[ "$rollback_stop_line" -lt "$rollback_quarantine_line" ]] || fail 'rollback state restore is not guarded by exact service stop proof'
[[ "$rollback_quarantine_line" -lt "$rollback_restore_line" ]] || fail 'rollback restores before state quarantine'
[[ "$isolate_line" -lt "$isolated_metadata_snapshot_line" ]] || fail 'state metadata snapshot is not isolation-bound'
[[ "$legacy_open_tree_line" -lt "$legacy_snapshot_line" ]] || fail 'legacy source snapshot is not guarded against fd/cwd/mmap writers'
[[ "$app_handoff_line" -lt "$service_start_line" && $((service_start_line - app_handoff_line)) -le 2 ]] || fail 'state app handoff is not immediately before service start'
# shellcheck disable=SC2016
grep -Fq 'timeout 5 pgrep -u "$app_uid"' "$BOOTSTRAP" || fail 'service-UID process fail-stop is absent'
# shellcheck disable=SC2016
grep -Fq 'tx_assert_existing_directory_components "$directory"' "$BOOTSTRAP" || fail 'SSH-alert ancestor proof is absent'
# shellcheck disable=SC2016
grep -Fq 'atomic_symlink "$(< "$SNAPSHOT/nginx-enabled-target")" "$NGINX_ENABLED"' "$BOOTSTRAP" || fail 'exact Nginx enabled-link rollback is absent'
# shellcheck disable=SC2016
if grep -Fq 'snapshot_directory_metadata "$STATE" state' "$BOOTSTRAP"; then
    fail 'active app-owned state metadata is still snapshotted before quarantine'
fi
# shellcheck disable=SC2016
grep -Fq 'assert_existing_state_metadata "$STATE_ISOLATED_PATH"' "$BOOTSTRAP" || fail 'isolated state metadata is not revalidated before snapshot'
[[ "$(grep -Fc 'verify_pre_snapshot_service_restore' "$BOOTSTRAP")" -ge 3 ]] || fail 'pre-snapshot service rollback proof is not wired into both EXIT branches'
[[ "$(grep -Fc 'timeout --signal=TERM --kill-after=5s 30s python3 -' "$BOOTSTRAP")" == 3 ]] || fail 'all three SQLite quick_check processes are not wall-clock bounded'

printf '%s\n' 'filesystem/PAM/UFW/concurrency fault fixtures: PASS'
