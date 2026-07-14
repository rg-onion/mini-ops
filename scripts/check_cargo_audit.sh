#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
cd "$PROJECT_ROOT"

if (( $# > 1 )) || (( $# == 1 )) && [[ "$1" != "--no-fetch" ]]; then
    printf 'Usage: %s [--no-fetch]\n' "$0" >&2
    exit 2
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/mini-ops-cargo-audit.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT

audit_args=(audit --json)
if (( $# == 1 )); then
    audit_args+=(--no-fetch)
fi

set +e
cargo "${audit_args[@]}" > "$work/audit.json"
audit_status=$?
set -e
if (( audit_status != 0 && audit_status != 1 )); then
    printf 'cargo audit failed before producing a policy report\n' >&2
    exit 1
fi

cargo tree --locked --target all -i spin@0.9.8 --prefix depth --no-dedupe \
    > "$work/dependency-tree.txt"
cargo tree --quiet --locked --target all -i rsa@0.9.10 \
    > "$work/ignored-advisory-tree.txt"
if [[ -s "$work/ignored-advisory-tree.txt" ]]; then
    printf 'Ignored RUSTSEC-2023-0071 package became reachable\n' >&2
    exit 1
fi
node scripts/check_cargo_audit.mjs \
    "$work/audit.json" "$work/dependency-tree.txt"
