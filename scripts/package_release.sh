#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)"
cd "$PROJECT_ROOT"

manifest_version="$(awk -F'"' '$1 ~ /^version = / { print $2; exit }' Cargo.toml)"
frontend_version="$(node -p "require('./frontend/package.json').version")"
version="${1:-$manifest_version}"

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.-]+)?$ ]] ||
    { printf 'Invalid release version: %s\n' "$version" >&2; exit 2; }
[[ "$version" == "$manifest_version" && "$version" == "$frontend_version" ]] ||
    { printf 'Cargo/frontend/release versions differ\n' >&2; exit 2; }
grep -Fxq 'publish = false' Cargo.toml ||
    { printf 'Cargo registry publishing must remain disabled\n' >&2; exit 2; }
[[ "$(node -p "require('./frontend/package.json').private")" == "true" ]] ||
    { printf 'Frontend registry publishing must remain disabled\n' >&2; exit 2; }

if [[ -n "${GITHUB_REF_NAME:-}" ]]; then
    [[ "$GITHUB_REF_NAME" == "v${version}" ]] ||
        { printf 'Release tag does not match version\n' >&2; exit 2; }
fi

[[ -z "$(git status --porcelain --untracked-files=no)" ]] ||
    { printf 'Tracked working tree must be clean for release packaging\n' >&2; exit 2; }

binary="${MINI_OPS_RELEASE_BINARY:-target/release/mini-ops}"
[[ -f "$binary" && -x "$binary" && ! -L "$binary" ]] ||
    { printf 'Release binary is missing, non-executable, or a symlink: %s\n' "$binary" >&2; exit 2; }

machine="$(uname -m)"
case "$machine" in
    x86_64) platform="linux-x86_64" ;;
    aarch64) platform="linux-aarch64" ;;
    *) printf 'Unsupported release architecture: %s\n' "$machine" >&2; exit 2 ;;
esac

if command -v file >/dev/null 2>&1; then
    case "$machine" in
        x86_64) file "$binary" | grep -Eq 'ELF 64-bit LSB.*(x86-64|x86_64)' ;;
        aarch64) file "$binary" | grep -Eq 'ELF 64-bit LSB.*(ARM aarch64|aarch64)' ;;
    esac || { printf 'Release binary architecture mismatch\n' >&2; exit 2; }
fi

dist="${MINI_OPS_RELEASE_DIST:-dist}"
name="mini-ops-v${version}-${platform}"
work="$(mktemp -d "${TMPDIR:-/tmp}/mini-ops-release.XXXXXXXX")"
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$dist" "$work/$name/target/release"

git archive --format=tar HEAD -- \
    Cargo.toml Cargo.lock frontend/package.json frontend/package-lock.json \
    .env.example LICENSE README.md README.ru.md docs scripts |
    tar -xf - -C "$work/$name"
install -m 0755 "$binary" "$work/$name/target/release/mini-ops"

epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
[[ "$epoch" =~ ^[0-9]+$ ]] ||
    { printf 'SOURCE_DATE_EPOCH must be an integer\n' >&2; exit 2; }

archive="$dist/${name}.tar.gz"
TZ=UTC tar \
    --sort=name \
    --mtime="@${epoch}" \
    --owner=0 \
    --group=0 \
    --numeric-owner \
    -C "$work" \
    -cf - "$name" |
    gzip -n > "$archive"

(
    cd "$dist"
    sha256sum "$(basename "$archive")" > SHA256SUMS
)

printf 'archive=%s\n' "$archive"
printf 'checksums=%s/SHA256SUMS\n' "$dist"
