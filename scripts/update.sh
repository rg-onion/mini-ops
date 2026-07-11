#!/bin/bash
set -Eeuo pipefail
IFS=$'\n\t'

cd "$(dirname "${BASH_SOURCE[0]}")/.."

echo "Starting experimental source build..."

if [ ! -d ".git" ]; then
    echo "Refusing to update: current directory is not a git checkout." >&2
    exit 1
fi

if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "Refusing to update: tracked local changes are present." >&2
    echo "Commit, stash, or deploy a clean checkout before running web-triggered updates." >&2
    exit 1
fi

# 1. Update Code
echo "Pulling latest changes..."
git pull --ff-only

# 2. Build Frontend (if in prod structure)
if [ -d "frontend" ]; then
    echo "Building frontend..."
    if [ -f "frontend/package-lock.json" ]; then
        npm --prefix frontend ci
    else
        npm --prefix frontend install
    fi
    npm --prefix frontend run build
fi

# 3. Build Backend
echo "Building backend..."
# Note: cargo build might take a while.
cargo build --release --locked

echo "Source build complete. Install the built artifact and restart the service to apply it."
# In a real systemd setup, we might do: sudo systemctl restart mini-ops
# Here we just exit with success, hoping the supervisor handles it.
