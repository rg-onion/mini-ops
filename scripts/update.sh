#!/bin/bash
set -e

echo "Starting update process..."

# 1. Update Code
echo "Pulling latest changes..."
git pull

# 2. Build Frontend (if in prod structure)
if [ -d "frontend" ]; then
    echo "Building frontend..."
    cd frontend
    npm install
    npm run build
    cd ..
fi

# 3. Build Backend
echo "Building backend..."
# Note: cargo build might take a while.
cargo build --release

echo "Update complete. Service restart required."
# In a real systemd setup, we might do: sudo systemctl restart mini-ops
# Here we just exit with success, hoping the supervisor handles it.
