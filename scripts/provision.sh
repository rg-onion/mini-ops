#!/bin/bash
set -e

# Configuration
USER="${DEPLOY_USER:-root}"
HOST="${DEPLOY_HOST:-your-server-ip}"
TARGET_DIR="${DEPLOY_TARGET_DIR:-/opt/mini-ops}"
REPO_URL="${DEPLOY_REPO_URL:-https://github.com/rg-onion/mini-ops.git}"
# Assuming we are pushing local git to remote or just cloning? 
# If private repo, we need keys. 
# For now, let's assume we copy the local directory (rsync) to allow "git pull" if it's initialized?
# Or properly: Server generates key, add to GitHub.
# Easier MVP: rsync the whole project folder (including .git) to server.

if [ "$HOST" = "your-server-ip" ]; then
  echo "Set DEPLOY_HOST before running, example:"
  echo "  DEPLOY_HOST=203.0.113.10 ./scripts/provision.sh"
  exit 1
fi

echo "🚀 Provisioning $HOST..."

# 1. Install Dependencies (Rust, Node, Docker)
echo "📦 Installing Dependencies on Server..."
ssh $USER@$HOST "apt-get update && apt-get install -y curl build-essential git gcc pkg-config libssl-dev"
# Install Rust
ssh $USER@$HOST "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
# Install Node (for frontend build)
ssh $USER@$HOST "curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && apt-get install -y nodejs"
# Install Docker (if not exists)
# ssh $USER@$HOST "curl -fsSL https://get.docker.com | sh" 

# Determine project root (assuming script is in scripts/ or project root)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 2. Upload Project files (rsync is better than git clone for private repos/local state)
echo "file_folder Uploading Project Source from $PROJECT_ROOT..."
rsync -avz --exclude 'target' --exclude 'node_modules' --exclude '.env' "$PROJECT_ROOT/" $USER@$HOST:$TARGET_DIR

# 3. Create .env file (Only if missing, to preserve AUTH_TOKEN)
echo "🔑 Confguring .env..."
ssh $USER@$HOST "if [ ! -f $TARGET_DIR/.env ]; then
  cat > $TARGET_DIR/.env <<EOF
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
DATABASE_URL=sqlite:mini-ops.db
SERVER_NAME=\$(hostname)
RUST_LOG=info
AGENT_LANG=ru
# AUTH_TOKEN generated on first run
EOF
else
  echo 'Skipping .env creation (file exists). Preserving AUTH_TOKEN.'
  # Ensure SERVER_NAME exists even if .env exists (append if missing)
  grep -q 'SERVER_NAME=' $TARGET_DIR/.env || echo \"SERVER_NAME=\$(hostname)\" >> $TARGET_DIR/.env
  grep -q 'RUST_LOG=' $TARGET_DIR/.env || echo \"RUST_LOG=info\" >> $TARGET_DIR/.env
  grep -q 'AGENT_LANG=' $TARGET_DIR/.env || echo \"AGENT_LANG=ru\" >> $TARGET_DIR/.env
fi"

# 4. Build on Server (First time)
echo "🔨 Building on Server (this may take time)..."
# We run build manually to avoid 'git pull' issues on first run (since we just rsynced the code)
ssh $USER@$HOST "cd $TARGET_DIR && source \$HOME/.cargo/env && (cd frontend && npm install && npm run build) && cargo build --release"

# 5. Setup Systemd
echo "⚙️ Setting up Systemd..."
ssh $USER@$HOST "cat > /etc/systemd/system/mini-ops.service <<EOF
[Unit]
Description=Mini-Ops Agent
After=network.target docker.service

[Service]
User=root
WorkingDirectory=$TARGET_DIR
ExecStart=$TARGET_DIR/target/release/mini-ops
Restart=always
EnvironmentFile=$TARGET_DIR/.env
Environment=PATH=/root/.cargo/bin:/usr/bin:/usr/local/bin

[Install]
WantedBy=multi-user.target
EOF"

ssh $USER@$HOST "systemctl daemon-reload && systemctl enable mini-ops && systemctl restart mini-ops"

echo "✅ Provisioning Complete!"
echo "👉 Access at http://$HOST:3000"
