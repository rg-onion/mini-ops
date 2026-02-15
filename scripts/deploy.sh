#!/bin/bash
set -e

# Configuration
USER="${DEPLOY_USER:-root}"
HOST="${DEPLOY_HOST:-your-server-ip}"
TARGET_DIR="${DEPLOY_TARGET_DIR:-/opt/mini-ops}"
BINARY_PATH="target/release/mini-ops"
SERVICE_NAME="mini-ops"

if [ "$HOST" = "your-server-ip" ]; then
  echo "Set DEPLOY_HOST before running, example:"
  echo "  DEPLOY_HOST=203.0.113.10 ./scripts/deploy.sh"
  exit 1
fi

echo "🚀 Starting Deployment to $HOST..."

# 1. Build Release
echo "📦 Building Release Binary..."
# Ensure frontend is built
cd frontend && npm run build && cd ..
# Build Rust binary
cargo build --release

# 2. Prepare Remote Directory
echo "📂 Preparing Remote Directory..."
ssh $USER@$HOST "mkdir -p $TARGET_DIR"

# 3. Stop Service (if running)
echo "🛑 Stopping Service..."
ssh $USER@$HOST "systemctl stop $SERVICE_NAME || true"

# 4. Upload Binary & Service File
echo "wu Uploading Files..."
scp $BINARY_PATH $USER@$HOST:$TARGET_DIR/mini-ops
scp scripts/mini-ops.service $USER@$HOST:/etc/systemd/system/$SERVICE_NAME.service

# 5. Set Permissions & Reload
echo "🔧 Configuring System..."
ssh $USER@$HOST "chmod +x $TARGET_DIR/mini-ops"
ssh $USER@$HOST "systemctl daemon-reload"
ssh $USER@$HOST "systemctl enable $SERVICE_NAME"
ssh $USER@$HOST "systemctl start $SERVICE_NAME"

echo "✅ Deployment Complete!"
echo "👉 Check logs: ssh $USER@$HOST 'journalctl -u $SERVICE_NAME -f'"
echo "👉 Access at: http://$HOST:3000"
