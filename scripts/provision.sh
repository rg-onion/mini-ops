#!/bin/bash
set -euo pipefail

printf '%s\n' \
    'provision.sh is disabled before build/network activity: use scripts/bootstrap_server.sh and start with DEPLOY_DRY_RUN=1.' >&2
exit 1
