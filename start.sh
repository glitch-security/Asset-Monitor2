#!/usr/bin/env bash
# AssetMonitor — Linux/macOS startup script
# Handles Docker Hub connectivity issues automatically.
#
# Usage:
#   ./start.sh          # First-time setup and start
#   ./start.sh rebuild  # Force image rebuild

set -euo pipefail

BASE_IMAGE="python:3.11-slim"
MIRROR_IMAGE="mirror.gcr.io/library/python:3.11-slim"

step()  { echo "==> $*"; }
ok()    { echo "    OK: $*"; }
warn()  { echo "    WARN: $*"; }
fail()  { echo "    FAIL: $*" >&2; }

# ── 1. Check Docker is running ────────────────────────────────────────────────
step "Checking Docker"
if ! docker info &>/dev/null; then
    fail "Docker is not running. Start Docker Desktop (macOS/Windows) or 'sudo systemctl start docker' (Linux) and retry."
    exit 1
fi
ok "Docker is running"

# ── 2. Ensure the base image is available locally ─────────────────────────────
step "Ensuring base image is available ($BASE_IMAGE)"

if ! docker image inspect "$BASE_IMAGE" &>/dev/null; then
    warn "Base image not cached locally. Trying Docker Hub..."
    if docker pull "$BASE_IMAGE" 2>/dev/null; then
        ok "Pulled from Docker Hub"
    else
        warn "Docker Hub unreachable. Pulling from Google mirror..."
        if ! docker pull "$MIRROR_IMAGE"; then
            fail "Could not pull image from Docker Hub or Google mirror."
            echo ""
            echo "Manual fix options:"
            echo "  1. Configure a Docker registry mirror in /etc/docker/daemon.json:"
            echo '     { "registry-mirrors": ["https://mirror.gcr.io"] }'
            echo "     Then: sudo systemctl restart docker"
            echo "  2. Or run:  docker pull $MIRROR_IMAGE"
            echo "             docker tag  $MIRROR_IMAGE $BASE_IMAGE"
            exit 1
        fi
        docker tag "$MIRROR_IMAGE" "$BASE_IMAGE"
        ok "Pulled from Google mirror and tagged as $BASE_IMAGE"
    fi
else
    ok "Base image already cached"
fi

# ── 3. Create data directory ──────────────────────────────────────────────────
mkdir -p data
# Linux: ensure the non-root UID 1000 inside the container can write the data dir
if [[ "$(uname)" == "Linux" ]]; then
    if ! chown 1000:1000 data 2>/dev/null; then
        sudo chown 1000:1000 data 2>/dev/null || warn "Could not chown data/ to UID 1000. Container may fail to write data."
    fi
fi

# ── 4. Start AssetMonitor ─────────────────────────────────────────────────────
step "Starting AssetMonitor"
docker compose up -d --build

# ── 5. Wait and show credentials ──────────────────────────────────────────────
echo ""
echo "Waiting for container to initialise..."
retries=24  # up to 2 minutes
while (( retries > 0 )); do
    sleep 5
    if curl -sf http://localhost:5000/health &>/dev/null; then
        break
    fi
    (( retries-- )) || true
done

cred_file="data/initial_credentials.txt"
if [[ -f "$cred_file" ]]; then
    echo ""
    echo "─── Initial Credentials ────────────────────────────────"
    cat "$cred_file"
    echo "────────────────────────────────────────────────────────"
    echo "(Delete this file after your first login)"
fi

echo ""
echo "AssetMonitor is running at http://localhost:5000"
