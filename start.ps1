#!/usr/bin/env pwsh
# AssetMonitor — Windows startup script
# Handles Docker Hub connectivity issues automatically (no admin rights required).
#
# Usage:
#   .\start.ps1            # First-time setup and start
#   .\start.ps1 -Rebuild   # Force image rebuild

param(
    [switch]$Rebuild
)

$ErrorActionPreference = "Stop"
$BASE_IMAGE = "python:3.11-slim"
$MIRROR_IMAGE = "mirror.gcr.io/library/python:3.11-slim"

function Write-Step([string]$msg) { Write-Host "==> $msg" -ForegroundColor Cyan }
function Write-Ok([string]$msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Warn([string]$msg) { Write-Host "    WARN: $msg" -ForegroundColor Yellow }
function Write-Fail([string]$msg) { Write-Host "    FAIL: $msg" -ForegroundColor Red }

# ── 1. Check Docker is running ────────────────────────────────────────────────
Write-Step "Checking Docker"
try {
    docker info 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
    Write-Ok "Docker is running"
} catch {
    Write-Fail "Docker is not running. Start Docker Desktop and retry."
    exit 1
}

# ── 2. Ensure the base image is available locally ─────────────────────────────
Write-Step "Ensuring base image is available ($BASE_IMAGE)"

$imageExists = (docker images -q $BASE_IMAGE 2>&1) -ne ""

if (-not $imageExists) {
    Write-Warn "Base image not cached locally. Trying Docker Hub..."

    docker pull $BASE_IMAGE 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Ok "Pulled from Docker Hub"
    } else {
        Write-Warn "Docker Hub unreachable. Pulling from Google mirror..."
        docker pull $MIRROR_IMAGE
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Could not pull image from Docker Hub or Google mirror."
            Write-Host ""
            Write-Host "Manual fix options:" -ForegroundColor Yellow
            Write-Host "  1. Configure a Docker registry mirror via Docker Desktop > Settings > Docker Engine:"
            Write-Host '     { "registry-mirrors": ["https://mirror.gcr.io"] }'
            Write-Host "  2. Or run:  docker pull $MIRROR_IMAGE"
            Write-Host "             docker tag  $MIRROR_IMAGE $BASE_IMAGE"
            exit 1
        }
        docker tag $MIRROR_IMAGE $BASE_IMAGE
        if ($LASTEXITCODE -ne 0) {
            Write-Fail "Failed to tag mirror image."
            exit 1
        }
        Write-Ok "Pulled from Google mirror and tagged as $BASE_IMAGE"
    }
} else {
    Write-Ok "Base image already cached"
}

# ── 3. Create data directory ──────────────────────────────────────────────────
if (-not (Test-Path "data")) {
    New-Item -ItemType Directory -Path "data" | Out-Null
}

# ── 4. Start AssetMonitor ─────────────────────────────────────────────────────
Write-Step "Starting AssetMonitor"

if ($Rebuild) {
    docker compose up -d --build
} else {
    docker compose up -d --build
}

if ($LASTEXITCODE -ne 0) {
    Write-Fail "docker compose failed. See output above."
    exit 1
}

# ── 5. Wait and show credentials ──────────────────────────────────────────────
Write-Host ""
Write-Host "Waiting for container to initialise..." -ForegroundColor Yellow
$retries = 24   # up to 2 minutes
while ($retries -gt 0) {
    Start-Sleep -Seconds 5
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:5000/health" -UseBasicParsing -TimeoutSec 3 -ErrorAction SilentlyContinue
        if ($response.StatusCode -eq 200) { break }
    } catch {}
    $retries--
}

$credFile = "data\initial_credentials.txt"
if (Test-Path $credFile) {
    Write-Host ""
    Write-Host "─── Initial Credentials ──────────────────────────────" -ForegroundColor Cyan
    Get-Content $credFile
    Write-Host "──────────────────────────────────────────────────────" -ForegroundColor Cyan
    Write-Host "(Delete this file after your first login)" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "AssetMonitor is running at http://localhost:5000" -ForegroundColor Green
