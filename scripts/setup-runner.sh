#!/bin/bash
# Setup GitHub Actions self-hosted runner on the VM
# Run this ON the server: bash scripts/setup-runner.sh
#
# Prerequisites:
# - Docker installed and working
# - User in docker group
# - /mnt/docker/phantom exists with the project

set -e

REPO="raiymbek2048/phantom"
RUNNER_DIR="$HOME/actions-runner"
WORK_DIR="/mnt/docker/phantom"

echo "=== PHANTOM GitHub Actions Runner Setup ==="

# Step 1: Get registration token (you need to provide a GitHub PAT)
if [ -z "$GITHUB_TOKEN" ]; then
    echo "Enter your GitHub Personal Access Token (with repo scope):"
    read -s GITHUB_TOKEN
fi

RUNNER_TOKEN=$(curl -s -X POST \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/actions/runners/registration-token" \
    | python3 -c "import sys,json; print(json.load(sys.stdin).get('token',''))")

if [ -z "$RUNNER_TOKEN" ]; then
    echo "ERROR: Failed to get runner token. Check your GitHub token."
    exit 1
fi
echo "Got runner registration token."

# Step 2: Download and extract runner
mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

if [ ! -f ./config.sh ]; then
    echo "Downloading GitHub Actions runner..."
    RUNNER_VERSION="2.322.0"
    curl -sO -L "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
    tar xzf "actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
    rm -f "actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz"
fi

# Step 3: Configure runner
echo "Configuring runner..."
./config.sh --url "https://github.com/$REPO" \
    --token "$RUNNER_TOKEN" \
    --name "phantom-vm" \
    --labels "self-hosted,linux,phantom" \
    --work "$WORK_DIR" \
    --unattended \
    --replace

# Step 4: Install as systemd service
echo "Installing runner as systemd service..."
sudo ./svc.sh install
sudo ./svc.sh start

echo ""
echo "=== Runner installed and running! ==="
echo "Check status: sudo ./svc.sh status"
echo "View logs: journalctl -u actions.runner.${REPO/\//-}.phantom-vm -f"
echo ""
echo "Now push to main branch and the deploy workflow will run automatically."
