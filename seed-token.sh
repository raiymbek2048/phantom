#!/bin/bash
# Seed PHANTOM with Claude refresh token (one-time setup).
#
# Run this on any machine with Claude CLI logged in:
#   ./seed-token.sh <PHANTOM_API_URL>
#
# Example:
#   ./seed-token.sh http://10.99.7.53
#
# Or on the server itself, extract from Claude credentials:
#   ./seed-token.sh local

set -e

PHANTOM_URL="${1:-http://localhost}"

# --- Extract refresh token ---

# Try macOS Keychain first (Claude Desktop / Claude Code on Mac)
REFRESH_TOKEN=""
if command -v security &>/dev/null; then
    REFRESH_TOKEN=$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['claudeAiOauth']['refreshToken'])" 2>/dev/null || true)
fi

# Try Linux Claude credentials file
if [ -z "$REFRESH_TOKEN" ]; then
    CREDS_FILE="$HOME/.claude/.credentials.json"
    if [ -f "$CREDS_FILE" ]; then
        REFRESH_TOKEN=$(python3 -c "
import json
with open('$CREDS_FILE') as f:
    data = json.load(f)
oauth = data.get('claudeAiOauth', {})
print(oauth.get('refreshToken', ''))
" 2>/dev/null || true)
    fi
fi

if [ -z "$REFRESH_TOKEN" ] || [[ ! "$REFRESH_TOKEN" == sk-ant-ort* ]]; then
    echo "ERROR: Could not find Claude refresh token."
    echo "Make sure you're logged in: claude login"
    exit 1
fi

echo "Found refresh token: ${REFRESH_TOKEN:0:25}..."

# --- Seed to PHANTOM ---

if [ "$PHANTOM_URL" = "local" ]; then
    # Direct Redis write (on server)
    echo "Writing directly to Redis..."
    docker compose exec -T redis redis-cli SET "phantom:settings:claude_refresh_token" "$REFRESH_TOKEN" > /dev/null 2>&1
    echo "OK: Refresh token written to Redis."
    echo "PHANTOM will auto-refresh the access token every hour."
else
    # Via API
    echo "Sending to PHANTOM API at $PHANTOM_URL..."

    # Login first
    LOGIN_RESP=$(curl -s -X POST "$PHANTOM_URL/api/auth/login" \
        -H "Content-Type: application/x-www-form-urlencoded" \
        -d "username=admin&password=changeme")
    JWT=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)

    if [ -z "$JWT" ]; then
        echo "ERROR: Could not login to PHANTOM API. Check URL and credentials."
        echo "Response: $LOGIN_RESP"
        exit 1
    fi

    # Seed token
    RESP=$(curl -s -X POST "$PHANTOM_URL/api/training/settings/claude-refresh-token" \
        -H "Authorization: Bearer $JWT" \
        -H "Content-Type: application/json" \
        -d "{\"refresh_token\": \"$REFRESH_TOKEN\"}")

    echo "Response: $RESP"
fi
