#!/bin/bash
# Sync Claude Code OAuth token from macOS Keychain to Redis (for Docker)
# Run this after 'claude login' or when token expires.
# Can also add to crontab: */30 * * * * /path/to/sync-claude-token.sh

TOKEN=$(security find-generic-password -s "Claude Code-credentials" -w 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['claudeAiOauth']['accessToken'])" 2>/dev/null)

if [ -z "$TOKEN" ]; then
    echo "ERROR: Could not read Claude Code OAuth token from Keychain."
    echo "Make sure you're logged in: claude login"
    exit 1
fi

docker compose exec -T redis redis-cli SET "phantom:settings:claude_oauth_token" "$TOKEN" > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "OK: Claude OAuth token synced to Redis (${TOKEN:0:14}...)"
else
    echo "ERROR: Failed to write to Redis. Is Docker running?"
    exit 1
fi
