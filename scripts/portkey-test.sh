#!/usr/bin/env bash
# Quick connectivity test for Portkey.ai AI Gateway
set -euo pipefail

PORTKEY_API_KEY="$(op read 'op://Dev Keys/Portkey AI API Key/credential')"

echo "Testing Portkey.ai connection..."

curl -s https://api.portkey.ai/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "x-portkey-api-key: $PORTKEY_API_KEY" \
  -d '{
    "model": "gpt-4o",
    "messages": [{"role": "user", "content": "Say hello in one sentence."}],
    "max_tokens": 50
  }' | python3 -m json.tool

echo ""
echo "Done."
