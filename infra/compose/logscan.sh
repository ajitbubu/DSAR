#!/usr/bin/env bash
# Fails if any seeded or test identifier appears in any service log (M8 acceptance).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
PATTERN='priya\.sharma@example|someone\.else@example|rahul\.verma@example|\+?91 ?98765|CUST-(1001|2002|3003)|Priya Sharma|E2E Requester|live\.check@|eyJhbGci|dev-password|GST records'
if docker compose -f "$HERE/docker-compose.yml" logs --no-color api worker outbox-relay web \
     mock-connectors 2>/dev/null | grep -Eio "$PATTERN" | sort | uniq -c; then
  echo "FAIL: personal data or secrets found in service logs"; exit 1
fi
echo "ok   no seeded identifiers, tokens or passwords in service logs"
