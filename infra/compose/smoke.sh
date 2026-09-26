#!/usr/bin/env bash
# Smoke test against the running local stack (`make up`). Local/dev only.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
API=http://localhost:8000
KC=http://localhost:8080/realms/idprivacy/protocol/openid-connect/token
COMPOSE="docker compose -f $HERE/docker-compose.yml"
# The dev password lives only in the realm fixture; read it from there.
PW="$(python3 -c "import json,sys; print(json.load(open('$HERE/keycloak/idprivacy-realm.json'))['users'][0]['credentials'][0]['value'])")"
fail=0

token() {
  curl -fsS -X POST "$KC" -d grant_type=password -d client_id=idprivacy-dev-cli \
    --data-urlencode "username=$1" --data-urlencode "password=$PW" \
    | python3 -c "import json,sys; print(json.load(sys.stdin)['access_token'])"
}

expect() {  # expect <label> <want-status> <curl args...>
  local label=$1 want=$2; shift 2
  local got; got=$(curl -s -o /dev/null -w '%{http_code}' "$@")
  if [[ "$got" == "$want" ]]; then echo "  ok   $label ($got)"; else echo "  FAIL $label (want $want, got $got)"; fail=1; fi
}

echo "health"
expect "api /readyz" 200 "$API/readyz"
expect "web /api/healthz" 200 http://localhost:3000/api/healthz
expect "mock-connectors /healthz" 200 http://localhost:8100/healthz

echo "authn/authz with real Keycloak tokens"
AUDITOR=$(token auditor@acme.example.test)
ANALYST=$(token analyst@acme.example.test)
GLOBEX=$(token auditor@globex.example.test)
UNPROV=$(token unprovisioned@example.test)
expect "no token -> 401" 401 "$API/v1/me"
expect "garbage token -> 401" 401 -H "Authorization: Bearer not.a.jwt" "$API/v1/me"
expect "analyst /v1/me -> 200" 200 -H "Authorization: Bearer $ANALYST" "$API/v1/me"
expect "unprovisioned -> 403" 403 -H "Authorization: Bearer $UNPROV" "$API/v1/me"
expect "analyst audit/verify -> 403" 403 -X POST -H "Authorization: Bearer $ANALYST" "$API/v1/audit/verify"
expect "acme auditor audit/verify -> 200" 200 -X POST -H "Authorization: Bearer $AUDITOR" "$API/v1/audit/verify"
expect "globex auditor audit/verify -> 200" 200 -X POST -H "Authorization: Bearer $GLOBEX" "$API/v1/audit/verify"

ACME_TENANT=$(curl -fsS -H "Authorization: Bearer $AUDITOR" "$API/v1/me" | python3 -c "import json,sys; print(json.load(sys.stdin)['tenant_id'])")
GLOBEX_TENANT=$(curl -fsS -H "Authorization: Bearer $GLOBEX" "$API/v1/me" | python3 -c "import json,sys; print(json.load(sys.stdin)['tenant_id'])")
if [[ "$ACME_TENANT" != "$GLOBEX_TENANT" ]]; then echo "  ok   tenants resolved from token, not input"; else echo "  FAIL tenant resolution"; fail=1; fi

echo "outbox -> relay -> celery"
MSG=$(python3 -c "import uuid; print(uuid.uuid4())")
$COMPOSE exec -T postgres psql -q -U idp_migrator -d idprivacy -c \
  "INSERT INTO outbox (id, tenant_id, topic, payload) VALUES ('$MSG', '$ACME_TENANT', 'system.noop', '{\"request_id\": \"$MSG\"}')" >/dev/null
for _ in $(seq 1 20); do
  if $COMPOSE logs worker 2>/dev/null | grep -q "$MSG"; then break; fi; sleep 0.5
done
if $COMPOSE logs worker 2>/dev/null | grep -q "noop_task_executed.*$MSG\|$MSG.*noop_task_executed"; then
  echo "  ok   worker executed task $MSG"
else
  echo "  FAIL worker did not execute outbox message $MSG"; fail=1
fi

echo "evidence storage"
expect "anonymous bucket listing denied" 403 http://localhost:8333/idprivacy-evidence

echo "log redaction"
if $COMPOSE logs api worker outbox-relay 2>/dev/null | grep -Eq "@(acme|globex)\.example\.test"; then
  echo "  FAIL staff email found in service logs"; fail=1
else
  echo "  ok   no staff emails in api/worker/relay logs"
fi

exit $fail
