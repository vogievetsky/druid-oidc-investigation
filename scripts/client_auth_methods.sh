#!/usr/bin/env bash
# Try every druid.auth.pac4j.oidc.clientAuthenticationMethod value against Keycloak.
#
# For each case this starts an extra, throwaway router on :9888 (joining the already-running cluster that
# was started with conf/druid/oidc-all), runs the scripted login against it, records the outcome plus the
# router's pac4j errors and Keycloak's warnings, and stops that router again.
#
# usage: scripts/client_auth_methods.sh <path-to-apache-druid-distribution> [outFile]
# needs: `docker compose up -d` (realm with clients druid, druid-jwt, druid-public) and the oidc-all cluster running.
set -uo pipefail

DIST="$(cd "${1:?usage: $0 <druid-dist> [outFile]}" && pwd)"
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="${2:-$HERE/../evidence/client-auth-methods-run.log}"
WORK="$(mktemp -d)"
PORT=9888

# case name | clientID | clientAuthenticationMethod ("auto" = leave unset)
CASES=(
  "auto|druid|auto"
  "client_secret_basic|druid|client_secret_basic"
  "client_secret_post|druid|client_secret_post"
  "client_secret_jwt (client set up for signed JWT)|druid-jwt|client_secret_jwt"
  "private_key_jwt|druid|private_key_jwt"
  "none (public client)|druid-public|none"
  "none (confidential client)|druid|none"
)

: > "$OUT"
log() { echo "$@" | tee -a "$OUT"; }

for c in "${CASES[@]}"; do
  IFS='|' read -r name client method <<< "$c"
  slug="$(echo "$name" | tr -c 'a-zA-Z0-9_' '-')"
  conf="$WORK/$slug/conf"
  mkdir -p "$conf" "$WORK/$slug/log"
  cp -R "$DIST/conf/druid/oidc-all/_common" "$conf/_common"
  # the case decides the method; drop the common default
  perl -i -ne 'print unless /^druid\.auth\.pac4j\.oidc\.clientAuthenticationMethod=/' "$conf/_common/common.runtime.properties"
  mkdir -p "$conf/router"
  {
    cat "$DIST/conf/druid/oidc-all/router/runtime.properties"
    echo "druid.plaintextPort=$PORT"
    echo "druid.auth.pac4j.oidc.clientID=$client"
    [ "$method" != "auto" ] && echo "druid.auth.pac4j.oidc.clientAuthenticationMethod=$method"
  } > "$conf/router/runtime.properties"

  log ""
  log "=================== $name  (clientID=$client, clientAuthenticationMethod=$method)"
  since="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  (cd "$DIST" && DRUID_LOG_DIR="$WORK/$slug/log" exec bin/run-druid router "$conf" "-Xms256m -Xmx256m -XX:MaxDirectMemorySize=128m" \
    > "$WORK/$slug/log/stdout.log" 2>&1) &
  pid=$!
  for _ in $(seq 1 90); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "http://localhost:$PORT/status/health")" = "200" ] && break
    kill -0 "$pid" 2>/dev/null || break
    sleep 1
  done
  if ! kill -0 "$pid" 2>/dev/null; then
    log "router FAILED TO START:"
    grep -h -E "ERROR|Exception" "$WORK/$slug/log/"*.log | head -5 | cut -c1-300 | tee -a "$OUT"
    continue
  fi

  DRUID_URL="http://localhost:$PORT" python3 -I "$HERE/oidc_flow.py" alice alice /status/self \
    "POST /druid/v2/sql {\"query\":\"SELECT 'ok' AS login\"}" 2>&1 \
    | grep -E "^(GET|POST) |^   -> |No login form|HTTP ERROR|<title>|Router cookies" | cut -c1-200 | tee -a "$OUT"

  log "-- router errors:"
  # pac4j failures surface as a Jetty "WARN ... HttpChannel - <path>" with the exception on the next line
  grep -h -A1 -E "ERROR|WARN.*(pac4j|Pac4j|oidc|HttpChannel)" "$WORK/$slug/log/router.log" 2>/dev/null \
    | grep -v -i "non-HTTPS" | grep -v '^--$' | sed -E 's/^[0-9T:,.-]+ //' | sort | uniq -c | head -5 | cut -c1-300 | tee -a "$OUT"
  log "-- keycloak warnings:"
  docker logs --since "$since" druid-keycloak 2>&1 | grep -E "WARN" | grep -o 'type="[^"]*".*error="[^"]*"\|clientId="[^"]*"\|error="[^"]*"' \
    | sort | uniq -c | head -5 | tee -a "$OUT"

  kill "$pid" 2>/dev/null
  for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  for _ in $(seq 1 30); do lsof -iTCP:$PORT -sTCP:LISTEN >/dev/null 2>&1 || break; sleep 1; done
done

rm -rf "$WORK"
echo "done; results in $OUT"
