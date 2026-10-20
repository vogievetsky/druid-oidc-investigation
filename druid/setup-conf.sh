#!/usr/bin/env bash
# Create the two investigation configs inside a Druid distribution, based on its conf/druid/auto:
#   conf/druid/oidc-router-only  - pac4j on the router only (docs taken literally)
#   conf/druid/oidc-all          - basic + pac4j on every service, broker request logging on
#
# usage: druid/setup-conf.sh <path-to-apache-druid-distribution>
# then:  cd <dist> && bin/start-druid -m 6g -c conf/druid/oidc-all   (or oidc-router-only)
set -euo pipefail

DIST="${1:?usage: $0 <path-to-apache-druid-distribution>}"
HERE="$(cd "$(dirname "$0")" && pwd)"
AUTO="$DIST/conf/druid/auto"
[ -d "$AUTO" ] || { echo "No $AUTO - is $DIST a Druid distribution?" >&2; exit 1; }

add_extensions() { # <common.runtime.properties> <ext>...
  local file="$1"; shift
  local exts=""
  for e in "$@"; do exts="$exts\"$e\", "; done
  EXTS="$exts" perl -i -pe 's/^(druid\.extensions\.loadList=\[)/$1$ENV{EXTS}/' "$file"
}

A="$DIST/conf/druid/oidc-router-only"
rm -rf "$A" && cp -R "$AUTO" "$A"
add_extensions "$A/_common/common.runtime.properties" druid-pac4j
{ echo; cat "$HERE/router-only.properties"; } >> "$A/router/runtime.properties"

B="$DIST/conf/druid/oidc-all"
rm -rf "$B" && cp -R "$AUTO" "$B"
add_extensions "$B/_common/common.runtime.properties" druid-pac4j druid-basic-security
{ echo; cat "$HERE/all-services.properties"; } >> "$B/_common/common.runtime.properties"
printf '\n# Log every query with the identity the broker saw\ndruid.request.logging.type=slf4j\n' >> "$B/broker/runtime.properties"

echo "Created:"
echo "  $A"
echo "  $B"
grep -h '^druid.extensions.loadList' "$A/_common/common.runtime.properties" "$B/_common/common.runtime.properties" | cut -c1-100
