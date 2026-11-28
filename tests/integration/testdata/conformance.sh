#!/usr/bin/env bash
set -uo pipefail
C="${BENCH_DIR:?}/certs"
T="${BENCH_DIR:?}"
LOG="${BENCH_LOG:?}"
PORT="${BENCH_TLS_PORT:?}"
MPORT="${BENCH_METRICS_PORT:?}"
FEATURES="${BENCH_FEATURES:-}"
pass=0
fail=0
skip=0
ok() { pass=$((pass + 1)); printf 'PASS %s\n' "$1"; }
ko() { fail=$((fail + 1)); printf 'FAIL %s -- %s\n' "$1" "$2"; }
check() { if [ "$2" = "$3" ]; then ok "$1"; else ko "$1" "want [$3] got [$2]"; fi; }
has() { if grep -qiE -- "$3" <<<"$2"; then ok "$1"; else ko "$1" "missing pattern $3"; fi; }
hasnt() { if grep -qiE -- "$3" <<<"$2"; then ko "$1" "unexpected pattern $3"; else ok "$1"; fi; }

c() {
  local host="$1.bench.test" path="$2"
  shift 2
  curl -sS --max-time 30 --noproxy '*' --resolve "$host:$PORT:127.0.0.1" \
    --cacert "$C/server-root.crt" "$@" "https://$host:$PORT$path"
}
GOOD=(--cert "$C/client-good.crt" --key "$C/client-good.key")

group() {
  local feature="$1"
  shift
  if [[ ",$FEATURES," == *",$feature,"* ]]; then
    "${feature//-/_}_checks"
  else
    for name in "$@"; do
      skip=$((skip + 1))
      printf 'SKIP %s -- %s\n' "$name" "$feature"
    done
  fi
}

proxy_checks() {
  hdr=$(c web01 /page -H 'Accept-Encoding: gzip' -D - -o "$T"/page.gz)
  check "page status" "$(printf '%s' "$hdr" | head -1 | awk '{print $2}')" "200"
  has "page gzip" "$hdr" '^content-encoding: gzip'
  check "page gunzip size" "$(gzip -dc "$T"/page.gz 2>/dev/null | wc -c)" "8192"
  has "hsts" "$hdr" '^strict-transport-security: max-age=31536000; includeSubDomains; preload'
  has "frame options" "$hdr" '^x-frame-options: SAMEORIGIN'
  has "nosniff" "$hdr" '^x-content-type-options: nosniff'
  has "xss" "$hdr" '^x-xss-protection: 1; mode=block'
  has "referrer" "$hdr" '^referrer-policy: strict-origin-when-cross-origin'
  has "permissions" "$hdr" '^permissions-policy: geolocation=\(\)'
  has "coop" "$hdr" '^cross-origin-opener-policy: same-origin'
  has "corp" "$hdr" '^cross-origin-resource-policy: same-site'
  has "robots" "$hdr" '^x-robots-tag: none,noarchive'
  hasnt "server stripped" "$hdr" '^server:'
  hasnt "powered-by stripped" "$hdr" '^x-powered-by:'
}

identity_checks() {
  echo=$(c web01 /echo -H 'X-Forwarded-For: 6.6.6.6' -H 'X-Real-IP: 6.6.6.6' -H 'Cf-Connecting-Ip: 6.6.6.6' \
    -H 'Forwarded: for=6.6.6.6' -H 'True-Client-Ip: 6.6.6.6' -H 'X-Mtls-Identity: spoof')
  check "x-real-ip" "$(printf '%s' "$echo" | jq -r '.headers["X-Real-Ip"][0]')" "127.0.0.1"
  check "x-forwarded-for" "$(printf '%s' "$echo" | jq -r '.headers["X-Forwarded-For"]|join(",")')" "127.0.0.1"
  check "x-forwarded-proto" "$(printf '%s' "$echo" | jq -r '.headers["X-Forwarded-Proto"][0]')" "https"
  check "x-forwarded-host" "$(printf '%s' "$echo" | jq -r '.headers["X-Forwarded-Host"][0]')" "web01.bench.test:$PORT"
  check "spoof headers stripped" "$(printf '%s' "$echo" | jq -r '[.headers|keys[]|select(test("^(Cf-Connecting-Ip|Forwarded|True-Client-Ip)$"))]|length')" "0"
}

streaming_checks() {
  hdr=$(c s3 /s3/obj -H 'Accept-Encoding: identity' -D - -o "$T"/s3)
  check "s3 get status" "$(printf '%s' "$hdr" | head -1 | awk '{print $2}')" "200"
  check "s3 get bytes" "$(wc -c <"$T"/s3)" "15360"
  hasnt "s3 identity" "$hdr" '^content-encoding:'
  hdr=$(c s3 /s3/obj -I)
  has "s3 head length" "$hdr" '^content-length: 15360'
  check "s3 big download" "$(c s3 '/big?mb=64' -o - | wc -c)" "67108864"
  hdr=$(c web01 /health -H 'Accept-Encoding: gzip' -D - -o "$T"/health)
  hasnt "small not compressed" "$hdr" '^content-encoding:'
  check "health body" "$(cat "$T"/health)" "ok"
}

routing_checks() {
  check "deny route" "$(c s3 /minio/admin/x -o /dev/null -w '%{http_code}')" "403"
}

tls_checks() {
  alert=$(openssl s_client -connect "127.0.0.1:$PORT" -servername nohost.bench.test </dev/null 2>&1)
  has "unknown SNI alert" "$alert" 'unrecognized name|alert number 112'
}

mtls_checks() {
  c mtls01 /echo -o /dev/null 2>/dev/null && ko "mtls no cert refused" "curl succeeded" || ok "mtls no cert refused"
  code=$(c mtls01 /echo -o /dev/null -w '%{http_code}' 2>/dev/null)
  [ "$code" = "000" ] && ok "mtls no cert no response" || ko "mtls no cert no response" "got $code"
  echo=$(c mtls01 /echo "${GOOD[@]}" -H 'X-Mtls-Identity: spoof' -H 'X-Mtls-Other: spoof')
  check "mtls identity forwarded" "$(printf '%s' "$echo" | jq -r '.headers["X-Mtls-Identity"]|join(",")')" "urn:noqer:mtls:clients:bench"
  check "mtls spoof stripped" "$(printf '%s' "$echo" | jq -r '.headers["X-Mtls-Other"]')" "null"
  check "mtls other identity" "$(c mtls01 /echo --cert "$C/client-other.crt" --key "$C/client-other.key" -o /dev/null -w '%{http_code}')" "403"
  check "mtls blocked fp" "$(c mtls01 /echo --cert "$C/client-blocked.crt" --key "$C/client-blocked.key" -o /dev/null -w '%{http_code}')" "403"
  code=$(c mtls01 /echo --cert "$C/client-rogue.crt" --key "$C/client-rogue.key" -o /dev/null -w '%{http_code}' 2>/dev/null)
  check "mtls rogue CA refused" "$code" "000"
  check "sni host mismatch" "$(c web01 /echo "${GOOD[@]}" -H "Host: mtls01.bench.test:$PORT" -o /dev/null -w '%{http_code}')" "421"
}

crowdsec_checks() {
  check "crowdsec ban" "$(c web01 /health --interface 127.0.0.2 -o /dev/null -w '%{http_code}')" "403"
}

limits_checks() {
  codes=""
  for _ in $(seq 1 12); do codes="$codes $(c rl /health -o /dev/null -w '%{http_code}')"; done
  has "rate limit 429" "$codes" '429'
  check "rate limit first ok" "$(printf '%s' "$codes" | awk '{print $1}')" "200"
}

forward_auth_checks() {
  check "forward auth deny" "$(c whoami /probe -o /dev/null -w '%{http_code}')" "401"
  probe=$(c whoami /probe -H 'Authorization: Bearer good-token')
  check "forward auth allow" "$(printf '%s' "$probe" | jq -r .probe)" "ok"
  check "bearer stripped" "$(printf '%s' "$probe" | jq -r .authorization)" ""
  last=$(curl -sS "$BENCH_AUTH_URL/last")
  check "auth x-forwarded-uri" "$(printf '%s' "$last" | jq -r '.["X-Forwarded-Uri"][0]')" "/probe"
  check "auth x-forwarded-method" "$(printf '%s' "$last" | jq -r '.["X-Forwarded-Method"][0]')" "GET"
  check "auth x-forwarded-host" "$(printf '%s' "$last" | jq -r '.["X-Forwarded-Host"][0]')" "whoami.bench.test:$PORT"
}

uploads_checks() {
  head -c 4096 /dev/urandom >"$T"/4k
  check "vm write" "$(c vm-upload /api/v1/write "${GOOD[@]}" --data-binary @"$T"/4k -H 'Content-Type: application/x-protobuf' -o /dev/null -w '%{http_code}')" "204"
  up=$(head -c 67108864 /dev/zero | c journald /insert/journald/upload "${GOOD[@]}" -X POST -T - -H 'Content-Type: application/vnd.fdo.journal')
  check "journald stream upload" "$(printf '%s' "$up" | jq -r .bytes)" "67108864"
  check "journald method" "$(c journald /insert/journald/upload "${GOOD[@]}" -o /dev/null -w '%{http_code}')" "404"
}

alpn_checks() {
  check "h2" "$(c web01 /health --http2 -o /dev/null -w '%{http_version}')" "2"
  check "h2 mtls" "$(c mtls01 /health "${GOOD[@]}" --http2 -o /dev/null -w '%{http_version}')" "2"
  check "h1" "$(c web01 /health --http1.1 -o /dev/null -w '%{http_version}')" "1.1"
}

observability_checks() {
  c web01 /health -o /dev/null
  access=""
  for _ in $(seq 1 30); do
    access=$(jq -Rc 'fromjson? | select(.client_ip == "127.0.0.1" and .method == "GET" and
      .path == "/health" and .status == 200 and (.route | type == "string"))' "$LOG")
    [ -n "$access" ] && break
    sleep 0.1
  done
  has "JSON access log" "$access" '^\{'
  has "metrics" "$(curl -sS --max-time 30 "http://127.0.0.1:$MPORT/metrics")" '^gatehouse_requests_total\{.*route="(bench/)?web01'
}

group proxy \
  "page status" "page gzip" "page gunzip size" \
  "hsts" "frame options" "nosniff" \
  "xss" "referrer" "permissions" \
  "coop" "corp" "robots" \
  "server stripped" "powered-by stripped"
group identity \
  "x-real-ip" "x-forwarded-for" "x-forwarded-proto" \
  "x-forwarded-host" "spoof headers stripped"
group streaming \
  "s3 get status" "s3 get bytes" "s3 identity" \
  "s3 head length" "s3 big download" "small not compressed" \
  "health body"
group routing \
  "deny route"
group tls \
  "unknown SNI alert"
group mtls \
  "mtls no cert refused" "mtls no cert no response" "mtls identity forwarded" \
  "mtls spoof stripped" "mtls other identity" "mtls blocked fp" \
  "mtls rogue CA refused" "sni host mismatch"
group crowdsec \
  "crowdsec ban"
group limits \
  "rate limit 429" "rate limit first ok"
group forward-auth \
  "forward auth deny" "forward auth allow" "bearer stripped" \
  "auth x-forwarded-uri" "auth x-forwarded-method" "auth x-forwarded-host"
group uploads \
  "vm write" "journald stream upload" "journald method"
group alpn \
  "h2" "h2 mtls" "h1"
group observability \
  "JSON access log" "metrics"

printf '%d passed, %d failed, %d skipped\n' "$pass" "$fail" "$skip"
[ "$fail" = 0 ] && [ "$((pass + fail + skip))" = 53 ]
