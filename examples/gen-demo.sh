#!/usr/bin/env bash
# Regenerate the example preflight reports from a synthetic demo fixture.
#
#   examples/gen-demo.sh
#
# Writes examples/preflight-demo.txt (text report) and
# examples/preflight-demo.json (the same assessment as JSON, schema
# info-guard/assessment/v1) from a 4-file fixture that exercises every
# report tier: key-shape hits, known-prefix bare tokens, a value shared
# across two key names (dagger footnotes), already-masked rows, and a
# session-timestamp date range. v0.5.0: the fixture also carries a .env
# source + a bare at-rest occurrence of one eligible value, producing a
# KNOWN (your .env values) row.
#
# The fixture values are SYNTHETIC and runtime-constructed by string
# concatenation — canonical fake secrets (key_..., ghp_..., sk-...)
# trip GitHub's push protection as literals, and this script is a
# committed file. The committed reports contain only 2+2 masked forms;
# raw values never leave the temp fixture.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
DEMO="$(mktemp -d)"
trap 'rm -rf "$DEMO"' EXIT

mkdir -p "$DEMO/cron/output" "$DEMO/logs" "$DEMO/sessions"

# Synthetic values, runtime-constructed (concatenation + printf) so no
# token-shaped literal exists in this committed file — canonical fake
# secrets trip GitHub's push protection as literals. Shapes mirror the
# battery's own fixture conventions:
#   jwt   = eyJhbG...VCJ9.<15×a|b>  (real JWT shape)
#   dsc   = MTQ5MjY4NTA5Mzk0MjQ2MDE3OQ                     (Discord shape)
#   sk-   = sk- + 28×A                                     (Anthropic shape)
#   ghp_  = ghp_ + 38×B                                    (GitHub PAT shape)
#   key_  = key_ + 30×C                                    (D140 shape)
jwt_hdr="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
jwt_a="$jwt_hdr"".$(printf 'a%.0s' $(seq 1 15))"
jwt_b="$jwt_hdr"".$(printf 'b%.0s' $(seq 1 15))"
dsc="MTQ5MjY4NTA5Mzk0MjQ2MDE3OQ"
sk_val="sk-$(printf 'A%.0s' $(seq 1 28))"
ghp_val="ghp_$(printf 'B%.0s' $(seq 1 38))"
kval="key_$(printf 'C%.0s' $(seq 1 30))"

printf 'key=%s\n' "$kval" > "$DEMO/cron/output/watch.log"
printf 'Authorization: ***\nHASS_TOKEN=%s\napi_key: ***\n' "$jwt_a" \
    > "$DEMO/logs/agent.log"
printf 'HASS_TOKEN=%s\nX-N8N-API-KEY: %s\nFIRECRAWL_API_KEY=***\ntoken=%s\n' \
    "$jwt_a" "$jwt_b" "$ghp_val" \
    > "$DEMO/sessions/session_20260424_211845_69c7b6.jsonl"
printf 'HASS_TOKEN=%s\nDISCORD_BOT_TOKEN=%s\nANTHROPIC_API_KEY=%s\nN8N_API_KEY=%s\nTUNNEL_TOKEN=%s\nAuthorization: ***\n' \
    "$jwt_a" "$dsc" "$sk_val" "$jwt_b" "$kval" \
    > "$DEMO/sessions/session_20260505_075138_3cf0d0a1.jsonl"
# v0.5.0 KNOWN tier: an eligible .env value + a BARE at-rest occurrence
# (the exact-value pass matches bare runs only — KEY=value lines are one
# run including the key, which never equals the value). The .env source
# itself is excluded from matching (self-match rule).
printf 'DEMO_TOKEN=%s\n' "$kval" > "$DEMO/.env"
printf 'bare demo token: %s\n' "$kval" \
    >> "$DEMO/sessions/session_20260505_075138_3cf0d0a1.jsonl"

# Both runs exit 1 on findings (0 = clean) — expected on this fixture;
# tolerate 0/1, abort on anything else (usage errors).
rc=0
HERMES_HOME="$DEMO" "$ROOT/bin/info-guard" preflight . \
    > "$HERE/preflight-demo.txt" || rc=$?
[ "$rc" -le 1 ] || exit "$rc"
HERMES_HOME="$DEMO" "$ROOT/bin/info-guard" preflight --json . \
    > "$HERE/preflight-demo.json" || rc=$?
[ "$rc" -le 1 ] || exit "$rc"

echo "[gen-demo] wrote $HERE/preflight-demo.txt + $HERE/preflight-demo.json"
echo "[gen-demo] fixture was synthetic and temp-only: $DEMO (removed on exit)"
