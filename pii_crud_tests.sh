#!/usr/bin/env bash
# Full test suite for runtime PII CRUD (pii-registry + pii_crud_guardrail).
# Run: ./pii_crud_tests.sh        (~7 min, makes real LLM calls)
set -u
cd "$(dirname "$0")"
. ./.env
REG="http://localhost:5003"
GW="http://localhost:4000"
AK="$PII_ADMIN_KEY"; MK="$LITELLM_MASTER_KEY"
TMP=/c/Users/stsel/AppData/Local/Temp/opencode
PASS=0; FAIL=0; INFO=0

ok(){   PASS=$((PASS+1)); echo "  PASS  $1"; }
bad(){  FAIL=$((FAIL+1)); echo "  FAIL  $1"; }
note(){ INFO=$((INFO+1)); echo "  info  $1"; }
hdr(){  echo; echo "=== $1 ==="; }

has(){ case "$2" in *"$1"*) return 0;; *) return 1;; esac; }
assert_in(){  if has "$1" "$2"; then ok "$3"; else bad "$3  [missing: $1]"; fi; }
assert_not(){ if has "$1" "$2"; then bad "$3  [found: $1]"; else ok "$3"; fi; }

# Unique per-run tag embedded in every prompt so DB reads are deterministic
# even across repeated suite runs (markers must never contain PII - it gets masked!)
# NOTE: tag() uses printf -v so the counter increments in THIS shell —
# never call it inside $() or the sequence number will be lost to a subshell.
#
# Marker format "$(date +%M%S) <T_${SEQ}>": BOTH parts must survive masking —
#   1. "<T_N>" is deliberately placeholder-shaped: the guardrail's
#      PLACEHOLDER_RE guarantees tokens like <T_22> are NEVER masked.
#   2. The run number is a bare 4-digit number (no letter wrapper!):
#      letter+digit tokens like "w3026x" get flagged as PERSON by presidio's
#      NER (context-dependent) and masked, which broke the DB poll. A bare
#      4-digit number matches no enabled recognizer regex and is never a NER
#      entity. wait_input() also filters by startTime >= suite start, so
#      markers never collide with an earlier suite run that reused the tag.
RUN_TAG="$(date +%M%S)"
SUITE_START="$(date -u '+%Y-%m-%d %H:%M:%S')"
SEQ=0
tag(){ SEQ=$((SEQ+1)); printf -v "$1" '%s' "$RUN_TAG <T_${SEQ}>: $2"; }

# JSON body built by python (immune to MSYS backslash mangling) -> file -> curl
JBODY="$TMP/pii_body.json"
jpost(){  python -c "import json,sys; open(sys.argv[1],'w').write(json.dumps(json.loads(sys.argv[2])))" "$JBODY" "$2" \
          && curl -s --max-time 30 -X POST "$REG$1" -H "X-API-Key: $AK" -H "Content-Type: application/json" --data-binary @"$JBODY"; }
jpatch(){ python -c "import json,sys; open(sys.argv[1],'w').write(json.dumps(json.loads(sys.argv[2])))" "$JBODY" "$2" \
          && curl -s --max-time 30 -X PATCH "$REG$1" -H "X-API-Key: $AK" -H "Content-Type: application/json" --data-binary @"$JBODY"; }

PSQL=(podman exec litellm-postgres psql -U litellm -p 9865 -d litellm -t -A -c)
# Deterministic DB read: wait for THIS run's row (unique tag marker), since
# LiteLLM writes spend logs asynchronously. The startTime floor keeps polls
# from matching rows of an earlier suite run that reused the same MMSS tag.
wait_input(){ # marker -> that request's masked user content
  local row=""
  for i in $(seq 1 40); do
    row=$("${PSQL[@]}" "SELECT proxy_server_request::jsonb->'messages'->-1->>'content' FROM \"LiteLLM_SpendLogs\" WHERE proxy_server_request::jsonb->'messages'->-1->>'content' LIKE '%$1%' AND \"startTime\" >= '$SUITE_START+00' ORDER BY \"startTime\" DESC LIMIT 1")
    [ -n "$row" ] && { echo "$row"; return 0; }
    sleep 1
  done
  echo ""
}

gw(){ # content outfile [max_tokens] [model] [nothink] -> prints http_code
  local mt="${3:-120}" m="${4:-gemma3}" extra=""
  [ "${5:-}" = "nothink" ] && extra=',"think":false'
  curl -s --max-time 150 "$GW/chat/completions" \
    -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
    -d "{\"model\":\"$m\"${extra},\"max_tokens\":$mt,\"messages\":[{\"role\":\"user\",\"content\":\"$1\"}]}" \
    -o "$2" -w "%{http_code}"
}
gw_wait(){ local code; code=$(gw "$@"); echo "$code"; }  # caller uses wait_input
resp(){ PYTHONIOENCODING=utf-8 python -c "
import json
try:
    r = json.load(open('$1', encoding='utf-8'))
    print((r['choices'][0]['message'].get('content') or ''))
except Exception:
    print('')"; }

reg_get(){ curl -s --max-time 30 "$REG$1" -H "X-API-Key: $AK"; }
reg_del(){ curl -s --max-time 30 -X DELETE "$REG$1" -H "X-API-Key: $AK"; }

echo "PII runtime CRUD test suite — $(date '+%H:%M:%S')  (run tag: $RUN_TAG)"

# ── A. health & seed ──────────────────────────────────────────
hdr "A. Health & seed"
assert_in '"ok"' "$(curl -s --max-time 10 "$REG/health")" "registry healthy"
assert_in 'version' "$(reg_get /version)" "config version readable"
ne=$(reg_get /entities | python -c "import json,sys; print(len(json.load(sys.stdin)))")
nr=$(reg_get /recognizers | python -c "import json,sys; print(len(json.load(sys.stdin)))")
[ "$ne" -ge 15 ] && ok "seeded entities >= 15 ($ne)" || bad "seeded entities ($ne)"
[ "$nr" -ge 9 ]  && ok "seeded recognizers >= 9 ($nr)" || bad "seeded recognizers ($nr)"

# ── B. dry-run /test ─────────────────────────────────────────
hdr "B. Dry-run /test endpoint"
t=$(jpost /test '{"text":"Email ravi@gmail.com, aadhaar 2345 6789 0123"}')
assert_in 'EMAIL_ADDRESS' "$t" "/test detects EMAIL_ADDRESS"
assert_in 'AADHAAR_NUMBER' "$t" "/test detects AADHAAR_NUMBER"
mt=$(echo "$t" | python -c "import json,sys; print(json.load(sys.stdin).get('masked_text',''))")
assert_not 'ravi@gmail.com' "$mt" "/test masks the values"

# ── C. custom recognizer lifecycle: ASML_EMAIL ───────────────
hdr "C. Runtime add/update/disable/enable/delete recognizer (ASML_EMAIL)"
reg_del /recognizers/ASML_EMAIL >/dev/null; reg_del /entities/ASML_EMAIL >/dev/null
r=$(jpost /recognizers '{"name":"ASML_EMAIL","patterns":[{"name":"ASML_PAT","regex":"[A-Za-z0-9._%+-]+@asmltd[.]com","score":0.9}]}')
assert_in '"created"' "$r" "POST /recognizers creates ASML_EMAIL"
t=$(jpost /test '{"text":"Contact ravi@asmltd.com now"}')
assert_in '<ASML_EMAIL_1>' "$t" "/test masks custom domain (custom wins over generic EMAIL_ADDRESS)"
tag m "My work email is ravi@asmltd.com. Note it down."
code=$(gw_wait "$m" "$TMP/c1.json" 100 qwen3.5 nothink)
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_in '<ASML_EMAIL_1>' "$inp" "gateway masks ASML email (HTTP $code)"
assert_not 'ravi@asmltd.com' "$inp" "raw ASML email never reaches LLM"
tag m "My work email is ravi@asmltd.com. Reply exactly and nothing else: noted <ASML_EMAIL_1>."
gw_wait "$m" "$TMP/c1b.json" 120 gemma3 >/dev/null
resp=$(resp "$TMP/c1b.json")
if has '<ASML_EMAIL_1>' "$resp"; then bad "restore FAILED (token visible in reply)"
elif has 'ravi@asmltd.com' "$resp"; then ok "restore worked (client got real email)"
else note "model paraphrased - nothing to restore"; fi

r=$(jpatch /recognizers/ASML_EMAIL '{"patterns":[{"name":"ASML_PAT","regex":"[A-Za-z0-9._%+-]+@asmltd[.]com|[A-Za-z0-9._%+-]+@asml[.]com","score":0.9}]}')
assert_in '"updated"' "$r" "PATCH /recognizers updates patterns"
t=$(jpost /test '{"text":"Mail raj@asmltd.com or priya@asml.com"}')
assert_in '<ASML_EMAIL_1>' "$t" "updated regex catches first domain"
assert_in '<ASML_EMAIL_2>' "$t" "updated regex catches second domain"

jpatch /recognizers/ASML_EMAIL '{"enabled":false}' >/dev/null
tag m "Contact me at ravi@asmltd.com about the order."
gw_wait "$m" "$TMP/c2.json" 60 >/dev/null
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_not '<ASML_EMAIL_' "$inp" "disabled recognizer: no ASML-specific token"
assert_in '<EMAIL_ADDRESS_' "$inp" "disabled recognizer: generic EMAIL_ADDRESS still masks"
jpatch /recognizers/ASML_EMAIL '{"enabled":true}' >/dev/null
tag m "Contact me at ravi@asmltd.com about the refund."
gw_wait "$m" "$TMP/c3.json" 60 >/dev/null
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_in '<ASML_EMAIL_1>' "$inp" "re-enabled recognizer masks again"
assert_not 'ravi@asmltd.com' "$inp" "raw email gone again after re-enable"
reg_del /recognizers/ASML_EMAIL >/dev/null
tag m "Contact me at ravi@asmltd.com about the invoice."
gw_wait "$m" "$TMP/c4.json" 60 >/dev/null
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_not '<ASML_EMAIL_' "$inp" "deleted recognizer: no ASML-specific token"
assert_in '<EMAIL_ADDRESS_' "$inp" "deleted recognizer: generic EMAIL_ADDRESS still masks"
reg_del /entities/ASML_EMAIL >/dev/null

# ── D. entity lifecycle: DATE_TIME ───────────────────────────
hdr "D. Runtime add/block/mask/delete entity (DATE_TIME)"
reg_del /entities/DATE_TIME >/dev/null
r=$(jpost /entities '{"name":"DATE_TIME","action":"MASK"}')
assert_in '"created"' "$r" "POST /entities creates DATE_TIME"
tag m "Report due date is 2026-11-15. Reply: A."
code=$(gw_wait "$m" "$TMP/d1.json" 80)
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_in '<DATE_TIME_' "$inp" "gateway masks date after runtime entity add (HTTP $code)"
assert_not '2026-11-15' "$inp" "raw date never reaches LLM"
jpatch /entities/DATE_TIME '{"action":"BLOCK"}' >/dev/null
code=$(gw "Report due date is 2026-11-15. Send status." "$TMP/d2.json" 60)
[ "$code" = "400" ] && ok "BLOCK action rejects request with 400" || bad "BLOCK expected 400, got $code"
jpatch /entities/DATE_TIME '{"action":"MASK"}' >/dev/null
tag m "Report due date is 2026-11-15. Reply: B."
code=$(gw_wait "$m" "$TMP/d3.json" 80)
assert_in '<DATE_TIME_' "$(wait_input "$RUN_TAG <T_${SEQ}>")" "back to MASK: date masked again (HTTP $code)"
reg_del /entities/DATE_TIME >/dev/null
tag m "Report due date is 2026-11-15. Reply: C."
gw_wait "$m" "$TMP/d4.json" 80 >/dev/null
assert_not '<DATE_TIME_' "$(wait_input "$RUN_TAG <T_${SEQ}>")" "deleted entity: date no longer masked"

# ── E. BLOCK on a built-in entity (PERSON) ───────────────────
hdr "E. BLOCK on built-in entity (PERSON)"
jpatch /entities/PERSON '{"action":"BLOCK"}' >/dev/null
code=$(gw "My name is Ravi Kumar, call me." "$TMP/e1.json" 60)
[ "$code" = "400" ] && ok "PERSON=BLOCK rejects request with 400" || bad "PERSON=BLOCK expected 400, got $code"
jpatch /entities/PERSON '{"action":"MASK"}' >/dev/null
tag m "My name is Ravi Kumar, ping me later."
code=$(gw_wait "$m" "$TMP/e2.json" 60)
assert_in '<PERSON_1>' "$(wait_input "$RUN_TAG <T_${SEQ}>")" "PERSON back to MASK: name masked (HTTP $code)"

# ── F. validation & auth ─────────────────────────────────────
hdr "F. Input validation & auth"
r=$(jpost /recognizers '{"name":"BAD_REGEX","patterns":[{"name":"x","regex":"([unclosed","score":0.9}]}')
assert_in 'invalid regex' "$r" "invalid regex rejected (400)"
code=$(curl -s -o "$TMP/f1.json" -w "%{http_code}" --max-time 10 -X POST "$REG/entities" -H "X-API-Key: wrong-key" -H "Content-Type: application/json" -d '{"name":"X1"}')
[ "$code" = "401" ] && ok "wrong admin key rejected (401)" || bad "wrong key expected 401, got $code"
r=$(jpost /entities '{"name":"PERSON","action":"MASK"}')
assert_in 'already exists' "$r" "duplicate entity rejected (409)"
r=$(jpost /entities '{"name":"lower_case","action":"MASK"}')
assert_in 'UPPERCASE_SNAKE' "$r" "bad entity name rejected (400)"

# ── G. regression: existing flows still mask ─────────────────
hdr "G. Regression - all seeded entities still mask"
tag m "My name is Ravi Kumar, mobile 9876543210. Say hi."
gw_wait "$m" "$TMP/g1.json" 60 >/dev/null
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_in '<PERSON_' "$inp" "PERSON masked"
assert_in '<INDIAN_PHONE_' "$inp" "INDIAN_PHONE masked"
assert_not '9876543210' "$inp" "raw mobile never reaches LLM"
tag m "My PAN is ABCDE1234F and Aadhaar is 2345 6789 0123. Confirm KYC."
gw_wait "$m" "$TMP/g2.json" 60 >/dev/null
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_in '<INDIAN_PAN_' "$inp" "PAN masked"
assert_in '<AADHAAR_NUMBER_' "$inp" "Aadhaar masked"
assert_not 'ABCDE1234F' "$inp" "raw PAN never reaches LLM"
tag m "My email is ravi@gmail.com and my card is 4111 1111 1111 1111."
gw_wait "$m" "$TMP/g3.json" 60 >/dev/null
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_in '<EMAIL_ADDRESS_' "$inp" "email masked"
assert_in '<CREDIT_CARD_' "$inp" "credit card masked"
assert_not '1111.' "$inp" "card digits never reach LLM"
tag m "Send payment to ravi@upi, bank IFSC SBIN0001234."
gw_wait "$m" "$TMP/g4.json" 60 >/dev/null
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_in '<UPI_ID_' "$inp" "UPI masked"
assert_in '<SBIN_IFSC_' "$inp" "IFSC masked"
tag m "GSTIN 29ABCDE1234F1Z5, car KA 01 AB 1234, pincode 560001. Summarize."
gw_wait "$m" "$TMP/g5.json" 60 >/dev/null
inp=$(wait_input "$RUN_TAG <T_${SEQ}>")
assert_in '<GSTIN_' "$inp" "GSTIN masked"
assert_in '<KA_VEHICLE_NUMBER_' "$inp" "vehicle masked"
assert_in '<INDIAN_PINCODE_' "$inp" "pincode masked"
tag m "My office line is 555-1234. Note it."
gw_wait "$m" "$TMP/g6.json" 60 >/dev/null
assert_in '<US_LOCAL_PHONE_' "$(wait_input "$RUN_TAG <T_${SEQ}>")" "US local phone masked"
tag m "What is the capital of Karnataka? One word."
gw_wait "$m" "$TMP/g7.json" 60 >/dev/null
# strip the (expected) <T_N> marker token before checking for stray placeholders
assert_not '<' "$(wait_input "$RUN_TAG <T_${SEQ}>" | sed -E 's/<T_[0-9]+>//g')" "negative test: no placeholders injected on PII-free text"

# ── H. fail-safety: registry down ────────────────────────────
# Two architectures, different (both privacy-safe) behavior when pii-registry
# is down:
#   default (config.yaml pii-crud guardrail): last-known-good cached config ->
#     masking continues, HTTP 200.
#   REJECTS_ON_REGISTRY_DOWN=1 (API-registered generic_guardrail_api): litellm
#     fail-closed -> request rejected (HTTP 500), never sent unmasked.
hdr "H. Fail-safety - registry down"
podman stop pii-registry >/dev/null 2>&1
sleep 2
tag m "My name is Ravi Kumar, email ravi@gmail.com. Greetings."
if [ "${REJECTS_ON_REGISTRY_DOWN:-0}" = "1" ]; then
  code=$(gw "My name is Ravi Kumar, email ravi@gmail.com. Greetings." "$TMP/h1.json" 60)
  if [ "$code" = "500" ]; then
    ok "fail-closed: request rejected while registry down (HTTP 500, never unmasked)"
  elif [ "$code" = "400" ]; then
    ok "fail-closed: request rejected while registry down (HTTP 400, never unmasked)"
  else
    bad "fail-closed expected 4xx/5xx while registry down, got $code"
  fi
else
  code=$(gw_wait "$m" "$TMP/h1.json" 60)
  assert_in '<PERSON_' "$(wait_input "$RUN_TAG <T_${SEQ}>")" "masking continues with registry stopped (cached config, HTTP $code)"
fi
podman start pii-registry >/dev/null 2>&1
sleep 4
assert_in '"ok"' "$(curl -s --max-time 10 "$REG/health")" "registry back up"

# ── I. audit & reload ────────────────────────────────────────
hdr "I. Audit trail & reload"
na=$(reg_get "/audit?limit=100" | python -c "import json,sys; print(len(json.load(sys.stdin)))")
[ "$na" -ge 10 ] && ok "audit log has $na entries" || bad "audit log only $na entries"
v1=$(reg_get /version | python -c "import json,sys; print(json.load(sys.stdin)['version'])")
v2=$(curl -s --max-time 10 -X POST "$REG/reload" -H "X-API-Key: $AK" | python -c "import json,sys; print(json.load(sys.stdin)['version'])")
[ "$v2" -gt "$v1" ] && ok "reload bumps version ($v1 -> $v2)" || bad "reload did not bump version"

echo
echo "══════════════════════════════════════════"
echo "RESULT: $PASS passed, $FAIL failed, $INFO info"
echo "══════════════════════════════════════════"
[ "$FAIL" -eq 0 ]
