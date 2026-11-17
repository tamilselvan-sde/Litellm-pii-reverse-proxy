# All curl commands — Linux edition

Every API command for the PII gateway stack in one file, written for **Linux
bash** (plain `curl`, single-quoted JSON, no escaping tricks needed).

Two APIs:

| API | Base URL | Auth |
|---|---|---|
| **pii-registry** — PII entities/recognizers CRUD (mask & block rules) | `http://localhost:5003` | `X-API-Key: $PII_ADMIN_KEY` (mutating ops + `/test` only) |
| **LiteLLM gateway** — chat completions + guardrail lifecycle (DB-managed CRUD) | `http://localhost:4000` | `Authorization: Bearer $LITELLM_MASTER_KEY` |

---

## 0. Setup (paste once per shell)

```bash
cd /path/to/litellm        # project folder containing .env
. ./.env                   # loads PII_ADMIN_KEY, LITELLM_MASTER_KEY, ...
# (if ./.env was ever edited on Windows, strip CRs once:  sed -i 's/\r$//' .env)

REG="http://localhost:5003"    # pii-registry
GATE="http://localhost:4000"   # LiteLLM gateway
AK="$PII_ADMIN_KEY"            # registry admin key
MK="$LITELLM_MASTER_KEY"       # gateway master key
```

> **Linux bonus:** single-quoted bash strings keep backslashes intact, so
> regexes like `\b`, `\d{5}`, `(?![0-9])` can be pasted directly into the JSON
> below. (On Git Bash/Windows those would get mangled — that gotcha does not
> exist on Linux.)

---

## 1. Read-only (no auth needed)

```bash
# liveness + DB check
curl -s "$REG/health"

# current config version (bumps on every change)
curl -s "$REG/version"

# the effective config the gateway guardrail fetches per request
curl -s "$REG/config" | python3 -m json.tool

# list everything (incl. disabled)
curl -s "$REG/entities"     | python3 -m json.tool
curl -s "$REG/recognizers"  | python3 -m json.tool

# recent config changes (audit trail)
curl -s "$REG/audit?limit=20" | python3 -m json.tool

# quick counts
curl -s "$REG/config" | python3 -c \
  "import json,sys; c=json.load(sys.stdin); print('version', c['version'], '| entities:', len(c['entities']), '| recognizers:', len(c['recognizers']))"
```

---

## 2. Entities — MASK or BLOCK a PII type

```bash
# add a presidio built-in entity, default action MASK
curl -s -X POST "$REG/entities" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"name":"DATE_TIME","action":"MASK"}'

# add with hard-block (any match => HTTP 400, request never reaches the LLM)
curl -s -X POST "$REG/entities" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"name":"DATE_TIME","action":"BLOCK"}'

# switch action later: MASK <-> BLOCK
curl -s -X PATCH "$REG/entities/PERSON" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"action":"BLOCK"}'

curl -s -X PATCH "$REG/entities/PERSON" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"action":"MASK"}'

# disable / re-enable (entity stays configured but inactive)
curl -s -X PATCH "$REG/entities/UPI_ID" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"enabled":false}'

curl -s -X PATCH "$REG/entities/UPI_ID" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"enabled":true}'

# delete
curl -s -X DELETE "$REG/entities/DATE_TIME" -H "X-API-Key: $AK"
```

---

## 3. Recognizers — custom regex / deny-list rules

```bash
# create: regex rule (auto-creates its entity; entity_action = MASK or BLOCK)
curl -s -X POST "$REG/recognizers" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{
        "name": "ASML_EMAIL",
        "patterns": [
          {"name": "ASML_PAT", "regex": "[A-Za-z0-9._%+-]+@asmltd\\.com", "score": 0.9}
        ],
        "context": ["work email", "company email"],
        "score": 0.9,
        "entity_action": "MASK"
      }'

# create with a deny_list instead of regex
curl -s -X POST "$REG/recognizers" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"name":"COMPETITOR_DOMAIN","deny_list":["acme-corp.com"],"entity_action":"BLOCK"}'

# update the regex
curl -s -X PATCH "$REG/recognizers/ASML_EMAIL" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"patterns":[{"name":"ASML_PAT","regex":"[A-Za-z0-9._%+-]+@asmltd\\.com|[A-Za-z0-9._%+-]+@asml\\.com","score":0.9}]}'

# raise the score
curl -s -X PATCH "$REG/recognizers/ASML_EMAIL" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"score":0.95}'

# disable / re-enable (generic built-ins may still catch the same values)
curl -s -X PATCH "$REG/recognizers/ASML_EMAIL" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"enabled":false}'

# delete (recognizer, then its auto-created entity)
curl -s -X DELETE "$REG/recognizers/ASML_EMAIL" -H "X-API-Key: $AK"
curl -s -X DELETE "$REG/entities/ASML_EMAIL"   -H "X-API-Key: $AK"
```

---

## 4. Dry-run masking — no LLM call, no log row

```bash
curl -s -X POST "$REG/test" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"text":"PAN ABCDE1234F, aadhaar 2345 6789 0123, card 4111 1111 1111 1111"}' \
  | python3 -m json.tool
# -> detections[], masked_text ("<TYPE_N>"), token_map

# masked text only:
curl -s -X POST "$REG/test" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"text":"Contact ravi@asmltd.com now"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['masked_text'])"
```

---

## 5. Ops

```bash
# force a config version bump (guardrail already re-fetches /config every request)
curl -s -X POST "$REG/reload" -H "X-API-Key: $AK"

# chat through the gateway (masking runs before the LLM, restore after it)
curl -s "$GATE/chat/completions" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d '{"model":"gemma3","max_tokens":80,
       "messages":[{"role":"user","content":"My card is 4111 1111 1111 1111, email ravi@gmail.com"}]}'

# ask for a specific registered guardrail by name (opt-in ones)
#   add:  "guardrails":["my-guardrail"]   to the chat body
```

Error codes to expect: `400` invalid regex/name/action, `401` missing/wrong
key, `404` unknown name, `409` name already exists, `502` analyzer error
during `/test`.

---

## 6. Guardrail lifecycle — full CRUD (gateway API, DB-managed)

Guardrails are stored in the LiteLLM Postgres DB and registered over the API —
**register / list / show / update / delete all take effect live, zero
restarts**. On LiteLLM v1.109.1 `/guardrails/register` only accepts
`guardrail: "generic_guardrail_api"`; LiteLLM POSTs every text to
`<api_base>/beta/litellm_basic_guardrail_api`. Pointing `api_base` at
pii-registry gives presidio masking (pre_call) + token restore (post_call)
driven by the registry's entity/recognizer config (sections 2–4). The registry
guardrail endpoint enforces auth — pass `api_key` in `litellm_params`
(LiteLLM forwards it as `x-api-key`).

#### 6.0 one-time: team (guardrails are team-scoped)

```bash
# find the pii-admin team or create it -> prints team_id
TEAM=$(curl -s "$GATE/team/list?page=1" -H "Authorization: Bearer $MK" \
  | python3 -c "import json,sys; \
print(next((t['team_id'] for t in json.load(sys.stdin) if t.get('team_alias')=='pii-admin'), ''))")
[ -z "$TEAM" ] && TEAM=$(curl -s -X POST "$GATE/team/new" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d '{"team_alias":"pii-admin"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['team_id'])")
echo "team_id: $TEAM"
```

#### 6.1 register (Create) — the mask + restore pair

```bash
# pre_call: presidio-mask PII before the LLM sees it
curl -s -X POST "$GATE/guardrails/register" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d "{\"guardrail_name\":\"pii-presidio\",
       \"team_id\":\"$TEAM\",
       \"litellm_params\":{\"guardrail\":\"generic_guardrail_api\",
                          \"mode\":\"pre_call\",
                          \"default_on\":true,
                          \"api_base\":\"http://pii-registry:8080\",
                          \"api_key\":\"$AK\"}}"
# -> {"guardrail_id": "...", "status": "pending_review", ...}

# post_call: restore <TYPE_N> tokens in the reply
curl -s -X POST "$GATE/guardrails/register" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d "{\"guardrail_name\":\"pii-presidio-restore\",
       \"team_id\":\"$TEAM\",
       \"litellm_params\":{\"guardrail\":\"generic_guardrail_api\",
                          \"mode\":\"post_call\",
                          \"default_on\":true,
                          \"api_base\":\"http://pii-registry:8080\",
                          \"api_key\":\"$AK\"}}"
```

#### 6.2 submissions + approve (status -> active, still no restart)

```bash
curl -s "$GATE/guardrails/submissions" -H "Authorization: Bearer $MK"

GR=$(curl -s "$GATE/guardrails/submissions" -H "Authorization: Bearer $MK" \
  | python3 -c "import json,sys; \
print([s['guardrail_id'] for s in json.load(sys.stdin)['submissions'] if s['guardrail_name']=='pii-presidio'][0])")

curl -s -X POST "$GATE/guardrails/submissions/$GR/approve" -H "Authorization: Bearer $MK"
# or reject instead:
curl -s -X POST "$GATE/guardrails/submissions/$GR/reject" -H "Authorization: Bearer $MK"
```

#### 6.3 list (Read)

```bash
curl -s "$GATE/guardrails/list" -H "Authorization: Bearer $MK"          # config.yaml ones (none by default)
curl -s "$GATE/guardrails/submissions" -H "Authorization: Bearer $MK"   # DB-managed ones live here
```

#### 6.4 show one (Read)

```bash
curl -s "$GATE/guardrails/$GR" -H "Authorization: Bearer $MK"
```

#### 6.5 update (Update) — change mode / api_base / default_on live

```bash
curl -s -X PATCH "$GATE/guardrails/$GR" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d "{\"guardrail_name\":\"pii-presidio\",
       \"litellm_params\":{\"guardrail\":\"generic_guardrail_api\",
                          \"mode\":\"post_call\",          # or pre_call
                          \"default_on\":false,            # opt-in per request
                          \"api_base\":\"http://pii-registry:8080\",
                          \"api_key\":\"$AK\"}}"
```

#### 6.6 test a registered guardrail without an LLM call

```bash
curl -s -X POST "$GATE/guardrails/apply_guardrail" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d '{"guardrail_name":"pii-presidio","text":"my account HDFC123456, email ravi@gmail.com"}'
# -> {"response_text": "my account <DEMO_ACCOUNT_1>, email <EMAIL_ADDRESS_2>"}
#    (token names depend on your current registry config; numbering is a
#     global per-text counter, so the second detection is always _N=2)
```

#### 6.7 delete (Delete) — and verify it took effect live

```bash
curl -s -X DELETE "$GATE/guardrails/$GR" -H "Authorization: Bearer $MK"
# -> {"message": "Guardrail <id> deleted successfully"}

# with no guardrails left, the LLM receives raw text (no masking):
curl -s "$GATE/chat/completions" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d '{"model":"gemma3","max_tokens":40,"messages":[{"role":"user","content":"Say hi to ravi@gmail.com"}]}'
```

#### one-command alternative: ./pii.sh

```bash
./pii.sh guardrail-add pii-presidio         http://pii-registry:8080 pre_call  true  # register + auto-approve (team auto-created)
./pii.sh guardrail-add pii-presidio-restore http://pii-registry:8080 post_call true
./pii.sh guardrail-list
./pii.sh guardrail-show pii-presidio
./pii.sh guardrail-update pii-presidio post_call            # [mode] [api_base]
./pii.sh guardrail-submissions
./pii.sh guardrail-approve <GUARDRAIL_ID>
./pii.sh guardrail-delete pii-presidio
```

Notes:
- `default_on:false` guardrails are opt-in per request: add
  `"guardrails":["name"]` to the chat body (section 5).
- Errors: `403` caller is not PROXY_ADMIN (use the master key), `404` unknown
  id, `400` invalid payload/mode.
- Rollback option: `config.yaml` still carries the old file-based guardrails as
  commented entries (`pii_crud_guardrail.py` stays mounted). Re-enabling those
  requires a container restart — the API path above never does.

---

## 7. Worked example: HDFC account numbers (5 → 6 digits → delete)

```bash
# 7a. create: any "HDFC" followed by exactly 5 digits -> <HDFC_ACCOUNT_1>
curl -s -X POST "$REG/recognizers" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"name":"HDFC_ACCOUNT",
       "patterns":[{"name":"HDFC_PAT","regex":"\\bHDFC[0-9]{5}(?![0-9])\\b","score":0.9}],
       "entity_action":"MASK"}'

# 7b. dry-run -> "My account is <HDFC_ACCOUNT_1> ok"
curl -s -X POST "$REG/test" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"text":"My account is HDFC12345 ok"}'

# 7c. end-to-end (LLM only ever sees <HDFC_ACCOUNT_1>; reply is restored)
curl -s "$GATE/chat/completions" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d '{"model":"gemma3","max_tokens":60,
       "messages":[{"role":"user","content":"Account HDFC12345 note it down"}]}'

# 7d. UPDATE the same recognizer to 6 digits (HDFC123456)
curl -s -X PATCH "$REG/recognizers/HDFC_ACCOUNT" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"patterns":[{"name":"HDFC_PAT","regex":"\\bHDFC[0-9]{6}(?![0-9])\\b","score":0.9}]}'

# 7e. verify the switch: 6-digit masked, 5-digit NOT masked anymore
curl -s -X POST "$REG/test" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"text":"HDFC123456 and HDFC12345"}'
# -> "…<HDFC_ACCOUNT_1> and HDFC12345"

# 7f. (optional) hard-block instead of mask -> HTTP 400 on any match
curl -s -X PATCH "$REG/entities/HDFC_ACCOUNT" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"action":"BLOCK"}'
# back to masking:  {"action":"MASK"}

# 7g. delete the rule (recognizer + auto entity)
curl -s -X DELETE "$REG/recognizers/HDFC_ACCOUNT" -H "X-API-Key: $AK"
curl -s -X DELETE "$REG/entities/HDFC_ACCOUNT"   -H "X-API-Key: $AK"
```

Why `(?![0-9])`: without it, the 5-digit rule `HDFC[0-9]{5}` would match
*inside* `HDFC123456` and leave a dangling `6` unmasked — the lookahead makes
each rule exact. On Linux you can write `\bHDFC[0-9]{5}\b` directly inside the
single-quoted JSON (bash keeps backslashes literal in single quotes).

---

## 8. Handy verification one-liners

```bash
# does my rule catch it? (registry dry-run, masked text only)
curl -s -X POST "$REG/test" -H "X-API-Key: $AK" \
  -H "Content-Type: application/json" \
  -d '{"text":"Contact ravi@asmltd.com, card 4111 1111 1111 1111"}' \
  | python3 -c "import json,sys; print(json.load(sys.stdin)['masked_text'])"

# what did the LLM actually receive? (masked input from the LiteLLM DB;
# podman exec here — use "docker exec" instead if the stack runs under Docker)
podman exec litellm-postgres psql -U litellm -p 9865 -d litellm -t -A -c \
  "SELECT proxy_server_request::jsonb->'messages'->-1->>'content'
     FROM \"LiteLLM_SpendLogs\" ORDER BY \"startTime\" DESC LIMIT 5"
```

Notes:
- Every registry change (POST/PATCH/DELETE) is audit-logged and live on the
  gateway's **next** request — no restarts, ever.
- Blocked (400) requests still appear in the spend logs with their original,
  unmasked content — LiteLLM logging behavior, not an LLM leak.
- With guardrails registered (section 6) and the registry stopped, the gateway
  fails **closed** — the request is rejected (HTTP 500), never sent unmasked.
- Full regression suite: `./pii_crud_tests.sh` (52 checks); API-guardrail mode
  (fail-closed section H): `REJECTS_ON_REGISTRY_DOWN=1 ./pii_crud_tests.sh`.
  Usage docs: `PII_CRUD_API.md` (registry CRUD + Swagger) and
  `PII_CRUD_GUARDRAIL.md` (guardrail internals + LiteLLM guardrail API +
  Portainer).
