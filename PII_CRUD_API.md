# Runtime PII CRUD — curl API Guide

Manage PII masking rules on the **live** LiteLLM gateway with plain curl calls
(or point-and-click via the built-in **Swagger UI** — section 0).
Every change takes effect on the **next request** — no container restarts, ever.

```
 ┌────────────┐  chat completions   ┌───────────────┐  fetch /config per request  ┌───────────────┐
 │   client   │ ──────────────────► │ LiteLLM :4000 │ ──────────────────────────► │ pii-registry  │
 └────────────┘                     │  (guardrail)  │                             │  :5003 (API)  │
                                    └───────┬───────┘                             └───────┬───────┘
                              mask <TYPE_N> │                                             │
                                            ▼                                             ▼
                                        Ollama LLM   ◄──────────── presidio-analyzer :5002 ──► Postgres (litellm DB)
                              ◄── restore real values (post_call)
```

- Registry base URL: `http://localhost:5003` (from the host) / `http://pii-registry:8080` (inside compose)
- Admin auth: header `X-API-Key: pii-admin-2026`  *(value of `PII_ADMIN_KEY` in `.env`)*
- Gateway: `http://localhost:4000` with `Authorization: Bearer $LITELLM_MASTER_KEY`

Run all examples from the project folder so `. ./.env` loads the keys:

```bash
cd /c/Users/stsel/Documents/litellm
. ./.env
REG="http://localhost:5003"
AK="$PII_ADMIN_KEY"
```

> Shortcut: almost everything below is also available as `./pii.sh <command>` —
> mapping table at the end. Prefer clicking over typing? Use the Swagger UI
> (**section 0**).
>
> Related docs:
> [`PII_CRUD_GUARDRAIL.md`](PII_CRUD_GUARDRAIL.md) — how the guardrail masks
> before the LLM / restores after it, LiteLLM's own guardrail API, fail-safety,
> and Portainer (http://localhost:9000) for browser-based stack management.

---

## 0. Swagger UI — the no-curl way

The registry ships interactive docs generated from its own OpenAPI spec:

| URL | What it is |
|---|---|
| **http://localhost:5003/docs** | Swagger UI — try every endpoint from the browser |
| http://localhost:5003/redoc | ReDoc — read-only reference view |
| http://localhost:5003/openapi.json | raw OpenAPI spec (import into Postman/Bruno) |

### 0.1 Authorize once

1. Open http://localhost:5003/docs
2. Click the green **Authorize** button (top right)
3. Paste the admin key (`pii-admin-2026`, the value of `PII_ADMIN_KEY` in `.env`)
4. Hit **Authorize** — the `X-API-Key` header is now attached to every
   "Try it out" call you make.

Endpoints without auth (health, version, config, listings, audit) work with or
without it; everything that mutates — plus `POST /test` — needs it.

### 0.2 The same worked example as section 1, in clicks

| Step | Endpoint | Body | Expect |
|---|---|---|---|
| Add | `POST /recognizers` | `{"name":"ASML_EMAIL","patterns":[{"name":"ASML_PAT","regex":"[A-Za-z0-9._%+-]+@asmltd[.]com","score":0.9}]}` | 200 `{"status":"created",...}` |
| Dry-run | `POST /test` | `{"text":"Contact ravi@asmltd.com"}` | `masked_text: "Contact <ASML_EMAIL_1>"` |
| Update | `PATCH /recognizers/ASML_EMAIL` | `{"score":0.95}` | 200 `{"status":"updated",...}` |
| Remove | `DELETE /recognizers/ASML_EMAIL` then `DELETE /entities/ASML_EMAIL` | — | 200 `{"status":"deleted",...}` |

Each operation has pre-filled example bodies in the UI — click **Try it out**,
tweak, **Execute**, read the response. Same rules as curl apply: changes are
live on the gateway's **next** request, no restarts, and every change lands in
the audit trail (`GET /audit`).

> Regexes in Swagger bypass Git-Bash argument parsing, so the MSYS gotcha in
> section 3 doesn't apply — but the body is still **JSON**: write escapes as
> `\\.` / `\\d{12}` in the JSON text (after the UI parses it, presidio receives
> `\.` / `\d{12}`).

---

## 1. Quick start — add a custom recognizer (worked example)

Goal: mask every email address ending in `@asmltd.com` as its own entity, live.

### 1.1 Create the recognizer (auto-creates the entity too)

```bash
curl -s -X POST "$REG/recognizers" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"name":"ASML_EMAIL",
       "patterns":[{"name":"ASML_PAT","regex":"[A-Za-z0-9._%+-]+@asmltd[.]com","score":0.9}]}'
```

Response:

```json
{"status":"created","name":"ASML_EMAIL","entity_action":"MASK",
 "spec":{"name":"ASML_EMAIL_Recognizer","supported_entity":"ASML_EMAIL",
         "patterns":[{"name":"ASML_PAT","regex":"[A-Za-z0-9._%+-]+@asmltd[.]com","score":0.9}]}}
```

### 1.2 Dry-run without calling the LLM

```bash
curl -s -X POST "$REG/test" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"text":"Contact ravi@asmltd.com or ravi@gmail.com"}' | python -m json.tool
```

```json
{
  "detections": [
    {"entity_type": "ASML_EMAIL",     "start": 8,  "end": 23, "score": 0.9, "text": "ravi@asmltd.com"},
    {"entity_type": "EMAIL_ADDRESS",  "start": 27, "end": 42, "score": 1.0, "text": "ravi@gmail.com"}
  ],
  "masked_text": "Contact <ASML_EMAIL_1> or <EMAIL_ADDRESS_2>",
  "token_map": {"<ASML_EMAIL_1>": "ravi@asmltd.com", "<EMAIL_ADDRESS_2>": "ravi@gmail.com"}
}
```

Custom recognizers win over generic built-ins on the *same* span; the longest
span always wins over a subspan.

### 1.3 Verify through the live gateway

```bash
curl -s http://localhost:4000/chat/completions \
  -H "Authorization: Bearer $LITELLM_MASTER_KEY" -H "Content-Type: application/json" \
  -d '{"model":"gemma3","max_tokens":80,
       "messages":[{"role":"user","content":"My work email is ravi@asmltd.com. Note it down."}]}'
```

The LLM only ever sees `<ASML_EMAIL_1>`; the reply has the token restored back
to `ravi@asmltd.com` if the model echoes it. Check what the LLM actually
received:

```bash
./view_logs.sh            # masked input + restored output per request
```

### 1.4 Remove it again

```bash
curl -s -X DELETE "$REG/recognizers/ASML_EMAIL" -H "X-API-Key: $AK"
curl -s -X DELETE "$REG/entities/ASML_EMAIL"   -H "X-API-Key: $AK"
```

---

## 2. Endpoint reference

### 2.1 Read-only (no auth)

| Endpoint | Purpose |
|---|---|
| `GET /health` | liveness + DB check |
| `GET /version` | current config version (bumps on every change) |
| `GET /config` | the effective config the gateway guardrail uses |

```bash
curl -s "$REG/config" | python -m json.tool
```

### 2.2 Entities — `POST /entities`

Add a presidio built-in entity (MASK by default). Name must be `UPPERCASE_SNAKE`.

```bash
curl -s -X POST "$REG/entities" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"name":"DATE_TIME","action":"MASK"}'
```

Body fields:

| Field | Values | Notes |
|---|---|---|
| `name` | `UPPERCASE_SNAKE` | must not already exist (409 otherwise) |
| `action` | `MASK` (default) or `BLOCK` | `BLOCK` = reject the request with HTTP 400 when detected |

### 2.3 Entities — `PATCH /entities/{name}`

Change action or enable/disable. Only send what you change.

```bash
# hard-block: requests containing a PERSON are rejected with 400
curl -s -X PATCH "$REG/entities/PERSON" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"action":"BLOCK"}'

# back to masking
curl -s -X PATCH "$REG/entities/PERSON" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"action":"MASK"}'

# stop masking entirely (entity stays configured but inactive)
curl -s -X PATCH "$REG/entities/UPI_ID" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"enabled":false}'

curl -s -X PATCH "$REG/entities/UPI_ID" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"enabled":true}'
```

### 2.4 Entities — `DELETE /entities/{name}`

```bash
curl -s -X DELETE "$REG/entities/DATE_TIME" -H "X-API-Key: $AK"
```

```json
{"status":"deleted","name":"DATE_TIME","orphaned_recognizers":[]}
```

> If `orphaned_recognizers` is non-empty, those recognizers no longer fire
> (their entity is gone). Delete them too if you want a clean config.

### 2.5 Recognizers — `POST /recognizers`

```bash
curl -s -X POST "$REG/recognizers" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{
        "name": "ASML_EMAIL",
        "patterns": [
          {"name": "ASML_PAT", "regex": "[A-Za-z0-9._%+-]+@asmltd[.]com", "score": 0.9}
        ],
        "score": 0.9,
        "context": ["work email", "company email"],
        "entity_action": "MASK"
      }'
```

Body fields:

| Field | Default | Notes |
|---|---|---|
| `name` | — | becomes BOTH the entity name and the recognizer (409 if taken) |
| `patterns` | `[]` | list of `{name, regex, score}`; regex must compile (400 otherwise) |
| `deny_list` | `[]` | plain terms to match (alternative to regex patterns) |
| `context` | `[]` | words that boost detection score when nearby |
| `score` | `0.9` | fallback score applied to patterns without one |
| `entity_action` | `MASK` | action of the auto-created entity (MASK or BLOCK) |

At least one `patterns` entry or one `deny_list` entry is required.

**Example — hard-block a domain with deny_list instead of regex:**

```bash
curl -s -X POST "$REG/recognizers" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"name":"COMPETITOR_DOMAIN","deny_list":["acme-corp.com"],"entity_action":"BLOCK"}'
```

### 2.6 Recognizers — `PATCH /recognizers/{name}`

```bash
# extend the regex to catch a second domain
curl -s -X PATCH "$REG/recognizers/ASML_EMAIL" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"patterns":[{"name":"ASML_PAT",
        "regex":"[A-Za-z0-9._%+-]+@asmltd[.]com|[A-Za-z0-9._%+-]+@asml[.]com",
        "score":0.9}]}'

# turn it off without deleting (generic EMAIL_ADDRESS still masks those emails)
curl -s -X PATCH "$REG/recognizers/ASML_EMAIL" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"enabled":false}'

# raise the detection score
curl -s -X PATCH "$REG/recognizers/ASML_EMAIL" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"score":0.95}'
```

### 2.7 Recognizers — `DELETE /recognizers/{name}`

```bash
curl -s -X DELETE "$REG/recognizers/ASML_EMAIL" -H "X-API-Key: $AK"
```

### 2.8 Listings

```bash
curl -s "$REG/entities"     | python -m json.tool   # all entities (incl. disabled)
curl -s "$REG/recognizers"  | python -m json.tool   # all recognizers (incl. disabled)
```

### 2.9 Dry-run — `POST /test`

Analyze + mask any text against the **current** config. No LLM call, no log row.

```bash
curl -s -X POST "$REG/test" \
  -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"text":"PAN ABCDE1234F, aadhaar 2345 6789 0123, card 4111 1111 1111 1111"}'
```

### 2.10 Ops — `POST /reload` and `GET /audit`

```bash
# force a version bump (guardrails already fetch /config every request,
# so reload is only for symmetry/audit bookkeeping)
curl -s -X POST "$REG/reload" -H "X-API-Key: $AK"

# recent config changes with timestamps
curl -s "$REG/audit?limit=20" | python -m json.tool
```

---

## 3. ⚠️ Git-Bash (MSYS) backslash gotcha — read this before pasting regexes

On this machine, curl runs from Git Bash (MSYS/MINGW). Bash/curl argument
parsing collapses `\\` → `\` and can mangle regexes in `-d` JSON strings:

```bash
# ❌ BROKEN — registry answers {"detail":"Invalid \escape"} and NOTHING is created
-d '{"regex":"[A-Za-z0-9._%+-]+@asmltd\\.com"}'
```

**Two safe options:**

1. **Avoid backslashes** — use `[.]` instead of `\.`, `\\b` is unnecessary here:

   ```bash
   -d '{"regex":"[A-Za-z0-9._%+-]+@asmltd[.]com"}'          # ✅ safe
   -d '{"regex":"[A-Za-z0-9._%+-]+[@]asmltd[.]com"}'        # ✅ safe
   ```

2. **Build the body with python and send it from a file** (needed for lookarounds,
   `\b`, `\d`, `^$` anchors, etc.):

   ```bash
   python -c "import json; open('/tmp/rgx.json','w').write(json.dumps({
       'name':'IMPS_REF','patterns':[{'name':'IMPS_PAT','regex':'IMPS\\\\d{12}','score':0.9}]}))"
   curl -s -X POST "$REG/recognizers" \
     -H "X-API-Key: $AK" -H "Content-Type: application/json" \
     --data-binary @/tmp/rgx.json
   ```

   (In the double-quoted python string each regex `\` is written `\\`, which
   `json.dumps` escapes again — the file gets the correct `\d`.)

`./pii.sh add-recognizer` already does this internally, so passing regexes to
`pii.sh` is always safe.

---

## 4. Behavior & fail-safety

| Event | What happens |
|---|---|
| CRUD change (POST/PATCH/DELETE) | audit row written + config version bumped; the gateway guardrail fetches `/config` on **every** request, so the next chat request uses the new config — no restart |
| Action `MASK` | value replaced with `<TYPE_N>` before the LLM, restored in the reply |
| Action `BLOCK` | request rejected with **HTTP 400** + list of blocking entity types |
| Entity `enabled: false` | entity not analyzed at all (no masking for it) |
| Recognizer `enabled: false` | recognizer off; a generic built-in may still catch the same value |
| Registry container down | guardrail uses the **last-known-good cached config** → masking continues |
| Presidio analyzer down | request rejected (500) — fail-closed, never send raw PII |
| Registry unreachable **and** no cache (fresh boot) | request rejected (500), fail-closed |

**BLOCK vs MASK gotcha:** blocked requests still appear in the LiteLLM spend
logs with their **original, unmasked** content (logging happens after the
guardrail rejects). That is LiteLLM's logging behavior, not a leak to the LLM.

---

## 5. Error codes

| Code | Trigger | Example body |
|---|---|---|
| 400 | invalid regex, bad action, bad name | `{"detail":"invalid regex in pattern 'x': missing ), unterminated subpattern at position 0"}` |
| 400 | name not UPPERCASE_SNAKE | `{"detail":"entity name must be UPPERCASE_SNAKE (letters/digits/_)"}` |
| 401 | missing/wrong `X-API-Key` | `{"detail":"admin key required (X-API-Key header)"}` |
| 404 | unknown entity/recognizer name | `{"detail":"entity 'FOO' not found"}` |
| 409 | name already exists | `{"detail":"recognizer 'ASML_EMAIL' already exists"}` |
| 502 | presidio analyzer error during `/test` | `{"detail":"presidio analyzer error: ..."}` |

---

## 6. `pii.sh` ↔ curl mapping

| `./pii.sh …` | Equivalent curl |
|---|---|
| `list` | `GET /entities` + `GET /recognizers` |
| `add-entity DATE_TIME [MASK\|BLOCK]` | `POST /entities` |
| `add-recognizer ASML_EMAIL 'REGEX' [score]` | `POST /recognizers` (backslash-safe) |
| `update ASML_EMAIL 'NEW_REGEX'` | `PATCH /recognizers/ASML_EMAIL` |
| `block-entity PERSON` / `mask-entity PERSON` | `PATCH /entities/PERSON {"action":"BLOCK\|MASK"}` |
| `disable E` / `enable E` | `PATCH /entities/E {"enabled":false\|true}` |
| `disable-recognizer R` / `enable-recognizer R` | `PATCH /recognizers/R {"enabled":false\|true}` |
| `remove NAME` | `DELETE /entities/NAME` + `DELETE /recognizers/NAME` |
| `test 'text'` | `POST /test` |
| `audit [n]` | `GET /audit?limit=n` |

### 6.1 Guardrail lifecycle via `pii.sh` (gateway :4000, live — no restarts)

| `./pii.sh …` | Equivalent gateway call |
|---|---|
| `guardrail-list` | `GET /guardrails/list` + `GET /guardrails/submissions` (DB-managed ones live there) |
| `guardrail-add NAME API_BASE [pre_call\|post_call] [true\|false]` | `POST /guardrails/register` (team `pii-admin` auto-created) **+ auto-approve** → active |
| `guardrail-show NAME_OR_ID` | `GET /guardrails/{id}` |
| `guardrail-update NAME_OR_ID [pre_call\|post_call] [API_BASE]` | `GET /guardrails/{id}` + `PATCH /guardrails/{id}` |
| `guardrail-delete NAME_OR_ID` | `DELETE /guardrails/{id}` |
| `guardrail-submissions` / `guardrail-approve ID` | raw review-queue access (approve is normally automatic) |

Notes:
- Only `litellm_params.guardrail: "generic_guardrail_api"` is accepted by
  `/guardrails/register` on v1.109.1 — the permanent masking guardrails
  (`pii-crud` / `pii-crud-restore`) come from `config.yaml` and need no
  management.
- `guardrail-add` approves immediately, so the guardrail is **active** in the
  same command; use `guardrail-submissions` + `guardrail-approve` if you want
  a human review step instead.

---

## 7. Handy verification one-liners

```bash
# effective config the guardrail is using right now
curl -s "$REG/config" | python -c "import json,sys; c=json.load(sys.stdin); \
print('version', c['version']); print('entities:', len(c['entities']), '| recognizers:', len(c['recognizers']))"

# does my new rule catch it? (no LLM call)
curl -s -X POST "$REG/test" -H "X-API-Key: $AK" -H "Content-Type: application/json" \
  -d '{"text":"Contact ravi@asmltd.com now"}' | python -c "import json,sys; \
print(json.load(sys.stdin)['masked_text'])"

# end-to-end: what did the LLM actually receive for this exact prompt?
./view_logs.sh
```

Full end-to-end regression suite (makes ~17 real LLM calls):

```bash
./pii_crud_tests.sh
```

---

## 8. What needs a restart? (answer: none of this)

| Task | Where | Restarts needed |
|---|---|---|
| Add / update / delete PII entity or regex recognizer, MASK ↔ BLOCK | this doc (registry, :5003) | **none** |
| Create / approve / update / delete a LiteLLM guardrail | `./pii.sh guardrail-*` (gateway, :4000) — see §6.1 | **none** |
| Manage containers in a browser | Portainer http://localhost:9000 | n/a (it *is* the restart tool, if ever needed) |
| Change model backend (Ollama ↔ vLLM) or guardrail entries in `config.yaml` | edit file + `podman compose up -d --force-recreate litellm` | this is the only restart path |

### 8.1 Where the data lives (all in the Postgres container — nothing is a file DB)

| Data | Store |
|---|---|
| PII entities, recognizers, audit trail, config version | Postgres container → database `pii_registry` (self-provisioned by pii-registry on startup — survives redeploys, volume `litellm_postgres_data`) |
| LiteLLM keys, teams, guardrail registrations, spend logs | Postgres container → database `litellm` |
| `pii_baseline.json` | one-time seed source only — after first boot the DB is the source of truth |
