# Runtime PII Guardrails — how the LiteLLM gateway masks & restores

The gateway runs **only** the runtime-managed PII guardrails. Every other
guardrail has been removed.

| Guardrail (config.yaml) | Mode | What it does |
|---|---|---|
| `pii-crud` | `pre_call` | Fetches live config from pii-registry, detects PII with presidio, replaces values with `<TYPE_N>` before the LLM sees them |
| `pii-crud-restore` | `post_call` | Swaps `<TYPE_N>` tokens in the reply back to the real values before the client sees them |

Both entries point to the same class — `pii_crud_guardrail.PiiCrudGuardrail` —
and run on **every** request (`default_on: true`). No opt-in, no per-request
flags.

> **Removed:** the `global-system-prompt` guardrail (system-message injector).
> Its config block, the `system_prompt_guardrail.py` mount in
> `docker-compose.yml`, the `GLOBAL_SYSTEM_PROMPT` var in `.env`, and the file
> itself are all gone. Responses no longer get a summary-style system prompt
> prepended.

---

## 1. Request flow

```
client ──► LiteLLM :4000
              │
              │  pre_call (pii-crud)
              │    1. GET http://pii-registry:8080/config        ← every request
              │    2. POST presidio-analyzer :3000/analyze        ← text + entities + ad-hoc recognizers
              │    3. action BLOCK?  → reject with HTTP 400
              │    4. else replace each detection with <TYPE_N>
              ▼
          Ollama / vLLM           (sees ONLY masked text)
              │
              │  post_call (pii-crud-restore)
              │    replace <TYPE_N> tokens in the reply with the real values
              ▼
client ◄── response
```

Because the config is fetched **per request**, any change made through the
registry API (curl / Swagger UI / `pii.sh`) applies to the very next chat
request — no restarts. CRUD operations are documented in
[`PII_CRUD_API.md`](PII_CRUD_API.md).

> **Guarantee: mask before the LLM, unmask after.**
> - The LLM (Ollama or vLLM — whichever is configured) can only ever receive
>   `<TYPE_N>` placeholders, because masking happens in `pre_call` before
>   routing. Proof: the spend-logs `input (masked)` column in `view_logs.sh`
>   shows the LLM's actual input, e.g.
>   `My card is <CREDIT_CARD_1> and email <EMAIL_ADDRESS_2>. Repeat them.`
> - The client gets real values back only via the `post_call` restore — the
>   un-masking happens *after* the LLM response, never before it.
> - BLOCK-ed requests never reach the LLM at all (rejected with 400).

## 2. Masking rules (pre_call)

- **Entities** from `/config` are the `{name: action}` map — `MASK` replaces
  with `<TYPE_N>`, `BLOCK` rejects the request with **HTTP 400** and a list of
  the blocking types.
- **Custom recognizers** are sent to presidio as `ad_hoc_recognizers` — but
  only those whose `supported_entity` is also present (and enabled) in the
  entity map.
- **Overlap resolution** — one winner per span, priority order:
  1. **longest span wins** (a full `CREDIT_CARD` beats an `AADHAAR` subspan),
  2. custom recognizer beats generic built-in on *equal* spans
     (`ASML_EMAIL` beats `EMAIL_ADDRESS`),
  3. higher presidio score, then earlier position.
- Text that already looks like a placeholder (`<PERSON_1>`) is never
  re-analyzed as PII.
- Tokens use one global counter per message in document order:
  `<EMAIL_ADDRESS_1>`, `<CREDIT_CARD_2>`, …

## 3. Restore rules (post_call)

- Token→value maps are stored **per request** (keyed by `litellm_call_id`),
  shared between the two guardrail entries via `litellm._pii_crud_state`.
- Replacement runs longest-token-first so `<INDIAN_PAN_1>` never half-matches
  inside `<INDIAN_PAN_NUMBER_1>`-style tokens.
- Result semantics (what `pii_crud_tests.sh` checks):
  - **PASS** — client sees the real values again,
  - **FAIL** — a token is still visible in the reply (map entry missing/expired
    or the model invented a token that was never masked),
  - **INFO** — the model paraphrased instead of echoing tokens; nothing to
    restore (expected with small models like gemma3-270m).
- Known limitation: the `<TYPE_N>` counter restarts per message, so if two
  different messages mask the same type, the later value wins in the shared
  map — restore may return the wrong original for the earlier message's token.
- **Streaming:** restore applies to non-streaming responses.

## 4. Fail-safety

| Situation | Behavior |
|---|---|
| Registry down | guardrail falls back to the **last-known-good cached config** → masking continues, request logged as version mismatch in logs |
| Registry down + no cache (fresh boot) | request rejected with **500** (fail-closed) |
| Presidio analyzer down | request rejected with **500** (fail-closed) |
| `PII_FAIL_OPEN=true` (env) | analyzer/registry failure lets the request through **unmasked** — opt-in only, default is fail-closed |
| Config version change | logged: `pii-crud guardrail: config version X -> Y (N entities, M recognizers)` |

## 5. Environment (set in `docker-compose.yml`)

| Var | Default | Purpose |
|---|---|---|
| `PII_REGISTRY_URL` | `http://pii-registry:8080` | where `/config` is fetched from |
| `PRESIDIO_ANALYZER_API_BASE` | `http://presidio-analyzer:3000` | presidio analyze endpoint |
| `PII_FAIL_OPEN` | `false` | `true` = proceed unmasked on backend failure (dangerous) |
| `PII_MAP_TTL_SECONDS` | `900` | token→value map lifetime; maps also hard-capped at 2000 entries |

## 6. Verify

```bash
./pii_crud_tests.sh     # full regression: 52 checks incl. mask/restore/BLOCK/fail-safety
./view_logs.sh          # per-request DB log: masked input + restored output
./pii.sh test 'text'    # dry-run masking without an LLM call (registry /test)
```

The spend-logs `input (masked)` column in `view_logs.sh` shows **exactly what
the LLM received** — that column must never contain raw PII.

> Note: requests **rejected** by a `BLOCK` entity still appear in the spend
> logs with their original, unmasked content — LiteLLM logs after the
> guardrail rejects. That is LiteLLM's logging behavior, not a leak to the LLM.

## 7. Files

| File | Role |
|---|---|
| `pii_crud_guardrail.py` | the guardrail class (mask + restore hooks) — mounted read-only into the LiteLLM container |
| `config.yaml` | the two `pii-crud` / `pii-crud-restore` entries under `guardrails:` |
| `docker-compose.yml` | mounts the guardrail file, sets `PII_REGISTRY_URL` / analyzer URLs; also runs **Portainer** |
| `PII_CRUD_API.md` | how to manage entities/recognizers at runtime (curl + Swagger) |

---

## 8. Portainer — manage the stack from a browser

`docker-compose.yml` runs a **Portainer CE** container (2.45.3) so the whole
stack can be inspected / restarted / stopped from a UI instead of podman
commands.

| | |
|---|---|
| URL | http://localhost:9000 |
| Login | **admin / admin@123456** (same password as the LiteLLM UI) |
| Environment | `local-podman` (pre-added) — lists all 6 containers |
| Data | persisted in the `portainer_data` volume |
| Socket | podman API socket mounted via the `podman_socket` volume |

### 8.1 Setup quirks (already applied in `docker-compose.yml`)

- **5-minute init window** — the admin account must be created within
  ~5 minutes of a fresh start, otherwise Portainer answers
  `Administrator initialization timeout` and the container has to be
  restarted first. It was initialized with the credentials above; restarts of
  the container don't reset it (data lives in the `portainer_data` volume).
- **Setup token** — each fresh Portainer start prints a one-time
  `setup_token=...` in its logs (`podman logs portainer`). Creating the admin
  via API needs header `X-Setup-Token: <token>`; creating it in the browser
  setup screen needs the token pasted there.
- **Socket gotcha** — podman-compose (Windows) translates absolute host paths
  like `/var/run/docker.sock` to `C:\...` (it once created a stray
  `C:\var\run\docker.sock` directory — removed). The compose file therefore
  mounts the podman API socket through the `podman_socket` named volume
  (`device: /run/podman` resolves **inside** the podman machine VM) and the
  environment URL is `unix:///var/run/podman/podman.sock`.

Using Portainer's *Restart* on `litellm-pii-gateway` is safe — config, PII
entities and recognizers all live in files/Postgres, nothing is lost. But for
the daily flow you never need it: every rule change is applied live by the
registry (section 9), no restart involved.

---

## 9. LiteLLM guardrail management API — tested on v1.109.1

The gateway itself exposes guardrail APIs (admin key required,
`Authorization: Bearer $LITELLM_MASTER_KEY`). What they can and cannot do:

| Endpoint | Works? | Notes |
|---|---|---|
| `GET /guardrails/list` | ✅ | lists the config.yaml guardrails (`pii-crud`, `pii-crud-restore`) |
| `POST /guardrails/register` | ✅ but limited | **only `litellm_params.guardrail: "generic_guardrail_api"` is accepted** — custom file-based classes like `PiiCrudGuardrail` are rejected; requires `team_id` |
| `GET /guardrails/submissions` | ✅ | dynamic registrations land as `pending_review` |
| `POST /guardrails/submissions/{id}/approve` | ✅ | status → `active`, applied to requests **without restart** |
| `GET/PUT/PATCH/DELETE /guardrails/{guardrail_id}` | ✅ | inspect/update/delete dynamic guardrails |

> **Custom guardrails cannot be created via API in v1.109.1.** The two
> `config.yaml` entries (mask + restore) are the permanent runtime guardrails.
> The runtime path for *new masking rules* is the pii-registry CRUD
> (`PII_CRUD_API.md`) — a new entity/recognizer is picked up by the existing
> guardrails on the next request.

### 9.1 Tested lifecycle (curl, no restarts at any step)

> One-command version: `./pii.sh guardrail-add NAME API_BASE [pre_call|post_call] [true|false]`
> (registers, auto-approves → active). Also `guardrail-list`, `guardrail-show`,
> `guardrail-update NAME [mode] [api_base]`, `guardrail-delete`. See
> `PII_CRUD_API.md` §6.1.

```bash
MK="sk-litellm-master-key-2026"   # LITELLM_MASTER_KEY
GATE="http://localhost:4000"

# 0. (once) guardrails are team-scoped - create a team
curl -s -X POST "$GATE/team/new" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d '{"team_alias":"pii-admin"}'
# -> team_id: 076f6509-...   (already created in this stack)

# 1. register (ONLY generic_guardrail_api; needs litellm_params.api_base)
curl -s -X POST "$GATE/guardrails/register" \
  -H "Authorization: Bearer $MK" -H "Content-Type: application/json" \
  -d '{"guardrail_name":"my-guardrail","team_id":"<team_id>",
       "litellm_params":{"guardrail":"generic_guardrail_api","mode":"pre_call",
                         "default_on":false,"api_base":"http://my-endpoint:8000"}}'
# -> {"guardrail_id":"<id>","status":"pending_review"}

# 2. review & approve
curl -s "$GATE/guardrails/submissions" -H "Authorization: Bearer $MK"
curl -s -X POST "$GATE/guardrails/submissions/<id>/approve" -H "Authorization: Bearer $MK"
# -> {"status":"active"}  - now runs on requests that reference it by name,
#    verified live with zero container restarts

# 3. use it per request (default_on:false -> opt-in)
curl -s "$GATE/chat/completions" ... -d '{"model":"gemma3",
       "guardrails":["my-guardrail"], "messages":[...]}'

# 4. delete
curl -s -X DELETE "$GATE/guardrails/<guardrail_id>" -H "Authorization: Bearer $MK"
```

### 9.2 The no-restart rule change flow (the one that matters daily)

```bash
# create a new PII rule: regex -> MASK
curl -s -X POST "http://localhost:5003/recognizers" \
  -H "X-API-Key: $PII_ADMIN_KEY" -H "Content-Type: application/json" \
  -d '{"name":"DEMO_INVOICE","patterns":[{"name":"DEMO_PAT","regex":"INV-[0-9]{6}","score":0.9}],"entity_action":"MASK"}'
# next gateway request: "Invoice number INV-202411" -> "Invoice number <DEMO_INVOICE_1>"   (verified)

# flip it to hard-block
curl -s -X PATCH "http://localhost:5003/entities/DEMO_INVOICE" \
  -H "X-API-Key: $PII_ADMIN_KEY" -H "Content-Type: application/json" -d '{"action":"BLOCK"}'
# next gateway request with INV-202411 -> HTTP 400   (verified)

# remove it again
curl -s -X DELETE "http://localhost:5003/recognizers/DEMO_INVOICE" -H "X-API-Key: $PII_ADMIN_KEY"
curl -s -X DELETE "http://localhost:5003/entities/DEMO_INVOICE"   -H "X-API-Key: $PII_ADMIN_KEY"
```

Every step above was executed live: the LLM received
`Invoice number <DEMO_INVOICE_1>`, then the request was rejected with 400,
then the rule disappeared — and the gateway container was never restarted.
