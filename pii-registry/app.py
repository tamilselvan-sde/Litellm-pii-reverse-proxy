"""
PII Registry — runtime CRUD for PII entities & custom regex recognizers.

Config lives in its own `pii_registry` Postgres database (never the `litellm`
one — its tables would block LiteLLM's Prisma migrations). The database is
created here automatically if missing, so the stack is self-provisioning on
any fresh Postgres volume. The LiteLLM gateway's pii_crud_guardrail fetches
/config on every request, so any change made through this API (curl or
Swagger UI) takes effect on the NEXT request — no container restarts.

Interactive docs:
  http://localhost:5003/docs   ← Swagger UI (click "Authorize", paste admin key)
  http://localhost:5003/redoc  ← ReDoc

Auth: every mutating endpoint + /test + /audit need the admin key
(env PII_ADMIN_KEY) as the X-API-Key header.
"""

import json
import os
import re
import time
from contextlib import asynccontextmanager, contextmanager
from typing import Optional

import httpx
import psycopg
from psycopg import errors as pg_errors
from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

DB_URL = os.getenv("PII_DATABASE_URL", "")
ADMIN_KEY = os.getenv("PII_ADMIN_KEY", "")
ANALYZER = os.getenv("PII_ANALYZER_URL", "http://presidio-analyzer:3000").rstrip("/")
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")

_pool: Optional[ConnectionPool] = None

app = FastAPI(
    title="PII Registry",
    version="1.2.0",
    description=(
        "Runtime CRUD for PII entities & custom regex recognizers used by the "
        "LiteLLM gateway's `pii-crud` guardrail.\n\n"
        "**1. Click *Authorize* and paste the admin key** (env `PII_ADMIN_KEY`).\n\n"
        "**2. Use any endpoint below.** Changes apply on the gateway's next "
        "request — no container restarts.\n\n"
        "Verify results without an LLM call via `POST /test`."
    ),
)

# Swagger UI "Authorize" button (paste PII_ADMIN_KEY there once)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


# ──────────────────────────── DB helpers ────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS pii_entities (
  name       TEXT PRIMARY KEY,
  action     TEXT NOT NULL DEFAULT 'MASK',
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  updated_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pii_recognizers (
  name       TEXT PRIMARY KEY,
  spec       JSONB NOT NULL,
  enabled    BOOLEAN NOT NULL DEFAULT TRUE,
  updated_by TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS pii_config_audit (
  id      BIGSERIAL PRIMARY KEY,
  ts      TIMESTAMPTZ NOT NULL DEFAULT now(),
  op      TEXT NOT NULL,
  target  TEXT NOT NULL,
  payload JSONB,
  actor   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS pii_config_audit_ts_idx ON pii_config_audit (ts DESC);
CREATE TABLE IF NOT EXISTS pii_config_version (
  id      INT PRIMARY KEY DEFAULT 1,
  version BIGINT NOT NULL DEFAULT 1
);
"""


def _get_pool() -> ConnectionPool:
    global _pool
    if _pool is None:
        _pool = ConnectionPool(
            DB_URL,
            name="pii-registry-pool",
            min_size=2,
            max_size=10,
            timeout=15,
            # Validate connections before handing them out — survives a
            # Postgres restart without serving dead connections.
            check=ConnectionPool.check_connection,
            kwargs={"autocommit": True, "row_factory": dict_row},
        )
    return _pool


@contextmanager
def tx():
    """Atomically run several statements in one pooled connection.

    Yields a cursor (dict rows). Every statement joins one BEGIN/COMMIT, so
    e.g. insert + audit + version bump either all land or none do.
    """
    with _get_pool().connection() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                yield cur


def q(sql, params=(), fetch=False):
    """One-shot query on a pooled connection (local DB, cheap & thread-safe)."""
    with _get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params)
            if fetch:
                return cur.fetchall()
            return None


def audit(op, target, payload=None, actor="admin", cur=None):
    sql = "INSERT INTO pii_config_audit(op, target, payload, actor) VALUES (%s, %s, %s::jsonb, %s)"
    args = (op, target, json.dumps(payload) if payload is not None else None, actor)
    if cur is not None:
        cur.execute(sql, args)
    else:
        q(sql, args)


def bump_version(cur=None):
    sql = "UPDATE pii_config_version SET version = version + 1 WHERE id = 1"
    if cur is not None:
        cur.execute(sql)
    else:
        q(sql)


def current_version():
    rows = q("SELECT version FROM pii_config_version WHERE id = 1", fetch=True)
    return rows[0]["version"] if rows else 1


def effective():
    ents = q("SELECT name, action, enabled FROM pii_entities ORDER BY name", fetch=True)
    recs = q("SELECT name, spec, enabled FROM pii_recognizers ORDER BY name", fetch=True)
    return {
        "version": current_version(),
        "entities": {r["name"]: r["action"] for r in ents if r["enabled"]},
        "recognizers": [r["spec"] for r in recs if r["enabled"]],
    }


def ensure_database():
    """Create the `pii_registry` database if it doesn't exist yet.

    Self-provisioning: works on any fresh Postgres volume AND on volumes
    that were initialized before this change (replaces
    docker-entrypoint-initdb.d/init-pii-db.sql, which only ever ran on
    first volume init).
    """
    # Same host/port/credentials, maintenance database `postgres`
    maintenance_url = DB_URL.rsplit("/", 1)[0] + "/postgres"
    with psycopg.connect(maintenance_url, autocommit=True) as conn:
        exists = conn.execute(
            "SELECT 1 FROM pg_database WHERE datname = 'pii_registry'"
        ).fetchone()
        if exists is None:
            conn.execute("CREATE DATABASE pii_registry")


def init_db():
    q(DDL)
    q("INSERT INTO pii_config_version(id, version) VALUES (1, 1) ON CONFLICT (id) DO NOTHING")
    # Seed once from the baseline snapshot (current prod config at migration time)
    if not q("SELECT 1 FROM pii_entities LIMIT 1", fetch=True):
        with open("/app/pii_baseline.json", "r", encoding="utf-8") as f:
            base = json.load(f)
        with tx() as cur:  # whole seed lands atomically
            for e in base.get("entities", []):
                cur.execute(
                    "INSERT INTO pii_entities(name, action, enabled, updated_by)"
                    " VALUES (%s, %s, TRUE, 'seed') ON CONFLICT (name) DO NOTHING",
                    (e["name"], e.get("action", "MASK")),
                )
                audit("seed-entity", e["name"], e, "seed", cur=cur)
            for r in base.get("recognizers", []):
                cur.execute(
                    "INSERT INTO pii_recognizers(name, spec, enabled, updated_by)"
                    " VALUES (%s, %s::jsonb, TRUE, 'seed') ON CONFLICT (name) DO NOTHING",
                    (r["name"], json.dumps(r)),
                )
                audit("seed-recognizer", r["name"], r, "seed", cur=cur)
            bump_version(cur=cur)


@asynccontextmanager
async def lifespan(_app):
    # uvicorn runs this before serving; the compose service-level healthcheck
    # keeps dependents waiting until the DB is ready and seeded.
    last = None
    for attempt in range(30):
        try:
            ensure_database()
            init_db()
            _get_pool().wait(timeout=30)
            break
        except Exception as exc:  # Postgres not up yet — retry
            last = exc
            if _pool is not None:
                try:
                    _pool.close()
                except Exception:
                    pass
                globals()["_pool"] = None
            if attempt == 29:
                raise RuntimeError(f"pii-registry could not initialize DB: {last}")
            time.sleep(2)
    yield
    if _pool is not None:
        _pool.close()


app.router.lifespan_context = lifespan


# ──────────────────────────── auth ────────────────────────────

async def require_key(x_api_key: Optional[str] = Depends(api_key_header)) -> str:
    if not ADMIN_KEY or x_api_key != ADMIN_KEY:
        raise HTTPException(status_code=401, detail="admin key required (X-API-Key header)")
    return x_api_key


# ──────────────────────────── models ────────────────────────────

class Pattern(BaseModel):
    model_config = {"json_schema_extra": {"examples": [
        {"name": "ASML_PAT", "regex": "[A-Za-z0-9._%+-]+@asmltd[.]com", "score": 0.9}
    ]}}
    name: str = "pattern"
    regex: str = Field(description="Python regex; avoid backslashes if calling from Git Bash curl")
    score: float = 0.9


class EntityIn(BaseModel):
    model_config = {"json_schema_extra": {"examples": [{"name": "DATE_TIME", "action": "MASK"}]}}
    name: str = Field(description="UPPERCASE_SNAKE, e.g. DATE_TIME")
    action: str = Field(default="MASK", description="MASK (replace with <TYPE_N>) or BLOCK (reject with 400)")


class EntityPatch(BaseModel):
    model_config = {"json_schema_extra": {"examples": [{"action": "BLOCK"}]}}
    action: Optional[str] = None
    enabled: Optional[bool] = None


class RecognizerIn(BaseModel):
    model_config = {"json_schema_extra": {"examples": [{
        "name": "ASML_EMAIL",
        "patterns": [{"name": "ASML_PAT", "regex": "[A-Za-z0-9._%+-]+@asmltd[.]com", "score": 0.9}],
        "entity_action": "MASK",
    }]}}
    name: str = Field(description="UPPERCASE_SNAKE; becomes BOTH the entity and the recognizer")
    patterns: list[Pattern] = []
    deny_list: list[str] = Field(default=[], description="plain terms to match (alternative to patterns)")
    context: list[str] = Field(default=[], description="nearby words that boost the score")
    score: float = 0.9
    entity_action: str = Field(default="MASK", description="action of the auto-created entity")


class RecognizerPatch(BaseModel):
    model_config = {"json_schema_extra": {"examples": [{"enabled": False}]}}
    patterns: Optional[list[Pattern]] = None
    deny_list: Optional[list[str]] = None
    context: Optional[list[str]] = None
    score: Optional[float] = None
    enabled: Optional[bool] = None


class TestIn(BaseModel):
    model_config = {"json_schema_extra": {"examples": [
        {"text": "Contact ravi@asmltd.com, PAN ABCDE1234F"}
    ]}}
    text: str


# ──────────────────────────── masking helpers (mirror of guardrail) ────────────────────────────

def resolve_overlaps(results, custom_entities=frozenset()):
    """Keep non-overlapping detections; order by start.

    Priority: longest span first (a full match always beats a subspan found
    by another recognizer), then custom recognizer entities over generic
    built-ins for equal spans, then highest score, then start.
    """
    def sort_key(r):
        is_custom = 0 if r["entity_type"] in custom_entities else 1
        return (-(r["end"] - r["start"]), is_custom, -float(r.get("score", 0)), r["start"])

    chosen = []
    for r in sorted(results, key=sort_key):
        if all(r["end"] <= c["start"] or r["start"] >= c["end"] for c in chosen):
            chosen.append(r)
    chosen.sort(key=lambda x: x["start"])
    return chosen


# Detections whose matched text is already a placeholder token are ignored
PLACEHOLDER_RE = re.compile(r"<[A-Z_]+_\d+>")


def mask_text(text, chosen, start_n=0):
    """Replace detections with <TYPE_N> (global counter, document order).

    start_n lets a caller keep ONE global counter across several texts (per
    LLM call), so every token is unique within the call and the restore map
    never has the same token mapped to two different values.
    """
    tokens, spans, n = {}, [], start_n
    for r in chosen:
        n += 1
        token = f"<{r['entity_type']}_{n}>"
        tokens[token] = text[r["start"]:r["end"]]
        spans.append((r["start"], r["end"], token))
    for start, end, token in reversed(spans):
        text = text[:start] + token + text[end:]
    return text, tokens, n


def call_analyzer(text, entities, ad_hoc):
    payload = {"text": text, "entities": entities, "language": "en"}
    if ad_hoc:
        payload["ad_hoc_recognizers"] = ad_hoc
    resp = httpx.post(f"{ANALYZER}/analyze", json=payload, timeout=30)
    resp.raise_for_status()
    return resp.json()


# ──────────────────────────── read endpoints ────────────────────────────

@app.get("/health", tags=["status"], summary="Liveness + DB check")
def health():
    q("SELECT 1", fetch=True)
    return {"status": "ok"}


@app.get("/version", tags=["status"], summary="Current config version")
def version():
    return {"version": current_version()}


@app.get("/config", tags=["status"], summary="Effective config the gateway guardrail uses")
def config():
    return effective()


@app.get("/entities", tags=["entities"], summary="List all entities (incl. disabled)")
def list_entities():
    return q("SELECT * FROM pii_entities ORDER BY name", fetch=True)


@app.get("/recognizers", tags=["recognizers"], summary="List all recognizers (incl. disabled)")
def list_recognizers():
    return q("SELECT * FROM pii_recognizers ORDER BY name", fetch=True)


@app.get("/audit", tags=["status"], summary="Recent config changes")
def get_audit(limit: int = 50):
    return q(
        "SELECT * FROM pii_config_audit ORDER BY ts DESC LIMIT %s", (limit,), fetch=True
    )


# ──────────────────────────── entity CRUD ────────────────────────────

@app.post("/entities", tags=["entities"], summary="Add entity (MASK or BLOCK)")
def add_entity(body: EntityIn, _key: str = Depends(require_key)):
    if not NAME_RE.match(body.name):
        raise HTTPException(400, "entity name must be UPPERCASE_SNAKE (letters/digits/_)")
    if body.action not in ("MASK", "BLOCK"):
        raise HTTPException(400, "action must be MASK or BLOCK")
    try:
        with tx() as cur:  # insert + audit + version bump land atomically
            cur.execute(
                "INSERT INTO pii_entities(name, action, updated_by) VALUES (%s, %s, %s)",
                (body.name, body.action, "admin"),
            )
            audit("add-entity", body.name, body.model_dump(), cur=cur)
            bump_version(cur=cur)
    except pg_errors.UniqueViolation:
        raise HTTPException(409, f"entity '{body.name}' already exists")
    return {"status": "created", "name": body.name, "action": body.action}


@app.patch("/entities/{name}", tags=["entities"], summary="Update entity action/enabled")
def patch_entity(name: str, body: EntityPatch, _key: str = Depends(require_key)):
    if not q("SELECT 1 FROM pii_entities WHERE name = %s", (name,), fetch=True):
        raise HTTPException(404, f"entity '{name}' not found")
    sets, args = [], []
    if body.action is not None:
        if body.action not in ("MASK", "BLOCK"):
            raise HTTPException(400, "action must be MASK or BLOCK")
        sets.append("action = %s")
        args.append(body.action)
    if body.enabled is not None:
        sets.append("enabled = %s")
        args.append(body.enabled)
    if sets:
        sets += ["updated_by = 'admin'", "updated_at = now()"]
        args.append(name)
        with tx() as cur:
            cur.execute(f"UPDATE pii_entities SET {', '.join(sets)} WHERE name = %s", args)
            audit("patch-entity", name, body.model_dump(exclude_none=True), cur=cur)
            bump_version(cur=cur)
    else:  # no-op patch still bumps so the gateway re-reads config
        with tx() as cur:
            audit("patch-entity", name, {}, cur=cur)
            bump_version(cur=cur)
    row = q("SELECT * FROM pii_entities WHERE name = %s", (name,), fetch=True)
    return {"status": "updated", "entity": row[0]}


@app.delete("/entities/{name}", tags=["entities"], summary="Remove entity")
def delete_entity(name: str, _key: str = Depends(require_key)):
    if not q("SELECT 1 FROM pii_entities WHERE name = %s", (name,), fetch=True):
        raise HTTPException(404, f"entity '{name}' not found")
    orphans = q(
        "SELECT name FROM pii_recognizers WHERE spec->>'supported_entity' = %s", (name,), fetch=True
    )
    with tx() as cur:
        cur.execute("DELETE FROM pii_entities WHERE name = %s", (name,))
        audit("delete-entity", name, {"orphaned_recognizers": [o["name"] for o in orphans]}, cur=cur)
        bump_version(cur=cur)
    return {"status": "deleted", "name": name, "orphaned_recognizers": [o["name"] for o in orphans]}


# ──────────────────────────── recognizer CRUD ────────────────────────────

@app.post("/recognizers", tags=["recognizers"], summary="Add custom recognizer (auto-creates its entity)")
def add_recognizer(body: RecognizerIn, _key: str = Depends(require_key)):
    if not NAME_RE.match(body.name):
        raise HTTPException(400, "recognizer name must be UPPERCASE_SNAKE (letters/digits/_)")
    if not body.patterns and not body.deny_list:
        raise HTTPException(400, "provide at least one pattern or deny_list entry")
    for p in body.patterns:
        try:
            re.compile(p.regex)
        except re.error as e:
            raise HTTPException(400, f"invalid regex in pattern '{p.name}': {e}")
    if q("SELECT 1 FROM pii_recognizers WHERE name = %s", (body.name,), fetch=True):
        raise HTTPException(409, f"recognizer '{body.name}' already exists")

    spec = {"name": f"{body.name}_Recognizer", "supported_entity": body.name}
    if body.patterns:
        spec["patterns"] = [p.model_dump() for p in body.patterns]
    if body.deny_list:
        spec["deny_list"] = body.deny_list
    if body.context:
        spec["context"] = body.context

    # The entity must exist AND be requested for the recognizer to ever fire.
    # Everything (entity + recognizer + audit + version bump) is one transaction.
    try:
        with tx() as cur:
            cur.execute(
                "INSERT INTO pii_entities(name, action, updated_by) VALUES (%s, %s, 'auto:recognizer')"
                " ON CONFLICT (name) DO NOTHING",
                (body.name, body.entity_action),
            )
            cur.execute(
                "INSERT INTO pii_recognizers(name, spec, updated_by) VALUES (%s, %s::jsonb, %s)",
                (body.name, json.dumps(spec), "admin"),
            )
            audit("add-recognizer", body.name, spec, cur=cur)
            bump_version(cur=cur)
    except pg_errors.UniqueViolation:
        raise HTTPException(409, f"recognizer '{body.name}' already exists")
    return {"status": "created", "name": body.name, "entity_action": body.entity_action, "spec": spec}


@app.patch("/recognizers/{name}", tags=["recognizers"], summary="Update recognizer patterns/enabled")
def patch_recognizer(name: str, body: RecognizerPatch, _key: str = Depends(require_key)):
    rows = q("SELECT spec FROM pii_recognizers WHERE name = %s", (name,), fetch=True)
    if not rows:
        raise HTTPException(404, f"recognizer '{name}' not found")
    spec = rows[0]["spec"]
    if body.patterns is not None:
        for p in body.patterns:
            try:
                re.compile(p.regex)
            except re.error as e:
                raise HTTPException(400, f"invalid regex in pattern '{p.name}': {e}")
        spec["patterns"] = [p.model_dump() for p in body.patterns]
    if body.deny_list is not None:
        spec["deny_list"] = body.deny_list
    if body.context is not None:
        spec["context"] = body.context
    if body.score is not None:
        for p in spec.get("patterns", []):
            p["score"] = body.score
    with tx() as cur:
        cur.execute(
            "UPDATE pii_recognizers SET spec = %s::jsonb, updated_by = 'admin', updated_at = now() WHERE name = %s",
            (json.dumps(spec), name),
        )
        if body.enabled is not None:
            cur.execute(
                "UPDATE pii_recognizers SET enabled = %s, updated_by = 'admin', updated_at = now() WHERE name = %s",
                (body.enabled, name),
            )
        audit("patch-recognizer", name, body.model_dump(exclude_none=True), cur=cur)
        bump_version(cur=cur)
    row = q("SELECT * FROM pii_recognizers WHERE name = %s", (name,), fetch=True)
    return {"status": "updated", "recognizer": row[0]}


@app.delete("/recognizers/{name}", tags=["recognizers"], summary="Remove recognizer")
def delete_recognizer(name: str, _key: str = Depends(require_key)):
    if not q("SELECT 1 FROM pii_recognizers WHERE name = %s", (name,), fetch=True):
        raise HTTPException(404, f"recognizer '{name}' not found")
    with tx() as cur:
        cur.execute("DELETE FROM pii_recognizers WHERE name = %s", (name,))
        audit("delete-recognizer", name, cur=cur)
        bump_version(cur=cur)
    return {"status": "deleted", "name": name}


# ──────────────────────────── ops ────────────────────────────

@app.post("/reload", tags=["ops"], summary="Force config version bump")
def reload_config(_key: str = Depends(require_key)):
    with tx() as cur:
        bump_version(cur=cur)
        audit("reload", "*", cur=cur)
    return {"status": "reloaded", "version": current_version()}


@app.post("/test", tags=["ops"], summary="Dry-run: analyze + mask text (no LLM call)")
def dry_run(body: TestIn, _key: str = Depends(require_key)):
    cfg = effective()
    entities = list(cfg["entities"].keys())
    if not entities:
        return {"detections": [], "masked_text": body.text, "token_map": {}}
    ad_hoc = [r for r in cfg["recognizers"] if r.get("supported_entity") in cfg["entities"]]
    try:
        results = call_analyzer(body.text, entities, ad_hoc)
    except Exception as e:
        raise HTTPException(502, f"presidio analyzer error: {e}")
    chosen = resolve_overlaps(results, {r.get("supported_entity") for r in ad_hoc})
    masked, tokens, _n = mask_text(body.text, chosen)
    return {
        "detections": [
            {
                "entity_type": r["entity_type"],
                "start": r["start"],
                "end": r["end"],
                "score": r["score"],
                "text": body.text[r["start"]:r["end"]],
            }
            for r in chosen
        ],
        "masked_text": masked,
        "token_map": tokens,
    }


# ──────────────────── LiteLLM Generic Guardrail API endpoint ────────────────────
#
# Lets LiteLLM register this registry as a LIVE presidio guardrail via the
# gateway API (no config.yaml, no restarts):
#
#   ./pii.sh guardrail-add pii-presidio http://pii-registry:8080 pre_call true
#   ./pii.sh guardrail-add pii-presidio-restore http://pii-registry:8080 post_call true
#
# Wire format (litellm GenericGuardrailAPI integration):
#   request  {litellm_call_id, texts: [...], input_type: "request"|"response", ...}
#   response {action: "NONE"|"BLOCKED"|"GUARDRAIL_INTERVENED",
#             blocked_reason?, texts?: [...same length as input...]}
# Returned texts are written back positionally into the message contents.
# Fail-closed: analyzer down -> 502 (litellm rejects); registry down ->
# litellm's unreachable_fallback="fail_closed" rejects. PII never leaks.

_GR_TTL = int(os.getenv("PII_MAP_TTL_SECONDS", "900"))
_GR_MAPS: dict = {}
_GR_LOCK = __import__("threading").Lock()


def _gr_store(call_id: str, tokens: dict):
    if not call_id or not tokens:
        return
    now = time.time()
    with _GR_LOCK:
        _GR_MAPS[call_id] = {"tokens": tokens, "ts": now}
        for k in [k for k, v in _GR_MAPS.items() if now - v["ts"] > _GR_TTL]:
            _GR_MAPS.pop(k, None)
        while len(_GR_MAPS) > 2000:
            oldest = min(_GR_MAPS, key=lambda k: _GR_MAPS[k]["ts"])
            _GR_MAPS.pop(oldest, None)


def _gr_load(call_id):
    if not call_id:
        return {}
    with _GR_LOCK:
        entry = _GR_MAPS.get(call_id)
        return dict(entry["tokens"]) if entry else {}


class GenericGuardrailRequest(BaseModel):
    # The rest of the payload (request_data, request_headers, structured_
    # messages, tools, model, ...) is accepted and ignored.
    model_config = {"extra": "allow"}
    litellm_call_id: Optional[str] = None
    texts: list[str] = []
    input_type: str = "request"


@app.post(
    "/beta/litellm_basic_guardrail_api",
    tags=["ops"],
    summary="Generic Guardrail API — presidio mask (pre_call) / restore (post_call)",
)
def litellm_basic_guardrail_api(body: GenericGuardrailRequest, _key: str = Depends(require_key)):
    cfg = effective()
    actions = cfg["entities"]
    entities = list(actions.keys())
    ad_hoc = [r for r in cfg["recognizers"] if r.get("supported_entity") in actions]
    custom_entities = {r.get("supported_entity") for r in ad_hoc}

    if body.input_type != "response":  # pre_call: mask (or BLOCK)
        if not body.texts:
            return {"action": "NONE"}
        out, tokens, n = [], {}, 0
        for text in body.texts:
            if not text:
                out.append(text)
                continue
            try:
                results = call_analyzer(text, entities, ad_hoc)
            except Exception as e:
                raise HTTPException(502, f"presidio analyzer error: {e}")
            blocked = sorted({r["entity_type"] for r in results if actions.get(r["entity_type"]) == "BLOCK"})
            if blocked:
                return {
                    "action": "BLOCKED",
                    "blocked_reason": "Blocked by PII policy: " + ", ".join(blocked),
                }
            usable = [r for r in results if not PLACEHOLDER_RE.fullmatch(text[r["start"]:r["end"]])]
            chosen = resolve_overlaps(usable, custom_entities)
            masked, tk, n = mask_text(text, chosen, n)
            tokens.update(tk)
            out.append(masked)
        if tokens:
            _gr_store(body.litellm_call_id, tokens)
            return {"action": "GUARDRAIL_INTERVENED", "texts": out}
        return {"action": "NONE"}

    # post_call: restore <TYPE_N> tokens (longest first) in the reply
    tokens = _gr_load(body.litellm_call_id)
    if not tokens or not body.texts:
        return {"action": "NONE"}
    out, changed = [], False
    for text in body.texts:
        restored = text
        for token in sorted(tokens, key=len, reverse=True):
            if token in restored:
                restored = restored.replace(token, tokens[token])
                changed = True
        out.append(restored)
    if changed:
        return {"action": "GUARDRAIL_INTERVENED", "texts": out}
    return {"action": "NONE"}
