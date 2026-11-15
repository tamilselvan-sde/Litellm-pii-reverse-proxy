"""
PII Registry — runtime CRUD for PII entities & custom regex recognizers.

Config lives in Postgres (same DB as LiteLLM). The LiteLLM gateway's
pii_crud_guardrail fetches /config on every request, so any change made
through this API (curl or Swagger UI) takes effect on the NEXT request —
no container restarts.

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
from typing import Optional

import httpx
import psycopg
from psycopg.rows import dict_row
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

DB_URL = os.getenv("PII_DATABASE_URL", "")
ADMIN_KEY = os.getenv("PII_ADMIN_KEY", "")
ANALYZER = os.getenv("PII_ANALYZER_URL", "http://presidio-analyzer:3000").rstrip("/")
NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")

app = FastAPI(
    title="PII Registry",
    version="1.1.0",
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
CREATE TABLE IF NOT EXISTS pii_config_version (
  id      INT PRIMARY KEY DEFAULT 1,
  version BIGINT NOT NULL DEFAULT 1
);
"""


def q(sql, params=(), fetch=False):
    """One-shot query with its own connection (local DB, cheap & thread-safe)."""
    with psycopg.connect(DB_URL, autocommit=True) as conn:
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(sql, params)
            if fetch:
                return cur.fetchall()
            return None


def audit(op, target, payload=None, actor="admin"):
    q(
        "INSERT INTO pii_config_audit(op, target, payload, actor) VALUES (%s, %s, %s::jsonb, %s)",
        (op, target, json.dumps(payload) if payload is not None else None, actor),
    )


def bump_version():
    q("UPDATE pii_config_version SET version = version + 1 WHERE id = 1")


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


def init_db():
    q(DDL)
    q("INSERT INTO pii_config_version(id, version) VALUES (1, 1) ON CONFLICT (id) DO NOTHING")
    # Seed once from the baseline snapshot (current prod config at migration time)
    if not q("SELECT 1 FROM pii_entities LIMIT 1", fetch=True):
        with open("/app/pii_baseline.json", "r", encoding="utf-8") as f:
            base = json.load(f)
        for e in base.get("entities", []):
            q(
                "INSERT INTO pii_entities(name, action, enabled, updated_by)"
                " VALUES (%s, %s, TRUE, 'seed') ON CONFLICT (name) DO NOTHING",
                (e["name"], e.get("action", "MASK")),
            )
            audit("seed-entity", e["name"], e, "seed")
        for r in base.get("recognizers", []):
            q(
                "INSERT INTO pii_recognizers(name, spec, enabled, updated_by)"
                " VALUES (%s, %s::jsonb, TRUE, 'seed') ON CONFLICT (name) DO NOTHING",
                (r["name"], json.dumps(r)),
            )
            audit("seed-recognizer", r["name"], r, "seed")
        bump_version()


for _attempt in range(30):
    try:
        init_db()
        break
    except Exception:
        if _attempt == 29:
            raise
        time.sleep(2)


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


def mask_text(text, chosen):
    """Replace detections with <TYPE_N> (global counter, document order)."""
    tokens, spans, n = {}, [], 0
    for r in chosen:
        n += 1
        token = f"<{r['entity_type']}_{n}>"
        tokens[token] = text[r["start"]:r["end"]]
        spans.append((r["start"], r["end"], token))
    for start, end, token in reversed(spans):
        text = text[:start] + token + text[end:]
    return text, tokens


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
    if q("SELECT 1 FROM pii_entities WHERE name = %s", (body.name,), fetch=True):
        raise HTTPException(409, f"entity '{body.name}' already exists")
    q(
        "INSERT INTO pii_entities(name, action, updated_by) VALUES (%s, %s, %s)",
        (body.name, body.action, "admin"),
    )
    audit("add-entity", body.name, body.model_dump())
    bump_version()
    return {"status": "created", "name": body.name, "action": body.action}


@app.patch("/entities/{name}", tags=["entities"], summary="Update entity action/enabled")
def patch_entity(name: str, body: EntityPatch, _key: str = Depends(require_key)):
    if not q("SELECT 1 FROM pii_entities WHERE name = %s", (name,), fetch=True):
        raise HTTPException(404, f"entity '{name}' not found")
    if body.action is not None:
        if body.action not in ("MASK", "BLOCK"):
            raise HTTPException(400, "action must be MASK or BLOCK")
        q("UPDATE pii_entities SET action = %s, updated_by = 'admin' WHERE name = %s", (body.action, name))
    if body.enabled is not None:
        q("UPDATE pii_entities SET enabled = %s, updated_by = 'admin' WHERE name = %s", (body.enabled, name))
    audit("patch-entity", name, body.model_dump(exclude_none=True))
    bump_version()
    row = q("SELECT * FROM pii_entities WHERE name = %s", (name,), fetch=True)
    return {"status": "updated", "entity": row[0]}


@app.delete("/entities/{name}", tags=["entities"], summary="Remove entity")
def delete_entity(name: str, _key: str = Depends(require_key)):
    if not q("SELECT 1 FROM pii_entities WHERE name = %s", (name,), fetch=True):
        raise HTTPException(404, f"entity '{name}' not found")
    orphans = q(
        "SELECT name FROM pii_recognizers WHERE spec->>'supported_entity' = %s", (name,), fetch=True
    )
    q("DELETE FROM pii_entities WHERE name = %s", (name,))
    audit("delete-entity", name, {"orphaned_recognizers": [o["name"] for o in orphans]})
    bump_version()
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

    # The entity must exist AND be requested for the recognizer to ever fire
    q(
        "INSERT INTO pii_entities(name, action, updated_by) VALUES (%s, %s, 'auto:recognizer')"
        " ON CONFLICT (name) DO NOTHING",
        (body.name, body.entity_action),
    )
    q(
        "INSERT INTO pii_recognizers(name, spec, updated_by) VALUES (%s, %s::jsonb, %s)",
        (body.name, json.dumps(spec), "admin"),
    )
    audit("add-recognizer", body.name, spec)
    bump_version()
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
    q("UPDATE pii_recognizers SET spec = %s::jsonb, updated_by = 'admin' WHERE name = %s", (json.dumps(spec), name))
    if body.enabled is not None:
        q("UPDATE pii_recognizers SET enabled = %s, updated_by = 'admin' WHERE name = %s", (body.enabled, name))
    audit("patch-recognizer", name, body.model_dump(exclude_none=True))
    bump_version()
    row = q("SELECT * FROM pii_recognizers WHERE name = %s", (name,), fetch=True)
    return {"status": "updated", "recognizer": row[0]}


@app.delete("/recognizers/{name}", tags=["recognizers"], summary="Remove recognizer")
def delete_recognizer(name: str, _key: str = Depends(require_key)):
    if not q("SELECT 1 FROM pii_recognizers WHERE name = %s", (name,), fetch=True):
        raise HTTPException(404, f"recognizer '{name}' not found")
    q("DELETE FROM pii_recognizers WHERE name = %s", (name,))
    audit("delete-recognizer", name)
    bump_version()
    return {"status": "deleted", "name": name}


# ──────────────────────────── ops ────────────────────────────

@app.post("/reload", tags=["ops"], summary="Force config version bump")
def reload_config(_key: str = Depends(require_key)):
    bump_version()
    audit("reload", "*")
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
    masked, tokens = mask_text(body.text, chosen)
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
