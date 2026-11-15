"""
Runtime PII guardrail for LiteLLM — config fetched from pii-registry per request.

Replaces the built-in presidio guardrail so PII entities/recognizers can be
added/updated/removed at runtime via the pii-registry REST API (curl) with
zero container restarts.

Registered in config.yaml twice (same class, two entries):
  - mode: pre_call  -> masks input  (<TYPE_N> placeholders)
  - mode: post_call -> restores <TYPE_N> in the response

Fail-safety (env knobs):
  PII_REGISTRY_URL    registry base URL (required)
  PII_FAIL_OPEN       "true" => analyzer failure lets the request through
                      UNMASKED. Default: false (reject with 500 — never leak).
  PII_MAP_TTL_SECONDS token->value map lifetime (default 900)

Streaming note: <TYPE_N> restore is applied to non-streaming responses.
"""

import os
import re
import threading
import time
import uuid

import httpx
from fastapi import HTTPException

import litellm
from litellm.integrations.custom_guardrail import CustomGuardrail
from litellm._logging import verbose_proxy_logger

# Detections whose matched text is already a placeholder token are ignored
PLACEHOLDER_RE = re.compile(r"<[A-Z_]+_\d+>")


# Shared state lives on the cached `litellm` module object (imported once per
# process). LiteLLM may execute this guardrail file separately for EACH config
# entry (pre_call + post_call), giving each copy its own module globals —
# attaching to litellm guarantees both copies share one state.
def _state():
    st = getattr(litellm, "_pii_crud_state", None)
    if st is None:
        st = {
            "maps": {},   # litellm_call_id -> {"tokens": {...}, "ts": float}
            "cfg": None,  # last-known-good config from the registry
            "http": None, # shared AsyncClient
            "lock": threading.Lock(),
        }
        litellm._pii_crud_state = st
    return st


def _client() -> httpx.AsyncClient:
    st = _state()
    if st["http"] is None:
        st["http"] = httpx.AsyncClient(timeout=30)
    return st["http"]


class PiiCrudGuardrail(CustomGuardrail):
    def __init__(self, **kwargs):
        self.registry_url = os.getenv("PII_REGISTRY_URL", "http://pii-registry:8080").rstrip("/")
        self.fail_open = os.getenv("PII_FAIL_OPEN", "false").lower() == "true"
        self.map_ttl = int(os.getenv("PII_MAP_TTL_SECONDS", "900"))
        super().__init__(**kwargs)

    # ───────────────────── config ─────────────────────

    async def _get_config(self) -> dict:
        """Fetch config from registry; on failure use last-known-good."""
        st = _state()
        try:
            r = await _client().get(f"{self.registry_url}/config", timeout=5)
            r.raise_for_status()
            cfg = r.json()
            with st["lock"]:
                old = st["cfg"]
                if old is None or cfg.get("version") != old.get("version"):
                    verbose_proxy_logger.info(
                        "pii-crud guardrail: config version %s -> %s (%s entities, %s recognizers)",
                        (old or {}).get("version"), cfg.get("version"),
                        len(cfg.get("entities", {})), len(cfg.get("recognizers", [])),
                    )
                st["cfg"] = cfg
            return cfg
        except Exception as e:
            with st["lock"]:
                cached = st["cfg"]
            if cached is None:
                if self.fail_open:
                    verbose_proxy_logger.error(
                        "pii-crud guardrail: registry unreachable (%s) and no cached "
                        "config — PII_FAIL_OPEN=true, proceeding UNMASKED", e,
                    )
                    return {"version": -1, "entities": {}, "recognizers": []}
                raise HTTPException(
                    status_code=500,
                    detail="PII registry unreachable and no cached config — request "
                           "rejected (fail-closed, never send raw PII)",
                )
            verbose_proxy_logger.error(
                "pii-crud guardrail: registry unreachable (%s) — using last-known-good "
                "config version %s", e, cached.get("version"),
            )
            return cached

    # ───────────────────── analyzer ─────────────────────

    async def _analyze(self, text: str, entities: list, ad_hoc: list) -> list:
        payload = {"text": text, "entities": entities, "language": "en"}
        if ad_hoc:
            payload["ad_hoc_recognizers"] = ad_hoc
        try:
            r = await _client().post(
                f"{os.getenv('PRESIDIO_ANALYZER_API_BASE', 'http://presidio-analyzer:3000').rstrip('/')}/analyze",
                json=payload,
            )
            r.raise_for_status()
            return r.json()
        except Exception as e:
            if self.fail_open:
                verbose_proxy_logger.error(
                    "pii-crud guardrail: analyzer failed (%s) — PII_FAIL_OPEN=true, "
                    "proceeding UNMASKED", e,
                )
                return []
            raise HTTPException(
                status_code=500,
                detail="PII analyzer unavailable — request rejected (fail-closed)",
            )

    # ───────────────────── masking ─────────────────────

    @staticmethod
    def _resolve_overlaps(results: list, custom_entities=frozenset()) -> list:
        """Keep non-overlapping detections, ordered by start.

        Priority: longest span first (a full match always beats a subspan
        found by another recognizer), then custom recognizer entities over
        generic built-ins for equal spans (domain-specific intent, e.g.
        ASML_EMAIL vs EMAIL_ADDRESS), then highest score, then start.
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

    def _mask(self, text: str, chosen: list, tokens: dict) -> str:
        """Replace detections with <TYPE_N> (global counter, document order)."""
        spans, n = [], 0
        for r in chosen:
            n += 1
            token = f"<{r['entity_type']}_{n}>"
            tokens[token] = text[r["start"]:r["end"]]
            spans.append((r["start"], r["end"], token))
        for start, end, token in reversed(spans):
            text = text[:start] + token + text[end:]
        return text

    def _store_map(self, call_id: str, tokens: dict):
        if not tokens:
            return
        now = time.time()
        st = _state()
        with st["lock"]:
            st["maps"][call_id] = {"tokens": tokens, "ts": now}
            # Evict old entries + hard cap
            for k in [k for k, v in st["maps"].items() if now - v["ts"] > self.map_ttl]:
                st["maps"].pop(k, None)
            while len(st["maps"]) > 2000:
                oldest = min(st["maps"], key=lambda k: st["maps"][k]["ts"])
                st["maps"].pop(oldest, None)

    # ───────────────────── hooks ─────────────────────

    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        data = data if isinstance(data, dict) else {}
        messages = data.get("messages")
        prompt = data.get("prompt")
        texts = []
        if isinstance(messages, list):
            for msg in messages:
                if isinstance(msg, dict) and isinstance(msg.get("content"), str) and msg["content"]:
                    texts.append(msg["content"])
        elif isinstance(prompt, str) and prompt:
            texts.append(prompt)
        if not texts:
            return data

        cfg = await self._get_config()
        actions = cfg.get("entities", {})
        if not actions:
            return data
        entities = list(actions.keys())
        ad_hoc = [r for r in cfg.get("recognizers", []) if r.get("supported_entity") in actions]

        call_id = data.get("litellm_call_id") or f"local-{uuid.uuid4().hex}"
        tokens = {}
        for text in texts:
            results = await self._analyze(text, entities, ad_hoc)
            # BLOCK action: reject the whole request
            blocked = sorted({r["entity_type"] for r in results if actions.get(r["entity_type"]) == "BLOCK"})
            if blocked:
                raise HTTPException(
                    status_code=400,
                    detail={"error": "Blocked by PII policy", "entities": blocked},
                )
            usable = [r for r in results if not PLACEHOLDER_RE.fullmatch(text[r["start"]:r["end"]])]
            custom_entities = {r.get("supported_entity") for r in ad_hoc}
            chosen = self._resolve_overlaps(usable, custom_entities)
            if chosen:
                masked = self._mask(text, chosen, tokens)
                self._swap_text(text, masked, messages, prompt, data)
        self._store_map(call_id, tokens)
        data["litellm_call_id"] = call_id
        return data
    @staticmethod
    def _swap_text(old: str, masked: str, messages, prompt, data):
        """Put the masked text back wherever the original came from."""
        if isinstance(messages, list):
            for msg in messages:
                if isinstance(msg, dict) and msg.get("content") == old:
                    msg["content"] = masked
        if prompt == old and isinstance(data, dict):
            data["prompt"] = masked

    async def async_post_call_success_hook(self, data, user_api_key_dict, response):
        call_id = data.get("litellm_call_id") if isinstance(data, dict) else None
        if not call_id:
            return response
        st = _state()
        with st["lock"]:
            entry = st["maps"].get(call_id)
            tokens = dict(entry["tokens"]) if entry else {}
        if not tokens:
            return response

        choices = (
            response.get("choices", [])
            if isinstance(response, dict)
            else getattr(response, "choices", []) or []
        )
        for choice in choices:
            msg = choice.get("message") if isinstance(choice, dict) else getattr(choice, "message", None)
            if msg is None:
                continue
            content = (
                msg.get("content") if isinstance(msg, dict) else getattr(msg, "content", None)
            )
            if isinstance(content, str) and content:
                restored = content
                for token in sorted(tokens, key=len, reverse=True):
                    restored = restored.replace(token, tokens[token])
                if restored != content:
                    if isinstance(msg, dict):
                        msg["content"] = restored
                    else:
                        setattr(msg, "content", restored)
        return response
