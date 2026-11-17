#!/usr/bin/env bash
# Runtime PII + guardrail management — no container restarts needed.
# Changes take effect on the NEXT request through the LiteLLM gateway.
#
# Usage examples:
#   ./pii.sh list                          # entities + recognizers
#   ./pii.sh add-entity DATE_TIME          # add built-in presidio entity
#   ./pii.sh add-recognizer ASML_EMAIL '[A-Za-z0-9._%+-]+@asmltd\.com'
#   ./pii.sh block-person                  # make PERSON a hard block (400)
#   ./pii.sh mask-person                   # back to MASK
#   ./pii.sh disable UPI_ID                # stop masking an entity
#   ./pii.sh enable UPI_ID
#   ./pii.sh update ASML_EMAIL '[A-Za-z0-9._%+-]+@asmltd\.com|@asml\.com'
#   ./pii.sh remove ASML_EMAIL
#   ./pii.sh test 'Contact me at ravi@asmltd.com'
#   ./pii.sh audit 15
#
# LiteLLM guardrail lifecycle (DB-managed, live without restarts):
#   ./pii.sh guardrail-list                         # all guardrails
#   ./pii.sh guardrail-add my-gr http://my-svc:8000 [pre_call|post_call] [true|false]
#                                                   # register + approve -> active
#   ./pii.sh guardrail-show my-gr                   # details by id or name
#   ./pii.sh guardrail-update my-gr post_call       # change mode (and api_base opt)
#   ./pii.sh guardrail-delete my-gr
set -u
cd "$(dirname "$0")"
. ./.env
REG="http://localhost:5003"
GATE="http://localhost:4000"
AK="$PII_ADMIN_KEY"
MK="$LITELLM_MASTER_KEY"

json_post() { curl -s --max-time 30 -X POST "$REG$1" -H "X-API-Key: $AK" -H "Content-Type: application/json" -d "$2"; }
json_patch() { curl -s --max-time 30 -X PATCH "$REG$1" -H "X-API-Key: $AK" -H "Content-Type: application/json" -d "$2"; }
# JSON body built by python - safe for any regex (MSYS mangles backslashes in args)
jbody() { python -c "import json,sys; open(sys.argv[1],'w').write(json.dumps(json.loads(sys.argv[2])))" "$TMPJ" "$1"; }
TMPJ="$(mktemp)"

# ── LiteLLM guardrail API (gateway :4000, master key) — python helper ──
# All JSON built/parsed in python: immune to MSYS backslash/quote mangling.
grapi() { # grapi <subcommand> [args...]  (see dispatch below)
  python - "$GATE" "$MK" "$@" <<'PY'
import json, sys, urllib.request, urllib.error

gate, mk = sys.argv[1], sys.argv[2]
sub = sys.argv[3]
args = sys.argv[4:]

def call(path, data=None, method=None):
    req = urllib.request.Request(
        gate + path,
        data=json.dumps(data).encode() if data is not None else None,
        headers={"Authorization": "Bearer " + mk, "Content-Type": "application/json"},
        method=method or ("POST" if data is not None else "GET"),
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode()
            return json.loads(body) if body.strip() else {}
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read().decode())
        except Exception:
            return {"error": str(e)}

def list_all():
    """config.yaml guardrails + DB-managed ones (they live in /submissions)."""
    out = []
    for g in call("/guardrails/list").get("guardrails", []):
        out.append(g)
    for g in call("/guardrails/submissions").get("submissions", []):
        if not any(x.get("guardrail_id") == g.get("guardrail_id") for x in out):
            out.append(g)
    return out

def resolve(id_or_name):
    for g in list_all():
        if g.get("guardrail_id") == id_or_name or g.get("guardrail_name") == id_or_name:
            return g
    return None

def ensure_team():
    for t in call("/team/list?page=1"):
        if t.get("team_alias") == "pii-admin":
            return t["team_id"]
    return call("/team/new", {"team_alias": "pii-admin"})["team_id"]

def bail(msg):
    print(msg)
    sys.exit(1)

if sub == "list":
    for g in list_all():
        p = g.get("litellm_params") or {}
        status = g.get("status") or "config"
        gid = g.get("guardrail_id") or "(config.yaml)"
        print(f"  {g['guardrail_name']:<22} {(p.get('mode') or ''):<9} "
              f"default_on={str(p.get('default_on')):<5} {status:<8} {gid}")
    sys.exit(0)

if sub == "add":  # name api_base [mode] [default_on] [api_key]
    if len(args) < 2:
        bail("usage: guardrail-add NAME API_BASE [pre_call|post_call] [true|false]")
    name, api_base = args[0], args[1]
    mode = args[2] if len(args) > 2 else "pre_call"
    default_on = args[3].lower() == "true" if len(args) > 3 else False
    api_key = args[4] if len(args) > 4 and args[4] else None
    if mode not in ("pre_call", "post_call"):
        bail("mode must be pre_call or post_call")
    payload = {
        "guardrail_name": name,
        "team_id": ensure_team(),
        "litellm_params": {
            "guardrail": "generic_guardrail_api",  # only accepted value on v1.109.1
            "mode": mode,
            "default_on": default_on,
            "api_base": api_base,
        },
    }
    if api_key:  # forwarded by litellm as x-api-key (registry auth)
        payload["litellm_params"]["api_key"] = api_key
    reg = call("/guardrails/register", payload)
    gid = reg.get("guardrail_id")
    if not gid:
        bail("register failed: " + json.dumps(reg))
    print(f"registered {name} -> {gid} (status: {reg.get('status')})")
    app = call(f"/guardrails/submissions/{gid}/approve", {})
    print("approved -> " + json.dumps(app.get("status") or app))
    sys.exit(0)

g = resolve(args[0]) if args else None
if g is None:
    bail(f"guardrail '{args[0] if args else ''}' not found")
gid = g.get("guardrail_id") or g.get("guardrail_name")

if sub == "show":
    print(json.dumps(call(f"/guardrails/{gid}"), indent=2))
elif sub == "update":  # id_or_name [mode] [api_base]
    mode = args[1] if len(args) > 1 else None
    api_base = args[2] if len(args) > 2 else None
    lp = g.get("litellm_params") or {}
    lp["guardrail"] = "generic_guardrail_api"
    if mode:
        if mode not in ("pre_call", "post_call"):
            bail("mode must be pre_call or post_call")
        lp["mode"] = mode
    if api_base:
        lp["api_base"] = api_base
    body = {"guardrail_name": g["guardrail_name"], "litellm_params": lp}
    out = call(f"/guardrails/{gid}", body, method="PATCH")
    print(json.dumps({"status": "updated", "name": out.get("guardrail_name"),
                      "mode": (out.get("litellm_params") or {}).get("mode"),
                      "api_base": (out.get("litellm_params") or {}).get("api_base")}))
elif sub == "delete":
    out = call(f"/guardrails/{gid}", method="DELETE")
    print(json.dumps(out))
else:
    bail(f"unknown guardrail subcommand: {sub}")
PY
}

cmd="${1:-list}"; shift || true

case "$cmd" in
  list)
    echo "── Entities ──"
    curl -s "$REG/entities" | python -c "import json,sys; [print(f\"  {e['name']:<22} {e['action']:<6} {'on' if e['enabled'] else 'OFF'}\") for e in json.load(sys.stdin)]"
    echo "── Recognizers ──"
    curl -s "$REG/recognizers" | python -c "import json,sys; [print(f\"  {r['name']:<34} {'on' if r['enabled'] else 'OFF'}\") for r in json.load(sys.stdin)]"
    ;;

  add-entity)
    [ $# -lt 1 ] && { echo "usage: ./pii.sh add-entity ENTITY_NAME [MASK|BLOCK]"; exit 1; }
    json_post /entities "{\"name\":\"$1\",\"action\":\"${2:-MASK}\"}" ; echo
    ;;

  add-recognizer)
    [ $# -lt 2 ] && { echo "usage: ./pii.sh add-recognizer NAME REGEX [score]"; exit 1; }
    jbody "{\"name\":\"$1\",\"patterns\":[{\"name\":\"${1}_PATTERN\",\"regex\":\"$2\",\"score\":${3:-0.9}}]}" \
      && curl -s --max-time 30 -X POST "$REG/recognizers" -H "X-API-Key: $AK" -H "Content-Type: application/json" --data-binary @"$TMPJ" ; echo
    ;;

  update)
    [ $# -lt 2 ] && { echo "usage: ./pii.sh update RECOGNIZER_NAME NEW_REGEX"; exit 1; }
    jbody "{\"patterns\":[{\"name\":\"${1}_PATTERN\",\"regex\":\"$2\",\"score\":0.9}]}" \
      && curl -s --max-time 30 -X PATCH "$REG/recognizers/$1" -H "X-API-Key: $AK" -H "Content-Type: application/json" --data-binary @"$TMPJ" ; echo
    ;;

  block-entity)  json_patch "/entities/$1" '{"action":"BLOCK"}' ; echo ;;
  mask-entity)   json_patch "/entities/$1" '{"action":"MASK"}' ; echo ;;
  disable)       json_patch "/entities/$1" '{"enabled":false}' ; echo ;;
  enable)        json_patch "/entities/$1" '{"enabled":true}' ; echo ;;
  disable-recognizer) json_patch "/recognizers/$1" '{"enabled":false}' ; echo ;;
  enable-recognizer)  json_patch "/recognizers/$1" '{"enabled":true}' ; echo ;;

  remove)
    [ $# -lt 1 ] && { echo "usage: ./pii.sh remove NAME"; exit 1; }
    curl -s --max-time 30 -X DELETE "$REG/entities/$1" -H "X-API-Key: $AK" ; echo
    curl -s --max-time 30 -X DELETE "$REG/recognizers/$1" -H "X-API-Key: $AK" ; echo
    ;;

  test)
    [ $# -lt 1 ] && { echo "usage: ./pii.sh test \"some text with PII\""; exit 1; }
    json_post /test "{\"text\":\"$1\"}" | python -c "
import json,sys
d=json.load(sys.stdin)
if 'detail' in d: print('ERROR:', d['detail']); sys.exit(0)
print('detections:')
for x in d['detections']: print(f\"  {x['entity_type']:<22} score={x['score']:<5} {x['text']!r}\")
print('masked:', d['masked_text'])"
    ;;

  audit)
    curl -s "$REG/audit?limit=${1:-15}" | python -c "import json,sys; [print(f\"  {a['ts'][:19]}  {a['op']:<18} {a['target']}\") for a in json.load(sys.stdin)]"
    ;;

  # ── LiteLLM guardrail lifecycle (DB-managed — live, no restarts) ──
  guardrail-list)
    grapi list
    ;;

  guardrail-add)
    [ $# -lt 2 ] && { echo "usage: ./pii.sh guardrail-add NAME API_BASE [pre_call|post_call] [default_on true|false]"; exit 1; }
    # $AK (PII_ADMIN_KEY) is appended automatically -> litellm sends it as
    # x-api-key so the registry guardrail endpoint enforces auth
    grapi add "$@" "$AK"
    ;;

  guardrail-show)
    [ $# -lt 1 ] && { echo "usage: ./pii.sh guardrail-show NAME_OR_ID"; exit 1; }
    grapi show "$@"
    ;;

  guardrail-update)
    [ $# -lt 2 ] && { echo "usage: ./pii.sh guardrail-update NAME_OR_ID [pre_call|post_call] [API_BASE]"; exit 1; }
    grapi update "$@"
    ;;

  guardrail-delete)
    [ $# -lt 1 ] && { echo "usage: ./pii.sh guardrail-delete NAME_OR_ID"; exit 1; }
    grapi delete "$@"
    ;;

  guardrail-submissions)
    python -c "
import json, urllib.request
req = urllib.request.Request('$GATE/guardrails/submissions', headers={'Authorization': 'Bearer $MK'})
print(json.dumps(json.load(urllib.request.urlopen(req)), indent=2))"
    ;;

  guardrail-approve)
    [ $# -lt 1 ] && { echo "usage: ./pii.sh guardrail-approve GUARDRAIL_ID"; exit 1; }
    python -c "
import json, urllib.request
req = urllib.request.Request('$GATE/guardrails/submissions/$1/approve', data=b'{}',
    headers={'Authorization': 'Bearer $MK', 'Content-Type': 'application/json'}, method='POST')
print(json.dumps(json.load(urllib.request.urlopen(req)), indent=2))"
    ;;

  *)
    echo "unknown command: $cmd"; exit 1 ;;
esac
