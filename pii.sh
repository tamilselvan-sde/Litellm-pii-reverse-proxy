#!/usr/bin/env bash
# Runtime PII entity/recognizer CRUD — no container restarts needed.
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
set -u
cd "$(dirname "$0")"
. ./.env
REG="http://localhost:5003"
AK="$PII_ADMIN_KEY"

json_post() { curl -s --max-time 30 -X POST "$REG$1" -H "X-API-Key: $AK" -H "Content-Type: application/json" -d "$2"; }
json_patch() { curl -s --max-time 30 -X PATCH "$REG$1" -H "X-API-Key: $AK" -H "Content-Type: application/json" -d "$2"; }
# JSON body built by python - safe for any regex (MSYS mangles backslashes in args)
jbody() { python -c "import json,sys; open(sys.argv[1],'w').write(json.dumps(json.loads(sys.argv[2])))" "$TMPJ" "$1"; }
TMPJ="$(mktemp)"

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

  *)
    echo "unknown command: $cmd"; exit 1 ;;
esac
