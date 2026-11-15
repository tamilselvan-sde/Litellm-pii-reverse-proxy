#!/usr/bin/env bash
# View recent LiteLLM requests: masked input + restored output.
# Usage: ./view_logs.sh [count]     (default 5)
N=${1:-5}
podman exec litellm-postgres psql -U litellm -p 9865 -d litellm -c "
SELECT \"startTime\"::timestamp(0) AS time,
       left(model, 12) AS model,
       left(proxy_server_request::jsonb->'messages'->0->>'content', 90) AS \"input (masked)\",
       left(response::jsonb->'choices'->0->'message'->>'content', 90) AS output
FROM \"LiteLLM_SpendLogs\"
ORDER BY \"startTime\" DESC
LIMIT ${N};"
