# Docker Compose deployment

Bring signet up in front of a local LLM in 60 seconds:

    cp .env.example .env
    # edit .env, set SIGNET_HMAC_SECRET = $(openssl rand -hex 32)
    docker compose up -d

The stack:

| Service | Port (host) | Role |
|---------|-------------|------|
| `signet`     | `127.0.0.1:8443` | The safety gate |
| `ollama`     | (internal only)  | OpenAI-compatible local LLM, auto-pulls `llama3.2:1b` on first start |
| `prometheus` | `127.0.0.1:9090` | Optional, scrapes `signet:/metrics` |
| `grafana`    | `127.0.0.1:3000` | Optional, dashboards |

Send a request through the gate:

    curl http://localhost:8443/v1/chat/completions \
        -H "Content-Type: application/json" \
        -H "X-Commit-Owner: human:alice@example.com" \
        -d '{"model":"llama3.2:1b","messages":[{"role":"user","content":"Hello"}]}'

A request with no owner header should be refused (proves the gate is
enforcing):

    curl -i http://localhost:8443/v1/chat/completions \
        -H "Content-Type: application/json" \
        -d '{"model":"llama3.2:1b","messages":[{"role":"user","content":"hi"}]}'
    # HTTP/1.1 403 Forbidden

View the audit log (the gate writes JSONL to a named volume):

    docker compose exec signet signet audit tail /var/log/signet/audit.jsonl -n 10

Verify the audit chain end-to-end:

    docker compose exec signet \
        signet audit verify /var/log/signet/audit.jsonl \
        --hmac-secret "$SIGNET_HMAC_SECRET"

## With Prometheus + Grafana

The observability stack is gated behind a compose profile so the
default `up` stays slim:

    docker compose --profile observability up -d

Then:

- Prometheus: <http://localhost:9090>  (target `signet:8443/metrics` should be UP)
- Grafana:    <http://localhost:3000>  (admin / admin -- change on first login)

Add Prometheus as a Grafana datasource pointed at `http://prometheus:9090`
and start with the metrics surfaced by `signet`'s `/metrics` endpoint
(refusal rate, p95 latency, audit-chain head age, etc.).

## Hardening checklist before production

This recipe is fine for single-node prod, but check `docs/deploying.md`
before exposing the gate outside loopback:

- Put TLS terminator + auth proxy in front (nginx, caddy, envoy).
- Mount audit volume on durable storage with a backup policy.
- Configure an external anchor (`Rfc3161Anchor` against FreeTSA is the
  lowest-friction option).
- For multi-worker uvicorn, switch to `FileLockingJsonlBackend` and
  `RedisRateLimitState`. See `docs/deploying.md` worker-count section.

## Tear down

    docker compose down            # keeps volumes (audit log preserved)
    docker compose down -v         # wipes audit log, ollama model cache,
                                   # prometheus data, grafana data
