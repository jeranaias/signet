# Kubernetes (Helm) deployment

Minimal viable Helm chart skeleton for signet. Not a fully-loaded
production chart -- enough to get `helm install` to render and apply,
then tune for your environment.

## Install

```bash
# Provision the HMAC secret out-of-band (preferred).
kubectl create secret generic signet-hmac \
    --from-literal=secret=$(openssl rand -hex 32) \
    -n signet

helm install signet ./ \
    --namespace signet --create-namespace \
    --set hmacSecret.existingSecret=signet-hmac \
    --set upstream.url=http://my-upstream.example.svc.cluster.local:8000/v1 \
    --set-file pipeline=./my-pipeline.py
```

For a quick demo with an inline secret (NEVER in production):

```bash
helm install signet ./ \
    --set hmacSecret.value=$(openssl rand -hex 32) \
    --set upstream.url=http://ollama.ollama.svc.cluster.local:11434/v1
```

## Render without applying

```bash
helm template signet ./ \
    --set hmacSecret.value=deadbeef \
    | kubectl --dry-run=client -f - apply
```

## What's in the chart

| File | Purpose |
|------|---------|
| `Chart.yaml` | Chart metadata; pinned to `signet-sign==0.1.8`. |
| `values.yaml` | All knobs (replicas, image, HMAC source, upstream URL, audit PVC, probes, security context). |
| `templates/deployment.yaml` | The signet container with `/healthz` liveness + `/readyz` readiness, non-root, read-only-rootfs, dropped capabilities. |
| `templates/service.yaml` | ClusterIP on 8443. |
| `templates/configmap.yaml` | `pipeline.py` mounted at `/etc/signet/pipeline.py`. |
| `templates/secret.yaml` | HMAC secret, only rendered when `existingSecret` is empty. |
| `templates/pvc.yaml` | Audit-log PVC. |

## Probes

- **livenessProbe** -> `/healthz`. Always 200 if the process is alive.
- **readinessProbe** -> `/readyz`. 503s when the upstream is
  unreachable, so traffic sheds without killing the pod.

Don't point both probes at the same endpoint; see
`docs/deploying.md` "Probe wiring".

## What this chart deliberately does NOT include

- **Ingress / TLS**: signet is not a TLS terminator. Front it with
  nginx-ingress, an Envoy gateway, or your service mesh's edge.
  See `docs/deploying.md` "TLS and the trust boundary".
- **Authentication proxy**: caller-asserted owner headers are
  attribution, not authentication. Put OIDC / mTLS in front.
  See `docs/integrations/auth.md`.
- **Redis-backed RateLimit**: when `replicaCount > 1`, swap the
  default in-process bucket for `RedisRateLimitState` in your
  pipeline.py. See `docs/deploying.md` rate-limiting section.
- **External anchor**: configure `Rfc3161Anchor` in your pipeline.py
  for tamper-evidence beyond the HMAC chain.
- **HorizontalPodAutoscaler**: add one with metrics that match your
  workload (CPU is fine for the proxy-bound shape).

These are intentional omissions: the chart is a starting point. Layer
your platform's standard ingress / auth / observability shape on top
rather than swimming against it.

## Validating without a cluster

```bash
helm lint ./
helm template signet ./ --set hmacSecret.value=deadbeef >/dev/null
```

The second command exits non-zero if any manifest fails to render.
