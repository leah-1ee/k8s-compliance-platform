# TASK-16: Final Demo Hardening and Cleanup

## Current State

TASK-15 completed the Grafana runtime dashboard recovery path.

Confirmed live validation:

```text
user cluster_id=cluster-ff1f78d5c20b
user cluster_name=user_cluster
grafana orgId=2
grafana datasource uid=kubeowl-prom-f4efeb00a6e0387b
Runtime Detection: Reporting=1, Total=5, High=3, Medium=2
KubeOwl Observability: Reporting=1, Total=5, High=3, Medium=2
```

Root cause fixed:

```text
old PROMETHEUS_URL=http://prometheus.monitoring.svc.cluster.local:9090
new PROMETHEUS_URL=http://monitoring-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090
```

TASK-15 follow-up changes prepared locally:

- `PROMETHEUS_URL` persisted in both ai-server deploy manifests.
- ai-server Grafana Prometheus proxy default now points at the validated kube-prometheus service.
- missing `/static/assets/screenshot-falco.png` landing-page reference removed.
- next ai-server image tag in manifests: `docker.io/leeon3345/compliance-ai-server:0.1.43`

## Remaining Work

### 1. Build and roll out TASK-15 final image

Build/push from local Mac:

```bash
docker buildx build --platform linux/amd64 \
  -t docker.io/leeon3345/compliance-ai-server:0.1.43 \
  -f ai-observability/ai-server/Dockerfile \
  ai-observability/ai-server \
  --push
```

Apply on the admin cluster:

```bash
kubectl apply -f cloud-deploy/ai-server.yaml
kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s
```

Verify:

```bash
kubectl exec -n compliance-system deploy/ai-classifier -- printenv | grep PROMETHEUS_URL
kubectl get deploy ai-classifier -n compliance-system \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

Expected:

```text
PROMETHEUS_URL=http://monitoring-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090
docker.io/leeon3345/compliance-ai-server:0.1.43
```

### 2. Re-verify browser warnings

Confirm the landing page no longer requests:

```text
/static/assets/screenshot-falco.png
```

`favicon.ico` may still 404 unless a favicon is added. This is cosmetic and separate from Grafana functionality.

### 3. Stabilize demo tunnel behavior

Intermittent `502` still indicates zrok/upstream reconnect behavior, not missing runtime data.

Re-check:

```bash
scripts/repair-demo-zrok.sh
kubectl logs -n compliance-system deploy/ai-classifier --since=5m \
  | grep -Ei ' 400 | 429 | 500 | 502|grafana/prometheus|api/ds/query'
```

If 502s persist, distinguish:

- zrok public tunnel reconnect
- local port-forward restart
- ai-server upstream Grafana unavailable
- Grafana root `/public` asset rewrite failure

Latest VM log finding:

```text
POST /api/ds/query?... HTTP/1.1" 200 OK
GET /api/annotations?... HTTP/1.1" 200 OK
WebSocket /grafana-ui/api/live/ws 403
```

Interpretation:

- Runtime dashboard data queries are healthy inside the cluster.
- Annotation calls are healthy inside the cluster.
- The visible browser instability is not the runtime metrics pipeline.
- Grafana Live WebSocket requests are rejected with `403` through the KubeOwl `/grafana-ui/` proxy path.
- Browser-side `502` reports can still appear on the public zrok URL even when ai-server logs show upstream Grafana HTTP calls succeeding.

TASK-16 should handle Grafana Live explicitly:

- Either proxy `/grafana-ui/api/live/ws` as a real WebSocket with the same auth context as the HTTP Grafana proxy.
- Or disable/suppress Grafana Live for the demo path if it is not needed, so the browser no longer retries a guaranteed `403`.
- Keep `/api/ds/query` and `/api/annotations` HTTP proxy behavior unchanged; they are currently returning `200 OK`.

### 4. Polish Grafana panels

The runtime data path is correct, but several panels are visually noisy:

- `Last Seen by Cluster` renders timestamp data awkwardly.
- some chart legends and axes crowd on narrow viewports.
- `Runtime Compliance Score` is mathematically simple and may need a clearer product definition.

Prefer panel JSON changes in the repo source dashboards, then re-provision/import.

### 5. Final end-to-end demo

Run one final scripted demo story:

1. Register or confirm user cluster.
2. Trigger a Falco smoke event from the user cluster.
3. Confirm `/ingest/falco-events` returns `200`.
4. Confirm ai-server `/metrics` shows the event counts.
5. Confirm central Prometheus returns the same total.
6. Confirm Runtime Detection and KubeOwl Observability dashboards show user-scoped values.
7. Capture screenshots for final documentation.

## Do Not Regress

- Keep user Grafana datasource URLs internal:

```text
http://ai-classifier.compliance-system.svc.cluster.local:8000/grafana/prometheus/{cluster_id}
```

- Keep Grafana access through KubeOwl `/grafana-ui/` auth proxy.
- Do not point ai-server Grafana proxy back to `http://prometheus.monitoring.svc.cluster.local:9090`.
- Do not accept user-cluster remote_write for this project stage; central ai-server `/metrics` remains the trusted source.
