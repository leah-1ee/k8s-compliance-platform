# TASK-15: Stabilize Grafana Proxy, Demo Tunnel, and Runtime Dashboard

## Current State

TASK-14에서 ai-server `/metrics` export와 중앙 Prometheus scrape는 동작한다.

확인된 metric:

```text
kubeowl_runtime_events_total{cluster_id="cluster-8b58a0c56096",cluster_name="school-cloud",severity="medium",source="sidekick"} 35
kubeowl_runtime_events_total{cluster_id="cluster-ff1f78d5c20b",cluster_name="user_cluster",severity="high",source="sidekick"} 2
kubeowl_runtime_events_total{cluster_id="cluster-ff1f78d5c20b",cluster_name="user_cluster",severity="medium",source="sidekick"} 1
```

central Prometheus query도 `kubeowl_runtime_events_total`을 반환했다. 따라서 현재 `No data`는 이벤트 부재나 Prometheus scrape 부재가 아니라 **Grafana proxy / datasource / browser asset loading path** 쪽 문제로 본다.

최신 관련 커밋:

- `a4d5604 fix(task-14): repair Grafana Prometheus proxy stability`
- `2c07cae fix(task-14): harden Grafana proxy asset handling`

최신 이미지 태그:

- Current VM image before TASK-15 fixes: `docker.io/leeon3345/compliance-ai-server:0.1.41`
- Next image including TASK-15 proxy path, Prometheus URL, and static 404 cleanup fixes: `docker.io/leeon3345/compliance-ai-server:0.1.43`

## Problems Observed

### 1. Grafana page still can show `about:blank`

브라우저에서 Grafana 진입 후 `about:blank` 또는 blank UI가 계속 발생할 수 있다.

Web inspector에서 보인 에러:

```text
URL: https://compliance-ai-console.shares.zrok.io/static/assets/screenshot-falco.png
Status: 404
Initializer: ui:118

URL: https://compliance-ai-console.shares.zrok.io/favicon.ico
Status: 404
```

`screenshot-falco.png`는 메인 UI hover preview asset이고 Grafana blank의 직접 원인은 아닐 수 있지만, public/static asset route 상태가 아직 불안정하다는 신호다.

### 2. Grafana datasource query previously returned 400

이전 로그에서는 Prometheus proxy 자체는 200 OK가 되었지만 Grafana `/api/ds/query`가 400을 냈다.

대표 로그:

```text
POST http://prometheus.monitoring.svc.cluster.local:9090/api/v1/query_range "HTTP/1.1 200 OK"
POST /grafana/prometheus/cluster-ff1f78d5c20b/api/v1/query_range HTTP/1.1" 200 OK
POST http://monitoring-grafana.monitoring.svc.cluster.local/api/ds/query?ds_type=prometheus&requestId=... "HTTP/1.1 400 Bad Request"
POST /api/ds/query?ds_type=prometheus&requestId=... HTTP/1.1" 400 Bad Request
```

`proxy.py`에서 Prometheus response의 `content-encoding`을 전달하지 않도록 수정했으므로, 다음 검증에서 `/api/ds/query` 400이 사라지는지 확인해야 한다.

### 3. zrok / local port-forward path is fragile

central VM demo path uses:

- ai-console local: `127.0.0.1:18000`
- Grafana local: `127.0.0.1:3001`
- response-server local: `127.0.0.1:5000`
- public: `https://compliance-ai-console.shares.zrok.io`

`scripts/start-demo-tunnels.sh` now wraps zrok and kubectl port-forward processes with `scripts/run-zrok-share-loop.sh`, but zrok still may briefly return 502 while upstream restarts.

Earlier browser/network symptoms:

```text
GET /public/build/... 502 Bad Gateway
GET /grafana-ui/public/plugins/... 502 Bad Gateway
GET /api/user/stars 502 Bad Gateway
GET /api/prometheus/grafana/api/v1/rules?... 502 Bad Gateway
```

Need distinguish between:

- temporary zrok upstream reconnect
- ai-server proxy returning 502 to browser because Grafana upstream is unavailable
- Grafana asset path rewrite failure causing root `/public/...` requests

## Files To Inspect First

### Grafana UI reverse proxy

```text
ai-observability/ai-server/app/grafana/ui_proxy.py
```

Focus:

- `/grafana-ui/{path:path}` route
- root `/public/{path:path}` route
- root `/api/*`, `/apis/*`, `/avatar/*` proxy routes
- `_proxy_grafana_path`
- `_request_headers`
- `_response_headers`
- `_response_content`
- `_rewrite_html`
- `_rewrite_asset_text`
- `_rewrite_location`

Risks:

- Grafana HTML/JS may still emit root `/public/...` or `/api/...` paths.
- Public asset requests are now allowed without console login, but should not send empty `X-WEBAUTH-*` headers.
- `content-encoding`, `content-length`, `transfer-encoding` must not be forwarded after body rewriting.

### Prometheus datasource proxy

```text
ai-observability/ai-server/app/grafana/proxy.py
```

Focus:

- `/grafana/prometheus/{cluster_id}/{path:path}`
- `_forward_request`
- `_rewrite_query_params`
- `_rewrite_form_items`
- `_response_headers`

Risks:

- Grafana datasource expects Prometheus JSON exactly.
- `content-encoding` should not be forwarded if `httpx` already decoded the body.
- `application/x-www-form-urlencoded` POST body must be re-encoded correctly after query injection.
- Rate limit should not block normal Grafana panel fan-out.

### Grafana provisioning

```text
ai-observability/ai-server/app/grafana/provisioning.py
```

Focus:

- `_ensure_datasource`
- datasource `url`
- `jsonData.httpMethod`
- `jsonData.httpHeaderName1`
- `secureJsonData.httpHeaderValue1`
- `_proxy_jwt`
- `_dashboard_payloads`

Risks:

- Datasource URL must be internal ai-server URL, not zrok/browser URL.
- JWT must be valid and long-lived enough.
- Existing datasource may keep stale secureJsonData if update payload is not accepted as expected by Grafana.

### Dashboards

```text
runtime-detection/manifests/grafana/dashboard-configmap.yaml
ai-observability/ai-server/app/grafana/dashboard_template.json
```

Focus:

- datasource UID replacement
- queries using `kubeowl_*` metrics
- whether panels use range query or instant query
- whether queries return data when cluster label is injected

### Tests

```text
ai-observability/ai-server/tests/test_grafana.py
ai-observability/ai-server/tests/test_proxy_auth.py
```

Tests should cover:

- root `/public/...` asset proxy without auth
- no empty auth proxy headers for anonymous public assets
- JS/CSS/JSON asset path rewrite
- Prometheus response headers do not include stale `content-encoding`
- form POST query_range rewrite

## Commands For Reproduction

### Check deployed image

```bash
kubectl get deploy ai-classifier -n compliance-system \
  -o jsonpath='{.spec.template.spec.containers[0].image}{"\n"}'
```

Expected:

```text
docker.io/leeon3345/compliance-ai-server:0.1.41
```

### Check ai-server health and metrics

```bash
curl -i http://127.0.0.1:18000/healthz
curl -s http://127.0.0.1:18000/metrics | grep kubeowl_runtime_events_total
```

### Check Grafana and ai-server logs

```bash
kubectl logs -n monitoring deploy/monitoring-grafana --since=5m \
  | grep -Ei 'datasource|query|error|bad request|prometheus'

kubectl logs -n compliance-system deploy/ai-classifier --since=5m \
  | grep -Ei 'api/ds/query|grafana/prometheus|public/build|frontend-metrics|login/ping| 400 | 429 | 500 | 502'
```

### Restart demo tunnel path

```bash
cd ~/vscode/k8s-compliance-platform
scripts/repair-demo-zrok.sh
```

### Re-provision user Grafana org/datasource/dashboards

Run in logged-in AI Console browser DevTools:

```js
fetch("/api/clusters/cluster-ff1f78d5c20b/grafana/provision", {
  method: "POST",
  credentials: "include"
}).then(r => r.json()).then(console.log)
```

## Validation Criteria

- AI Console loads without repeated 502s after tunnel stabilizes.
- `/static/assets/screenshot-falco.png` either resolves or the UI no longer references a missing asset.
- Grafana opens through `/grafana-ui/` without `about:blank`.
- Browser console has no chunk load failures for:
  - `/public/build/*Panel*.js`
  - `/public/build/*.js`
  - `/grafana-ui/public/plugins/*`
- Grafana `/api/ds/query` no longer returns 400.
- ai-server logs show:

```text
POST /grafana/prometheus/cluster-ff1f78d5c20b/api/v1/query_range HTTP/1.1" 200 OK
```

and no adjacent:

```text
POST /api/ds/query?... HTTP/1.1" 400 Bad Request
```

- Runtime Detection dashboard shows values for `cluster-ff1f78d5c20b`:
  - high = 2
  - medium = 1
  - total = 3
- Dashboard list shows all expected dashboards:
  - `Gatekeeper Compliance Overview`
  - `Runtime Detection`
  - `KubeOwl Observability`

## Notes

- Do not rely on Docker build from central VM. Docker image is built and pushed from local Mac, then VM only pulls/applies the tag.
- If a new ai-server code change is made, bump both manifests:

```text
ai-observability/k8s/ai-server.yaml
cloud-deploy/ai-server.yaml
```

- Current VM script assumes `18000`, not `18002`.
- If browser still shows `about:blank`, collect:
  - Network entry for first failed JS chunk
  - Response body for `/api/ds/query` if any 400 remains
  - ai-server logs around the same timestamp
  - Grafana logs around the same timestamp

## Validation Result

TASK-15 VM validation completed on 2026-05-25.

Confirmed user cluster:

```text
cluster_id=cluster-ff1f78d5c20b
cluster_name=user_cluster
grafana_org_id=2
grafana_datasource_uid=kubeowl-prom-f4efeb00a6e0387b
```

Falco smoke event from the user cluster was ingested by the central ai-server:

```text
POST /ingest/falco-events HTTP/1.1" 200 OK
```

Central ai-server `/metrics` exported the trusted SQLite-backed user cluster counts:

```text
kubeowl_runtime_events_total{cluster_id="cluster-ff1f78d5c20b",cluster_name="user_cluster",severity="high",source="sidekick"} 3
kubeowl_runtime_events_total{cluster_id="cluster-ff1f78d5c20b",cluster_name="user_cluster",severity="medium",source="sidekick"} 2
```

Central Prometheus returned the expected total:

```text
query=sum(kubeowl_runtime_events_total{cluster_id="cluster-ff1f78d5c20b"})
value=5
```

Grafana dashboard JSON for `orgId=2` was verified to use the user datasource UID:

```text
uid=kubeowl-prom-f4efeb00a6e0387b
name=kubeowl-prometheus-cluster-ff1f78d5c20b
url=http://ai-classifier.compliance-system.svc.cluster.local:8000/grafana/prometheus/cluster-ff1f78d5c20b
```

Root cause for the remaining `0` values was the ai-server Grafana Prometheus proxy pointing at the wrong in-cluster Prometheus service:

```text
old PROMETHEUS_URL=http://prometheus.monitoring.svc.cluster.local:9090
new PROMETHEUS_URL=http://monitoring-kube-prometheus-prometheus.monitoring.svc.cluster.local:9090
```

After updating `PROMETHEUS_URL` and rolling out `deploy/ai-classifier`, Grafana datasource query returned:

```json
[
  [1779701731581],
  [5]
]
```

Runtime Detection and KubeOwl Observability dashboards then showed:

```text
Reporting Clusters=1
Total Events=5
High Events=3
Medium Events=2
```

Follow-up committed locally:

- `PROMETHEUS_URL` is now persisted in both ai-server deploy manifests so future rollouts do not revert to the wrong Prometheus service.
- The ai-server Prometheus proxy default now matches the validated kube-prometheus service.
- The missing `/static/assets/screenshot-falco.png` reference was removed from the landing hover card to eliminate the non-functional 404 warning.
