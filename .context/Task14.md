# TASK-14: Admin Grafana Access and Metrics Export

## Goal

관리자가 `/admin` 콘솔에서 관리자용 Grafana 대시보드로 바로 이동할 수 있게 한다.

TASK-13에서 일반 사용자는 KubeOwl `Cluster Setup`의 클러스터별 Grafana 버튼을 통해 `/grafana-ui/` auth proxy 경로로 들어가고, 사용자별 Grafana org/Viewer 권한/클러스터 프록시 datasource를 사용한다. 관리자 UX는 이 사용자 흐름과 분리한다.

또한 TASK-13 smoke에서 Falco Sidekick → KubeOwl ingest → Runtime Detection 저장은 성공했지만 Grafana 대시보드는 `No data`가 나왔다. 원인은 runtime events가 SQLite에 저장되고, Grafana dashboard는 Prometheus datasource를 보기 때문이다. TASK-14는 보안적으로 안전한 Prometheus metric export 방식을 함께 정리한다.

## Security Decision: Metrics Pipeline

추천 방식은 **ai-server가 사용자 이벤트를 집계한 Prometheus metrics를 `/metrics`로 노출하고, 중앙 Prometheus가 내부 DNS로 ai-server만 scrape하는 방식**이다.

선택지 비교:

- **Recommended: ai-server `/metrics` export**
  - 사용자 클러스터는 기존처럼 Falco Sidekick webhook으로 이벤트만 전송한다.
  - ai-server는 이미 cluster token 검증, user/cluster ownership, SQLite 저장을 담당한다.
  - Prometheus는 중앙 클러스터 내부에서만 ai-server `/metrics`를 scrape한다.
  - 외부 사용자 클러스터 Prometheus를 중앙 Prometheus에 직접 연결하지 않는다.
  - 노출하는 값은 집계 카운터/게이지 중심으로 제한한다.
  - 장점: 공격 표면이 작고, tenant 경계가 ai-server에서 일관되게 통제되며, Prometheus/Grafana는 계속 ClusterIP 내부에 둘 수 있다.

- **Not recommended for current school VM: user-cluster Prometheus remote_write/federation**
  - 각 사용자 클러스터에 Prometheus/agent/remote_write credential이 필요하다.
  - 중앙 수신 endpoint, 인증, tenant label 강제, replay/DoS 방어가 추가로 필요하다.
  - 잘못 설정하면 다른 tenant metric이 섞이거나 중앙 Prometheus가 외부 입력면이 된다.
  - 운영 복잡도가 현재 목표 규모(~10 users, school VM)에 비해 크다.

따라서 TASK-14는 **SQLite-backed ai-server metrics export + central Prometheus scrape**를 우선한다.

## Requirements

- Admin page에서만 관리자 Grafana 진입점을 제공한다.
- 일반 사용자 UI 상단의 전역 Grafana 버튼은 제거된 상태를 유지한다.
- 관리자 Grafana 접근은 사용자 클러스터별 Viewer org가 아니라 admin/master dashboard 관리 목적이어야 한다.
- Grafana OSS만 사용한다. Enterprise datasource permission에 의존하지 않는다.
- Grafana direct NodePort 노출은 사용하지 않는다.
  - TASK-13 이후 Grafana Service는 ClusterIP다.
  - 브라우저 접근은 KubeOwl 인증 프록시 경로(`/grafana-ui/`)를 통해 처리한다.
- admin token/session 검증 후 admin Grafana 경로로 안내한다.
- Grafana dashboard가 실제 데이터를 표시할 수 있도록 ai-server `/metrics` endpoint를 추가한다.
- `/metrics`는 중앙 Prometheus에서만 scrape되도록 Kubernetes NetworkPolicy 또는 ServiceMonitor/Prometheus scrape config를 내부 DNS 기준으로 구성한다.
- Prometheus는 계속 ClusterIP만 사용하고 외부에 노출하지 않는다.
- 사용자 클러스터가 별도 VM/minikube일 경우 Sidekick ingest는 `FALCO_INGEST_BASE_URL`처럼 접근 가능한 중앙 ingest URL을 사용하지만, Prometheus metric 수집은 중앙 ai-server가 저장된 이벤트를 집계해 노출한다.

## Suggested Implementation

1. `/admin` UI에 `Admin Grafana` 버튼 추가.
2. 버튼은 admin 인증 확인 후 admin/master org dashboard 목록 또는 대표 dashboard로 이동한다.
3. backend에 admin 전용 endpoint 추가 후보:
   - `POST /admin/api/grafana/provision-master`
   - `GET /admin/api/grafana/url`
4. admin 접근 시 Grafana auth.proxy header에 admin-safe identity를 주입할지, 기존 Grafana admin credential 기반 API-only 관리로 둘지 결정한다.
5. 관리자 대시보드 템플릿 관리:
   - master dashboards는 Grafana org `1`에 둔다.
   - 사용자 org provisioning은 `GRAFANA_MASTER_DASHBOARD_UIDS`를 기준으로 master dashboard JSON을 복사한다.
6. ai-server metrics endpoint 추가:
   - 후보 endpoint: `GET /metrics`
   - Prometheus text exposition format 사용.
   - 초기 metric 후보:
     - `kubeowl_runtime_events_total{cluster_id,cluster_name,severity,source}`
     - `kubeowl_runtime_events_recent_24h{cluster_id,cluster_name,severity}`
     - `kubeowl_cluster_last_seen_timestamp_seconds{cluster_id,cluster_name}`
     - `kubeowl_clusters_active_total{user_id}` 또는 user_id 없는 aggregate variant 검토
   - high-cardinality label 방지:
     - raw `rule`, `pod`, `container`, `command`, `user email`은 기본 label로 넣지 않는다.
     - 필요 시 top-N 또는 dashboard API에서 처리한다.
   - cluster_id는 ai-server가 저장한 trusted cluster row 기준으로만 emit한다.
7. Prometheus scrape 구성:
   - central Prometheus가 `http://ai-server.compliance-system.svc.cluster.local:8000/metrics` scrape.
   - Prometheus NetworkPolicy/egress는 필요한 경우 ai-server로의 egress만 허용.
   - ai-server `/metrics`는 별도 외부 노출 없이 ClusterIP 경로에서만 사용.

## Validation

- 일반 사용자:
  - KubeOwl 상단에 전역 Grafana 버튼이 없어야 한다.
  - `Cluster Setup`의 클러스터별 Grafana 버튼으로 자기 org Viewer dashboard에 들어가야 한다.
- 관리자:
  - `/admin`에서만 admin Grafana 진입점이 보여야 한다.
  - admin Grafana에서는 master dashboards를 확인/관리할 수 있어야 한다.
- Security:
  - Grafana Service는 ClusterIP 유지.
  - Grafana NetworkPolicy는 ai-server/ai-classifier ingress만 허용.
  - Prometheus Service는 ClusterIP 유지.
  - Prometheus가 사용자 클러스터 remote_write를 직접 받지 않아야 한다.
  - `/metrics`에 tenant-sensitive raw fields가 label로 노출되지 않아야 한다.
- Metrics:
  - Falco smoke event 발생 후 Runtime Detection에 이벤트가 보인다.
  - 중앙 Prometheus query에서 `kubeowl_runtime_events_total` 또는 TASK-14에서 정한 metric이 보인다.
  - 사용자 Grafana dashboard가 Prometheus proxy 경유로 자기 cluster_id 데이터만 표시한다.

## Notes

- Current master dashboard UID env:
  - `GRAFANA_MASTER_DASHBOARD_UIDS="compliance-overview,compliance-runtime-detection"`
  - `GRAFANA_MASTER_ORG_ID="1"`
- Imported master dashboards currently verified in new Task13 Grafana:
  - `compliance-overview`
  - `compliance-runtime-detection`
- TASK-13 smoke note:
  - 별도 minikube/user cluster는 `ai-server.compliance-system.svc.cluster.local`을 해석할 수 없다.
  - 별도 사용자 클러스터 연결에는 `FALCO_INGEST_BASE_URL`로 zrok/Ingress/VPN/tunnel 등 접근 가능한 중앙 ingest URL이 필요하다.
  - Runtime Detection이 보여도 Grafana가 `No data`일 수 있다. 이는 Prometheus metric export가 아직 없기 때문이며 TASK-14에서 `/metrics`로 해결한다.
