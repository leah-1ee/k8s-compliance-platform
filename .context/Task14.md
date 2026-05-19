# TASK-14: Admin Grafana Access

## Goal

관리자가 `/admin` 콘솔에서 관리자용 Grafana 대시보드로 바로 이동할 수 있게 한다.

TASK-13에서 일반 사용자는 KubeOwl `Cluster Setup`의 클러스터별 Grafana 버튼을 통해 `/grafana-ui/` auth proxy 경로로 들어가고, 사용자별 Grafana org/Viewer 권한/클러스터 프록시 datasource를 사용한다. 관리자 UX는 이 사용자 흐름과 분리한다.

## Requirements

- Admin page에서만 관리자 Grafana 진입점을 제공한다.
- 일반 사용자 UI 상단의 전역 Grafana 버튼은 제거된 상태를 유지한다.
- 관리자 Grafana 접근은 사용자 클러스터별 Viewer org가 아니라 admin/master dashboard 관리 목적이어야 한다.
- Grafana OSS만 사용한다. Enterprise datasource permission에 의존하지 않는다.
- Grafana direct NodePort 노출은 사용하지 않는다.
  - TASK-13 이후 Grafana Service는 ClusterIP다.
  - 브라우저 접근은 KubeOwl 인증 프록시 경로(`/grafana-ui/`)를 통해 처리한다.
- admin token/session 검증 후 admin Grafana 경로로 안내한다.

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

## Notes

- Current master dashboard UID env:
  - `GRAFANA_MASTER_DASHBOARD_UIDS="compliance-overview,compliance-runtime-detection"`
  - `GRAFANA_MASTER_ORG_ID="1"`
- Imported master dashboards currently verified in new Task13 Grafana:
  - `compliance-overview`
  - `compliance-runtime-detection`
