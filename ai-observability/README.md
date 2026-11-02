# ai-observability

이 폴더는 KubeOwl의 중앙 AI 콘솔, 시각화 대시보드, 운영 문서와 배포 파일을 모아둔 작업 영역이다.

## 하위 폴더 역할

- `ai-server/` - FastAPI 기반 AI 분류 서버와 웹 UI 정적 자산
- `dashboards/` - Grafana 대시보드 JSON/ConfigMap 소스
- `deploy/` - AI 서버, Ingress, 정리 작업, Prometheus/Grafana 배포 설정
- `docs/` - 현재 구현을 재현하는 API 및 운영 문서

## 배포 기준

- AI 서버 배포: `kubectl apply -f ai-observability/deploy/ai-server.yaml`
- Ingress와 정리 CronJob: `ai-observability/deploy/ai-server-ingress.yaml`,
  `ai-observability/deploy/ai-server-cleanup-cronjob.yaml`
- 모니터링 Helm values와 ServiceMonitor: `ai-observability/deploy/monitoring/`

배포 파일은 이 디렉터리를 원본으로 사용하며 별도 VM용 사본을 만들지 않는다.
