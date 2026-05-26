# ai-observability

이 폴더는 KubeOwl의 AI 서버, 시각화 대시보드, 공개 문서, 배포용 Kubernetes 예시를 모아둔 상위 작업 영역이다.

## 하위 폴더 역할

- `ai-server/` - FastAPI 기반 AI 분류 서버와 웹 UI 정적 자산
- `dashboards/` - Grafana 대시보드 JSON/ConfigMap 소스
- `docs/` - 테스트 증빙, 스크린샷, 문서형 산출물
- `k8s/` - 현재는 제거됨. 예전에는 로컬 배포 예시가 있었지만 지금은 `cloud-deploy/`를 사용한다.

## 배포 기준

- 개발/검증 원본은 `ai-server/`, `dashboards/`, `docs/`에 둔다.
- 학교 클라우드 VM에 올리는 사본은 `cloud-deploy/`를 기준으로 본다.
