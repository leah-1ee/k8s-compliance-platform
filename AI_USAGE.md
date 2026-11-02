# AI 활용 내역

KubeOwl 개발에서는 생성형 AI를 설계와 구현을 보조하는 도구로 사용했습니다.
AI가 만든 결과를 그대로 제출하지 않고, 사람이 범위와 보안 기준을 결정한 뒤 코드 리뷰와
자동화 테스트를 통해 검증했습니다.

## 활용 분야

| 분야 | AI 활용 내용 | 사람의 검토 및 결정 |
|---|---|---|
| 요구사항 정리 | 기능을 작은 작업 단위로 분해하고 영향 파일을 식별 | 최종 구현 범위와 우선순위 결정 |
| 코드 구현 | FastAPI API, UI 동작, Kubernetes 매니페스트 초안 작성 및 수정 | 인증 방식, 권한 범위, 배포 구조 검토 |
| 테스트 | API 테스트 케이스 추가, 실패 원인 분석, 회귀 테스트 실행 | 기대 동작 확인 및 실패 수정 승인 |
| 보안 검토 | 토큰 노출, 과도한 RBAC, prompt injection, 개인정보 전달 위험 점검 | 최소 권한, 비밀정보 환경변수 주입, LLM 입력 마스킹 적용 |
| 문서화 | README와 배포 절차를 현재 코드 구조에 맞게 정리 | 오래된 내용과 재현 불가능한 자료 제거 |

## 주요 설계 결정

- 자유 프롬프트로 Kubernetes 정책을 자동 생성·적용하지 않고 검증된 정책 템플릿을 사용했습니다.
- LLM은 위반 원인 설명과 조치 가이드의 보조 수단이며, API 장애 시 규칙 기반 분석으로 동작합니다.
- 사용자 요청은 세션 쿠키, 클러스터 이벤트 수집은 ingest token, 관리자 기능은 관리자 토큰으로 분리했습니다.
- 중앙 서버가 사용자 클러스터의 kubeconfig를 보관하지 않도록 이벤트 push 방식을 선택했습니다.
- Kubernetes Secret, OAuth 비밀값, ingest token은 코드와 문서에 실제 값을 기록하지 않습니다.

## 검증 방식

AI가 수정한 코드도 일반 코드와 동일하게 다음 검증을 통과해야 반영했습니다.

```bash
.venv/bin/python -m pytest ai-observability/ai-server/tests/
python3 runtime-detection/response-server/tests/test_all.py
python3 runtime-detection/response-server/tests/test_integration.py
make -C k8s-policy-engine test
```

최종 제출 정리 시 확인한 결과:

- AI 서버 테스트: 133개 통과
- Runtime Detection 단위 테스트: 20개 통과
- Runtime Detection 통합 테스트: 12개 통과
- Gatekeeper Rego 테스트: 16개 통과
- 제출 대상 Kubernetes YAML: 25개 파싱 확인

## AI 사용 기록 관리

개발 중에는 작업별 요구사항과 결정 사항을 로컬 `.context/` 문서로 관리했습니다.
해당 원본에는 오래된 경로, 로컬 명령, 운영 메모가 섞여 있어 제출 저장소에는 포함하지 않고,
현재 코드와 일치하는 활용 방식과 검증 결과만 이 문서에 정리했습니다.
