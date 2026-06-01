# Grafana Dashboard

## Purpose

AI Classifier와 Gatekeeper 정책 상태를 Prometheus 메트릭 기반으로 시각화한다.

## Panels

| Panel | Query | Description |
|---|---|---|
| AI Classification Requests | `sum(increase(compliance_ai_requests_total{service="response-server"}[$__range]))` | 선택한 시간 범위 동안 Response Server에서 AI Classifier로 전달된 분류 요청 수를 표시한다. |
| AI Classification Errors | `sum(increase(compliance_ai_errors_total{service="response-server"}[$__range]))` | 선택한 시간 범위 동안 AI 분류 처리 중 발생한 오류 수를 표시한다. |
| Seconds Since Last Gatekeeper Audit | `(time() - gatekeeper_audit_last_run_time) or vector(0)` | Gatekeeper의 마지막 감사 실행 이후 경과 시간을 초 단위로 표시한다. |
| Gatekeeper Violations by Enforcement | `sum by (enforcement_action) (gatekeeper_violations) or vector(0)` | Gatekeeper 정책 위반을 enforcement action 기준으로 집계한다. |
| Gatekeeper Violations Total | `sum(gatekeeper_violations) or vector(0)` | Gatekeeper v3.22 audit 메트릭에서 제공되는 전체 위반 수를 집계한다. |
| Gatekeeper Audit Duration | `rate(gatekeeper_audit_duration_seconds_sum[5m]) / rate(gatekeeper_audit_duration_seconds_count[5m])` | 최근 5분 동안 Gatekeeper 감사 작업의 평균 소요 시간을 초 단위로 표시한다. |

## Evidence

Dashboard screenshots are stored in `images/`.
