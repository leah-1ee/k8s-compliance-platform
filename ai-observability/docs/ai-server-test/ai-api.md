# AI API Server

## 목적

Falco 이벤트를 입력받아 위협 심각도와 판단 근거를 반환한다.

## 실행

```bash
cd ai-observability/ai-server
uvicorn app.main:app --reload --port 8000
```

## 분류 API

```http
POST /classify
Content-Type: application/json
```

### 요청

```json
{
  "rule": "Compliance - Shell Spawned in Container",
  "priority": "Warning",
  "output": "Shell spawned in container",
  "output_fields": {
    "proc.name": "bash",
    "user.name": "root",
    "user.uid": 0,
    "container.id": "abc123",
    "k8s.ns.name": "default"
  },
  "tags": ["shell", "runtime"],
  "time": "2026-04-30T10:00:00Z"
}
```

### 응답

```json
{
  "severity": "medium",
  "reason": "priority:Warning->medium | risk_pattern:medium | context:root_user",
  "confidence": 0.75
}
```

## 개발 기준

- 개인정보 및 토큰성 필드 마스킹
- LLM 요청은 분석/요약 직전 redaction pipeline을 반드시 지난다
- prompt injection 또는 jailbreak 류 정책 생성 요청은 서버에서 거부한다
- 고위험 deny 정책은 시스템 네임스페이스 blast radius 확인을 요구한다
- 이 문서는 `/docs` 공개 문서와 함께 현재 분류 API 동작을 설명하며, 런타임 이벤트 분석 문서와 용어가 어긋나지 않도록 유지한다.
- 응답 스키마 고정
- 재현 가능한 규칙 기반 기본 분류
- LLM 장애 시 대체 가능한 구조
- 판단 근거 포함
