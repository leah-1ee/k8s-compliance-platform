# ai-server

이 폴더는 KubeOwl의 FastAPI 기반 AI 서버 구현체다.

## 포함 내용

- `app/` - API, 인증, Grafana 프록시, 정책 생성, 정적 UI
- `tests/` - 서버 동작 검증용 pytest 테스트
- `Dockerfile` - AI 서버 컨테이너 이미지 정의
- `requirements.txt` - Python 의존성

## 역할

- `generate-policy`와 `analyze-violation` 같은 AI/정책 API를 제공한다.
- `/ui`, `/docs`, `/admin`에 필요한 정적 파일과 라우트를 함께 포함한다.
- Grafana 연동과 런타임 이벤트 분석 로직도 이 서버에서 관리한다.
