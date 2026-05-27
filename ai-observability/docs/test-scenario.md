# KubeOwl 테스트 시나리오

이 문서는 KubeOwl의 기능 검증, 발표 리허설, 화면 캡처와 영상 녹화를 같은 순서로 진행하기 위한 테스트 시나리오다.

## 테스트 목적

- 공개 초기 화면, 사용자 콘솔, 관리자 콘솔, 공개 문서가 끊기지 않는지 확인한다.
- 정책 생성, 클러스터 적용 가이드, 런타임 이벤트 분석, AI Report, Slack 알림, Grafana 연결을 end-to-end로 검증한다.
- 발표 자료에 사용할 이미지와 영상 컷을 같은 흐름에서 확보한다.

## 사전 조건

- AI 서버가 Kubernetes에서 정상 실행 중이어야 한다.
- 사용자 계정과 관리자 토큰이 준비되어 있어야 한다.
- 사용자 클러스터가 등록되어 있고 Falco Sidekick ingest URL/token 설정이 완료되어 있어야 한다.
- Slack 알림 검증 시 클러스터별 Slack webhook과 알림 토글이 활성화되어 있어야 한다.
- Grafana 확인 시 사용자 Grafana org/datasource provisioning이 완료되어 있어야 한다.

## 1. 초기 화면

1. 브라우저에서 사이트 루트(`/`)를 연다.
2. KubeOwl 로고, 주요 설명, 로그인 버튼, 문서 진입 버튼이 첫 화면에서 자연스럽게 보이는지 확인한다.
3. 초기 화면 맨 아래 이미지가 화면 분위기와 어긋나지 않는지 확인한다.

기대 결과:

- 비로그인 상태에서도 초기 화면이 깨지지 않는다.
- 로그인과 문서 진입 경로가 명확하다.
- 이미지가 잘리지 않고 하단 영역에 안정적으로 표시된다.

초기 화면 하단 이미지:

![초기 화면 하단 이미지](../ai-server/app/static/assets/landing-background.png)

## 2. 이미지/영상 파트

이미지 캡처 대상:

- 초기 화면 전체와 하단 이미지 영역
- 사용자 로그인 후 클러스터 등록 화면
- Policy Generator에서 YAML이 생성된 화면
- Violation Detail에서 원인/수정 YAML 생성 버튼이 보이는 화면
- AI Report에서 숫자 카드, Blast Radius, Timeline, Next Action이 보이는 화면
- Grafana 대시보드 진입 후 메트릭이 표시된 화면

영상 촬영 순서:

1. 초기 화면에서 로그인한다.
2. 클러스터를 등록하고 등록된 클러스터 카드와 Grafana 버튼을 보여준다.
3. 정책을 생성하고 enforcement action을 Deny, Warn, Dryrun 순서로 확인한다.
4. 적용 가이드를 열어 사용자가 직접 `kubectl`로 적용하는 흐름을 설명한다.
5. 런타임 이벤트를 발생시킨 뒤 Violation Detail과 AI Report를 확인한다.
6. Slack 알림과 Grafana 대시보드로 같은 이벤트가 이어지는 것을 보여준다.

보조 캡처:

![사용자 클러스터 화면](../../screenshots/00-user_cluster_node.png)

## 3. Policy Generator

1. Policy Generator 탭으로 이동한다.
2. 사전 정의 정책을 하나 선택한다.
3. enforcement action을 선택하고 정책을 생성한다.
4. 생성된 YAML을 복사하거나 적용 가이드로 이동한다.

기대 결과:

- Deny, Warn, Dryrun 버튼이 줄바꿈 없이 표시된다.
- 생성된 YAML이 정책 종류와 enforcement action을 반영한다.
- 사용자가 다음 행동을 바로 선택할 수 있다.

## 4. 클러스터 적용 가이드

1. 적용 대상 클러스터를 선택한다.
2. 적용 가이드 생성 버튼을 누른다.
3. `kubectl config current-context`, 권한 확인, dry-run, apply 순서가 안내되는지 확인한다.

기대 결과:

- AI 서버가 사용자 클러스터에 직접 apply하지 않는다는 점이 명확하다.
- 적용 상태가 없는 경우 불필요한 `대기` 배지가 노출되지 않는다.
- 명령어가 복사 가능한 형태로 표시된다.

## 5. Cluster Setup

1. 클러스터를 등록한다.
2. 새로고침 버튼으로 목록을 다시 불러온다.
3. 휴지통 토글을 켜서 삭제된 클러스터 목록으로 이동한다.
4. 휴지통 토글을 다시 꺼서 활성 클러스터 목록으로 돌아온다.

기대 결과:

- 기본 상태의 휴지통 아이콘은 파란색이다.
- 휴지통 목록에서는 휴지통 아이콘이 빨간색이다.
- 활성 목록으로 돌아오면 휴지통 아이콘이 다시 파란색으로 돌아온다.

## 6. Runtime Violation Detail

1. Falco 이벤트를 발생시킨다.
2. Violation Detail에서 이벤트를 선택한다.
3. rule, severity, namespace, pod, container, command, resource manifest를 확인한다.
4. `LLM으로 원인/수정 YAML 생성` 문구와 분석 버튼 위치를 확인한다.

기대 결과:

- 운영자가 어디를 확인해야 하는지 바로 알 수 있다.
- 버튼과 설명 문구가 같은 작업 영역 안에서 가깝게 보인다.
- 분석 결과는 원인, 영향, 수정 방향을 함께 제공한다.

## 7. AI Report

1. AI Report 탭으로 이동한다.
2. 리포트를 생성한다.
3. 숫자 카드, Top Rules, Blast Radius, Timeline, Recommendations, Next Actions를 확인한다.

기대 결과:

- 총 위반 수, 심각도, 영향 클러스터/네임스페이스/Pod 수가 상단에서 바로 보인다.
- 영향받은 클러스터, 네임스페이스, Pod가 목록으로 표시된다.
- 위반이 어느 시간대에 몰렸는지 Timeline으로 확인할 수 있다.
- `Violation Detail에서 확인하기` 같은 다음 행동 버튼이 제공된다.

## 8. Slack 알림

1. 클러스터별 알림 설정에서 Slack 토글을 켠다.
2. High 또는 Critical 런타임 이벤트를 발생시킨다.
3. Slack 채널에 알림이 도착하는지 확인한다.
4. 같은 rule/namespace/pod/container 조합으로 이벤트를 반복 발생시켜 중복 제어를 확인한다.

기대 결과:

- Low/Medium 이벤트는 Slack 알림 후보가 아니다.
- High/Critical 이벤트는 클러스터별 설정과 webhook 조건을 통과해야 발송된다.
- 같은 원인의 반복 이벤트는 `slack_notification_state` 기준으로 묶이고, cooldown 동안 무제한 알림이 발생하지 않는다.

## 9. Grafana

1. 사용자 콘솔에서 Grafana 버튼을 누른다.
2. 사용자별 Grafana org와 dashboard가 열리는지 확인한다.
3. Gatekeeper, Falco, AI Classification 관련 패널을 확인한다.

기대 결과:

- Grafana가 인증 프록시 뒤에서 열린다.
- 다른 사용자의 클러스터 메트릭이 섞이지 않는다.
- 이벤트 발생 후 대시보드 수치가 갱신된다.

## 10. 관리자 콘솔

1. `/admin`으로 이동한다.
2. 관리자 토큰으로 진입한다.
3. 사용자, 클러스터, 감사 로그, Grafana provisioning 상태를 확인한다.

기대 결과:

- 사용자 화면과 관리자 화면의 권한 경계가 유지된다.
- 클러스터 복구/비활성화 같은 운영 작업이 감사 로그에 남는다.
- 관리자 화면에서 전체 운영 상태를 확인할 수 있다.

## 종료 체크리스트

- `/`, `/docs`, `/ui`, `/admin` 경로가 모두 정상 동작한다.
- 사용자 로그인, 정책 생성, 이벤트 분석, AI Report 생성이 순서대로 성공한다.
- Slack 알림은 High/Critical 조건과 중복 제어 조건을 만족한다.
- Grafana 대시보드에 사용자 범위 메트릭이 표시된다.
- 발표용 이미지와 영상 컷이 최신 UI 기준으로 저장되어 있다.
