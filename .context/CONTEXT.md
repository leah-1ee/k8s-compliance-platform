# Project Context

## One-line Summary
Policy-as-Code based Kubernetes compliance automation platform.
Natural language → Rego policy via LLM, Falco event AI classification, real-time dashboard.

## Current Image Version
Current deployed image target: `docker.io/leeon3345/compliance-ai-server:0.1.8`
Next build/deploy tag: `docker.io/leeon3345/compliance-ai-server:0.1.9`
If `0.1.9` was already pushed for TASK-02, use `docker.io/leeon3345/compliance-ai-server:0.1.10` for TASK-03 publish.

## Tech Stack
- Backend: Python (FastAPI), SQLite (WAL mode, PVC persistent)
- Monitoring: Prometheus, Grafana
- Auth: Google OAuth (implemented, not live) + dev-login fallback
- Infra: Kubernetes, OPA Gatekeeper, Falco Sidekick

## Completed

- Gatekeeper policy UI: public (no login required)
- Google OAuth: code done, not live (Google Cloud 카드 문제로 보류)
- Dev login (`/auth/dev-login`): active via `DEV_AUTH_ENABLED=true`
- SQLite: WAL mode, PVC persistent
- `/admin`: cluster register, token issue/rotate/disable
- `/admin`: full user list, per-user cluster list, active/disabled status, last seen, event count
- Falco Sidekick: POST `/ingest/falco-events`, verified by ingest token
- `cluster_id`, `cluster_kind` stored; demo/customer/source/legacy filter exists
- TASK-01 done: `/ingest/falco-events` tags clusters in `DEMO_CLUSTER_NAMES` as `kind=demo` on ingest
- TASK-01 done: Runtime UI has cluster / cluster kind / source filters; legacy response-server events are opt-in
- `clusters.user_id` added (storage.py:30); per-user UNIQUE on cluster name
- `/api/clusters`: register / list / token-rotate API for logged-in users (main.py:427)
- `/runtime-events`, event detail, AI report: scoped to logged-in user's clusters (main.py:378)
- `Cluster Setup` tab in `/ui`: register cluster, Falco Sidekick install command, last seen, token rotate (index.html:54, app.js:396)
- `Violation Detail`, `AI Report` tabs: show guide message if not logged in
- `/runtime-events`, `/runtime-events/{id}`, `/resource-manifest`, `/analyze-runtime-event/{id}`, `/compliance-report`: return `401` if no session
- Tests: user cluster register, same cluster name allowed per different user, runtime event isolation
- TASK-02 done: Violation Detail API now returns severity explanation and recommended fix fields
- TASK-02 done: deterministic fallback analysis works when LLM is disabled or no API key is configured
- TASK-02 done: Violation Detail UI renders rule / cluster / namespace / pod / container context, cause, severity explanation, recommended fix, YAML snippet, and copy button
- TASK-02 done: LLM incident analysis normalization accepts the new fields while preserving older responses
- TASK-03 done locally: per-user Slack webhook URL persistence
- TASK-03 done locally: Slack settings API, Slack test button API, and frontend behavior
- TASK-03 done locally: High/Critical runtime events notify Slack only when the owning cluster has Slack enabled
- TASK-03 done locally: per-cluster Slack on/off toggle
- TASK-03 done locally: Slack settings area shows login guide when not authenticated
- TASK-03 note: `app/static/index.html` was intentionally not changed; Slack UI is injected by `app/static/app.js`
- Tests: `48 passed, 32 warnings` in `ai-observability/ai-server/tests`

## Deployment Notes

- Deployed image target: `docker.io/leeon3345/compliance-ai-server:0.1.8`
- Active deployment in cluster: `deploy/ai-classifier -n compliance-system`
- Deployment env:
  - `CLUSTER_NAME=school-cloud`
  - `DEMO_CLUSTER_NAMES=school-cloud`
  - `DEV_AUTH_ENABLED=true`
  - `DEV_AUTH_EMAIL=demo@school.test`
- Update command:
  - `kubectl set image deploy/ai-classifier -n compliance-system ai-classifier=docker.io/leeon3345/compliance-ai-server:<tag>`
  - `kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s`
- Runtime event verification requires Falco + Falco Sidekick installed in the user's cluster. If `kubectl get pods -A | grep -Ei 'falco|sidekick'` shows no running Falco/Sidekick pods, the UI will correctly show no recent runtime events.
- Cluster cleanup UI currently supports disable only. There is no delete button yet.

## Auth State

- Dev mode: `DEV_AUTH_ENABLED=true`, `DEV_AUTH_EMAIL=demo@school.test`
- UI shows dev-login button only — this is EXPECTED (no Google Secret configured)
- Production: set `DEV_AUTH_ENABLED=false`, switch to Google OAuth or school SSO

## UI Access Control

| Feature | Auth Required |
|---|---|
| Policy creation (Gatekeeper) | No (public) |
| Runtime detection | Yes |
| Violation Detail | Yes |
| AI Report | Yes |
| Cluster Setup | Yes |
| Slack settings | Yes |
| Admin (`/admin`) | Admin only |

## Remaining Tasks (priority order)

1. **Google OAuth live** — after Google Cloud card issue resolved, configure real OAuth credentials and disable dev-login
2. **Manifest fetch refactor** — central AI server querying K8s API directly doesn't fit user-cluster model
   - 1st: provide `kubectl` command for user to run
   - 2nd: collector/agent sends manifest snapshot with event
3. **Admin cleanup controls** — optional delete/archive for disabled test clusters; current UI only disables clusters
4. **Ops docs** — zrok stabilization script, image tag/deploy procedure, SQLite backup/reset, demo data cleanup

## Do Not Change (fixed decisions)

- SQLite `replicas: 1`, `strategy: Recreate` — never change
- Falco ingest auth: `Bearer <ingest_token>` only, not session cookie (machine-to-machine)
- No password storage — OAuth `provider_subject` only
- Image build: `linux/amd64` via buildx then push
- No workspace concept yet — keep it simple with `user_id` only

## Git

- Branch: `ai-observability-leeon`
- Add only files you modified in `git add` — no mass revert

## Last Modified Files

```
ai-observability/ai-server/app/storage.py
ai-observability/ai-server/app/main.py
ai-observability/ai-server/app/static/app.js
ai-observability/ai-server/tests/test_api.py
```

Last test result: `48 passed, 32 warnings`
