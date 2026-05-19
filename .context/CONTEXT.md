# Project Context

## One-line Summary
Policy-as-Code based Kubernetes compliance automation platform.
Natural language → Rego policy via LLM, Falco event AI classification, real-time dashboard.

## Current Image Version
Current VM image observed: `docker.io/leeon3345/compliance-ai-server:0.1.17`
Next build/deploy tag for current AI server/UI changes: `docker.io/leeon3345/compliance-ai-server:0.1.18`
`0.1.10` was the older deployed image. `0.1.11` was prepared by TASK-04, `0.1.12` by TASK-05, `0.1.13` by TASK-06, `0.1.15` by TASK-10 branding/deploy prep, and `0.1.16`/`0.1.17` were used during TASK-10 policy apply/UI iteration; do not overwrite or reuse older tags.

## Tech Stack
- Backend: Python (FastAPI), SQLite (WAL mode, PVC persistent)
- Monitoring: Prometheus, Grafana
- Auth: Google OAuth (implemented, deployment prepared, credentials not issued yet) + dev-login fallback
- Infra: Kubernetes, OPA Gatekeeper, Falco Sidekick

## Completed

- Gatekeeper policy UI: public (no login required)
- Google OAuth: code done, not live (Google Cloud 카드 문제로 보류)
- Dev login (`/auth/dev-login`): active via `DEV_AUTH_ENABLED=true`
- SQLite: WAL mode, PVC persistent
- `/admin`: cluster register, token issue/rotate/disable
- `/admin`: full user list, per-user cluster list, active/disabled status, last seen, event count
- `/api/clusters/{cluster_id}` supports user-owned soft delete (`status=deleted`) and restore from trash (`status=disabled`)
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
- TASK-04 done locally: Google OAuth live deployment manifest prepared for `0.1.11`
- TASK-04 done locally: `ai-google-oauth` secret references are required in live manifests so fake/missing OAuth credentials fail clearly
- TASK-04 blocked for actual live login: Google OAuth Client ID/Secret have not been created yet; do not create the Kubernetes secret with placeholder values
- TASK-05 done locally: `/resource-manifest` now returns user-scoped kubectl manifest guidance instead of central-server Kubernetes API fetches
- TASK-05 done locally: runtime analysis no longer falls back to direct central-server manifest fetch when event snapshots are missing
- TASK-05 done locally: UI shows copyable kubectl manifest lookup guidance without changing `app/static/index.html`
- TASK-05 done locally: focused tests added for manifest guidance auth, user scoping, kubectl command generation, and missing-field degradation
- TASK-06 done locally: `/ingest/falco-events` accepts `resource_manifest` snapshots from top-level payloads or nested `event` payloads
- TASK-06 done locally: string snapshots are stored as-is after trimming; structured object snapshots are normalized to JSON text
- TASK-06 done locally: malformed scalar snapshots and snapshots over 200 KB are ignored safely and fall back to TASK-05 kubectl guidance
- TASK-06 done locally: event detail and `/analyze-runtime-event/{id}` use the stored snapshot only through the owning user's cluster scope
- TASK-06 done locally: `app/static/index.html` was not touched; existing `app/static/app.js` behavior already handles stored snapshots and kubectl guidance
- TASK-06 deployed/smoke-tested on VM with image `docker.io/leeon3345/compliance-ai-server:0.1.13`
- TASK-06 VM smoke used the `school-cloud` demo cluster and verified `TASK-06 Manifest Snapshot Smoke`
- TASK-06 screenshot evidence stored under `ai-observability/docs/ai-server-test/task6-manifest-snapshot/`
- TASK-07 done locally: Gatekeeper policy drift between `cloud-deploy/policies` and `k8s-policy-engine` was compared and synchronized
- TASK-07 done locally: `k8s-policy-engine` is documented as the development/validation source of truth; `cloud-deploy/policies` is the VM deployable copy
- TASK-07 done locally: `local-path-storage` and `falco` namespace exclusions plus `docker.io/leeon3345/` registry allowlist are mirrored in both policy trees
- TASK-07 done locally: policy dry-run/smoke commands and Falco validation/smoke commands are documented
- TASK-07 VM validated: Gatekeeper dry-run passed; allowed image admitted; `nginx:latest` denied by registry/latest policies
- TASK-07 VM validated: Falco rules loaded with existing `evt.dir` deprecation warnings; Falco/Falco Sidekick reached Running after `falco` namespace policy exclusion
- TASK-07 VM validated: AI Console showed new Falco runtime events from `school-cloud`
- TASK-07 screenshot evidence stored under `ai-observability/docs/ai-server-test/task7-policy-falco-hygiene/`
- UI refactor done locally: `KubeOwl` B2B Cloud Console redesign using vanilla HTML/CSS/JS only
- UI refactor done locally: fixed left sidebar navigation, responsive summary metric cards, Policy Generator split-view, dark/light theme toggle, polished code output panels
- UI refactor done locally: Runtime Event cards now show id/time/context, default limit is 50, display limit control exists, and infra namespace hiding is available
- UI refactor done locally: Slack Notifications, Cluster Setup, Violation Detail, and AI Report spacing/badge/toggle polish completed
- TASK-10 update done locally: dashboard metrics are no longer hard-coded; `/dashboard-summary` drives Active Policies, Recent Violations, Runtime Events, and Last Sync
- TASK-10 note: `Active Policies` counts live Gatekeeper `constraints.gatekeeper.sh/v1beta1` objects, not generated policy drafts; Policy Generator still needs a cluster apply flow for this metric to increase from generated policies
- TASK-10 update done locally: Cluster Setup supports trash/restore for user-owned clusters
- Grafana recovery done locally: Compliance Overview and Runtime Detection dashboards are now provisioned from JSON/ConfigMap instead of relying on volatile Grafana UI state; important stat panels fall back to `0` when Prometheus series do not exist yet
- TASK-08 preserved: Runtime Event UI usability follow-up remains the previous task context
- TASK-09 done locally: pre-login landing/intro and user login UX for the console
- TASK-10 done locally: brand renamed to `KubeOwl`, uploaded owl/Kubernetes logo added, Grafana/Slack CSS data-URL icons applied, and deploy manifests prepared for image `docker.io/leeon3345/compliance-ai-server:0.1.15`
- TASK-10 policy apply flow done locally and committed: authenticated cluster policy apply endpoint, per-user cluster ownership/status checks, multi-document ordering, apply history, honest `not_configured` fallback, and tests added
- TASK-10 fallback fixed locally and committed: Gatekeeper `ConstraintTemplate` and generated `Constraint` are split into staged heredocs with CRD Established wait; fallback includes permission check, admin RBAC, dry-run, and apply commands
- TASK-10 UI polish done locally and committed/partially pending: Policy Apply guidance, status pill, Cluster Setup/Sidekick terminal block, Slack cluster notification spacing, EnforcementAction selected-state visibility, and Grafana dashboard card layout
- TASK-10 Grafana dashboard naming done locally: provisioned `Compliance Overview` renamed to `Gatekeeper Compliance Overview`; `Runtime Detection — Compliance Dashboard` renamed to `Runtime Detection`; ConfigMap JSON source remains the source of truth
- TASK-10 VM finding: `Active Policies` requires read-only `constraints.gatekeeper.sh` RBAC on the actual deployment ServiceAccount (`compliance-system:ai-classifier`), not `compliance-system:default`
- TASK-07 note: no AI server code or UI changed; no new AI server image tag is required
- Tests: `62 passed, 56 warnings` in `ai-observability/ai-server/tests`; `node --check ai-observability/ai-server/app/static/app.js` passes

## Deployment Notes

- Deployed image target: `docker.io/leeon3345/compliance-ai-server:0.1.13`
- Active deployment in cluster: `deploy/ai-classifier -n compliance-system`
- Deployment env:
  - `CLUSTER_NAME=school-cloud`
  - `DEMO_CLUSTER_NAMES=school-cloud`
  - `DEV_AUTH_ENABLED=true`
  - `DEV_AUTH_EMAIL=demo@school.test`
- TASK-04 prepared deployment env in manifests:
  - `image=docker.io/leeon3345/compliance-ai-server:0.1.11`
- TASK-05 handoff image:
  - build/push/set `docker.io/leeon3345/compliance-ai-server:0.1.12`
  - `DEV_AUTH_ENABLED=false`
  - `SESSION_COOKIE_SECURE=true`
  - `PUBLIC_BASE_URL=https://compliance-ai-console.shares.zrok.io`
  - required secret: `ai-google-oauth` with `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
- TASK-06 handoff image:
  - build/push/set `docker.io/leeon3345/compliance-ai-server:0.1.13`
  - Future collector/agent payload contract: send `resource_manifest` as either a YAML string at the top level or a structured object/string under `event.resource_manifest`
  - Keep ingest auth as `Authorization: Bearer <ingest_token>`
  - Do not configure fake Google OAuth credentials; live OAuth smoke remains deferred until real credentials exist
- TASK-07 note:
  - Policy/Falco hygiene changed only policy/docs assets; no new AI server image is required
  - If future AI server code changes after TASK-10, use `docker.io/leeon3345/compliance-ai-server:0.1.16`
  - Gatekeeper policy source of truth: `k8s-policy-engine/`
  - VM deployable policy copy: `cloud-deploy/policies/`
  - Falco namespace is excluded from Gatekeeper validate/mutation policies because Falco requires privileged host-level access
  - Falco Sidekick demo install should keep `minimumpriority=warning`; lowering to `notice` is useful for smoke but too noisy for the UI
- Update command:
  - `kubectl set image deploy/ai-classifier -n compliance-system ai-classifier=docker.io/leeon3345/compliance-ai-server:<tag>`
  - `kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s`
- Runtime event verification requires Falco + Falco Sidekick installed in the user's cluster. If `kubectl get pods -A | grep -Ei 'falco|sidekick'` shows no running Falco/Sidekick pods, the UI will correctly show no recent runtime events.
- User Cluster Setup cleanup supports trash/restore. Admin cleanup/refactor still needs a first-class archive/restore/delete UX.
- TASK-10 VM rollout target image:
  - `docker.io/leeon3345/compliance-ai-server:0.1.15`
  - `kubectl set image deploy/ai-classifier -n compliance-system ai-classifier=docker.io/leeon3345/compliance-ai-server:0.1.15`
  - `kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s`
- TASK-11/current rollout target image:
  - `docker.io/leeon3345/compliance-ai-server:0.1.18`
  - `kubectl set image deploy/ai-classifier -n compliance-system ai-classifier=docker.io/leeon3345/compliance-ai-server:0.1.18`
  - `kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s`
- TASK-11 Grafana ConfigMap apply:
  - `kubectl apply -f ai-observability/dashboards/grafana/compliance-overview-configmap.yaml`
  - `kubectl apply -f runtime-detection/manifests/grafana/dashboard-configmap.yaml`
  - Restart Grafana if sidecar/provisioning does not refresh titles automatically
- TASK-11 Active Policies RBAC:
  - deployment ServiceAccount observed: `ai-classifier`
  - required read-only permission: `get,list,watch` on `resources: ["*"]` in `apiGroups: ["constraints.gatekeeper.sh"]`
  - verify with `kubectl auth can-i list k8srequirenonroot.constraints.gatekeeper.sh --as=system:serviceaccount:compliance-system:ai-classifier`

## Auth State

- Current deployed dev mode: `DEV_AUTH_ENABLED=true`, `DEV_AUTH_EMAIL=demo@school.test`
- UI shows dev-login button only — this is EXPECTED (no Google Secret configured)
- Production/live OAuth: `DEV_AUTH_ENABLED=false`, Google OAuth secret required; wait until real Google Cloud OAuth credentials exist

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
| Policy cluster apply | Yes |

## Remaining Tasks (priority order)

1. **TASK-11 VM rollout and smoke (P0)** — build/push `docker.io/leeon3345/compliance-ai-server:0.1.18`, roll out `deploy/ai-classifier`, apply Grafana ConfigMaps, and verify dashboard titles/UI changes are live.
2. **Active Policies verification (P0)** — ensure `compliance-system:ai-classifier` has read-only `constraints.gatekeeper.sh` RBAC and confirm `/dashboard-summary` reports live Gatekeeper constraint count.
3. **Demo hardening pass (P0)** — verify one end-to-end story: generate/apply Gatekeeper policy, trigger/observe violation, show Runtime Detection event, run Violation Detail, generate AI Report PDF, and show Grafana dashboards with non-empty or intentionally-zero panels.
4. **Grafana cleanup (P1)** — decide whether the visible `Grafana Overview` dashboard is external/default or should be removed/renamed; keep repo JSON/ConfigMaps as source of truth.
5. **User-cluster RBAC docs (P1)** — document that fallback apply requires the user's kubeconfig account to have Gatekeeper/NetworkPolicy permissions; central per-user-cluster Active Policies needs a future agent/read-only connection model.
6. **Ops docs (P1)** — document zrok stabilization, image tag/deploy procedure, SQLite/Grafana backup and persistence, Grafana dashboard apply commands, and demo data cleanup.
7. **Admin page cleanup/refactor (P1)** — add first-class archive/restore/delete UX for test clusters, improve table filtering/search, and separate user/cluster/event operations.
8. **Google OAuth live smoke (P2/final)** — after Google Console signup and real credentials exist, create real `ai-google-oauth` secret and deploy/smoke-test the current image.

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
ai-observability/ai-server/app/runtime_client.py
ai-observability/ai-server/app/static/index.html
ai-observability/ai-server/app/static/app.js
ai-observability/ai-server/app/static/styles.css
ai-observability/ai-server/app/static/assets/kubeowl-logo.png
ai-observability/ai-server/tests/test_api.py
ai-observability/dashboards/grafana/
ai-observability/k8s/ai-server.yaml
ai-observability/docs/ai-server-test/task6-manifest-snapshot/
ai-observability/docs/ai-server-test/task7-policy-falco-hygiene/
cloud-deploy/README.md
cloud-deploy/policies/
k8s-policy-engine/README.md
k8s-policy-engine/constraints/
k8s-policy-engine/mutations/
runtime-detection/README.md
runtime-detection/manifests/grafana/
cloud-deploy/ai-server.yaml
.context/CONTEXT.md
.context/Task11.md
.context/Task4.md
.context/Task5.md
.context/Task6.md
.context/Task7.md
.context/Task8.md
.context/Task9.md
.context/Task10.md
```

Last AI server test result: `62 passed, 56 warnings` after policy apply flow, fallback guidance, UI layout polish, and Grafana dashboard card/title updates
