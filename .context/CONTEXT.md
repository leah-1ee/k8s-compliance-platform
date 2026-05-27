# Project Context

## One-line Summary
Policy-as-Code based Kubernetes compliance automation platform.
Natural language → Rego policy via LLM, Falco event AI classification, real-time dashboard.

## Current Image Version
Current VM image observed by user during TASK-17/18/19 UI-docs stabilization: `docker.io/leeon3345/compliance-ai-server:0.2.10`
Next build/deploy tag for TASK-20 demo polish: use a fresh tag after `docker.io/leeon3345/compliance-ai-server:0.2.10`; do not overwrite or reuse older tags.
`0.1.10` was the older deployed image. `0.1.11` was prepared by TASK-04, `0.1.12` by TASK-05, `0.1.13` by TASK-06, `0.1.15` by TASK-10 branding/deploy prep, `0.1.16`/`0.1.17` were used during TASK-10 policy apply/UI iteration, `0.1.18` is the TASK-10 completed/Grafana-title image observed in use, `0.1.20` is the TASK-11 UI/trash cleanup follow-up target, `0.1.43` started the TASK-15/16 Grafana proxy and dashboard recovery image line, `0.1.47` included TASK-16 Grafana Live, splash storage, favicon, and transient Grafana retry hardening, and `0.2.10` is the current UI/docs polish and demo-prep image line.

## Tech Stack
- Backend: Python (FastAPI), SQLite (WAL mode, PVC persistent)
- Monitoring: Prometheus, Grafana
- Auth: Google OAuth live login works with real credentials; dev-login fallback exists but live manifests should keep `DEV_AUTH_ENABLED=false`
- Infra: Kubernetes, OPA Gatekeeper, Falco Sidekick

## Completed

- Gatekeeper policy UI: public (no login required)
- Google OAuth: live activation completed; real OAuth credentials exist and users can log in with Google
- Dev login (`/auth/dev-login`): fallback exists; live deployment should keep `DEV_AUTH_ENABLED=false`
- `/docs`: public documentation page, accessible without login
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
- TASK-04 original blocker resolved later: real Google OAuth Client ID/Secret now exist and live Google login works
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
- TASK-11 VM/user-reported verification: `0.1.18` was rolled out successfully, Grafana dashboard titles were updated, and `ai-classifier` ServiceAccount returned `yes` for Gatekeeper constraint read access.
- TASK-11 UI hardening done locally: policy fallback guide now explains up front that the AI server cannot directly apply to user clusters, splits kubectl commands into editable/copyable steps, uses supplied arrow icons, improves light-mode code contrast, and labels fallback resources as pending kubectl execution instead of `skipped`.
- TASK-11 Cluster Setup cleanup done locally: user trash view is intended to show deleted clusters only, deleted clusters can be restored or permanently deleted, and deleted clusters are purged automatically after 3 days.
- TASK-12 created: Google OAuth live activation and admin console cleanup are next; validation and docs are intentionally last.
- TASK-13 done locally/VM-iterated: secure Grafana OSS multi-tenant observability implemented with Prometheus ClusterIP, Grafana ClusterIP behind KubeOwl `/grafana-ui/` auth proxy, Prometheus proxy query injection, per-user Grafana org provisioning, proxy-backed datasource, multi-dashboard master copy via `GRAFANA_MASTER_DASHBOARD_UIDS`, audit logging, rate limiting, and tests.
- TASK-13 VM findings fixed locally: NetworkPolicy needs namespaceSelector + podSelector because ai-server runs in `compliance-system` while Prometheus/Grafana run in `monitoring`; Grafana 13 datasource update needs UID endpoint; auth proxy headers must be ASCII-safe for Korean display names; dashboard opening should use `/grafana-ui/d/...?...orgId=<user-org>` instead of `/org/switch`.
- TASK-13 UI follow-up done locally: removed topbar global Grafana button, kept Grafana access on per-cluster rows, changed cluster row actions to vertical layout, and replaced the user trash action text with a red icon-only button.
- TASK-13/14 metrics finding: Falco Sidekick ingest to Runtime Detection works for separate user clusters when `FALCO_INGEST_BASE_URL` points to a reachable central ingest URL, but Grafana remains `No data` until ai-server exports trusted SQLite event aggregates as Prometheus metrics. Security decision for TASK-14: prefer ai-server `/metrics` scraped by central Prometheus over user-cluster Prometheus remote_write/federation.
- TASK-15 completed locally/VM-validated: Grafana Runtime Detection and KubeOwl Observability dashboards now show user-scoped metrics (`Reporting=1`, `Total=5`, `High=3`, `Medium=2`) after fixing ai-server `PROMETHEUS_URL` to the kube-prometheus service, persisting that env in manifests, and removing the missing `screenshot-falco.png` hover-card reference.
- TASK-15 validation note: `runtime-detection/manifests/grafana/dashboard-configmap.yaml` and `ai-observability/ai-server/app/grafana/dashboard_template.json` both provision user datasource UID `kubeowl-prom-f4efeb00a6e0387b` for `cluster-ff1f78d5c20b`; Grafana `/api/ds/query` returned the expected `5`.
- TASK-16 created: public Grafana access is now data-correct but still visually unstable because `/grafana-ui/api/live/ws` returns `403` and the browser can still surface intermittent public-path `502`s; keep `api/ds/query` and `api/annotations` as-is and stabilize or suppress Grafana Live for the demo path.
- TASK-16 completed locally/VM-iterated: Grafana Live `403` noise removed, `/api/ds/query` and `/api/annotations` kept intact, splash user-storage 404 and `/favicon.ico` 404 suppressed, transient Grafana upstream `502/503/504` calls retried, and runtime dashboard panels polished.
- TASK-17 created: homepage/user console and admin page UI polish should be done with the existing vanilla HTML/CSS/JS stack before final screenshots; defer full React migration to a later v2 frontend refactor.
- Security finding before TASK-17: live `ai-classifier-admin` Secret was observed as `ADMIN_TOKEN=change-me-before-deploy`; rotate it to a strong random value before treating public admin as demo-safe. This does not delete Grafana/SQLite data.
- TASK-07 note: no AI server code or UI changed; no new AI server image tag is required
- Tests: latest TASK-16 run was `105 passed, 101 warnings` in `ai-observability/ai-server/tests`; `node --check ai-observability/ai-server/app/static/app.js` should still be run after TASK-17 UI edits

## Deployment Notes

- Current deployed image target: `docker.io/leeon3345/compliance-ai-server:0.2.10`
- Active deployment in cluster: `deploy/ai-classifier -n compliance-system`
- Current live deployment env expectations:
  - `CLUSTER_NAME=school-cloud`
  - `DEMO_CLUSTER_NAMES=school-cloud,boanlab-cloud`
  - `DEV_AUTH_ENABLED=false`
  - `SESSION_COOKIE_SECURE=true`
  - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` from real `ai-google-oauth` Secret
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
  - `docker.io/leeon3345/compliance-ai-server:0.1.20`
  - `kubectl set image deploy/ai-classifier -n compliance-system ai-classifier=docker.io/leeon3345/compliance-ai-server:0.1.20`
  - `kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s`
- TASK-17/TASK-18/TASK-19 rollout target image:
  - `docker.io/leeon3345/compliance-ai-server:0.2.10`
  - `kubectl apply -f cloud-deploy/ai-server.yaml`
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

- Current live auth target: `DEV_AUTH_ENABLED=false`, `SESSION_COOKIE_SECURE=true`, real `ai-google-oauth` Secret configured
- Google login works in live deployment
- Dev login remains a fallback route but should stay disabled in live public demo
- Admin token security issue: rotate `ai-classifier-admin` away from `change-me-before-deploy`

## UI Access Control

| Feature | Auth Required |
|---|---|
| Policy creation (Gatekeeper) | No (public) |
| Docs | No (public) |
| Runtime detection | Yes |
| Violation Detail | Yes |
| AI Report | Yes |
| Cluster Setup | Yes |
| Slack settings | Yes |
| Admin (`/admin`) | Admin only |
| Policy cluster apply | Yes |

## Remaining Tasks (priority order)

1. **TASK-20 Demo Scenario and Repository Cleanup (P0)** — finalize the demo walk-through, keep the public docs and landing experience aligned, finish folder/file organization and stale reference cleanup, and keep `README.md`, `ai-observability/docs/ai-server-test/testing.md`, `ai-observability/docs/ai-server-test/ai-api.md`, and `ai-observability/docs/web-ui/README.md` in sync with the public `/docs` entry and current `0.2.10` rollout notes; see `.context/Task20.md`.

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
ai-observability/ai-server/app/static/docs.html
ai-observability/ai-server/app/static/assets/kubeowl-logo.png
ai-observability/ai-server/app/static/assets/main-logo.png
ai-observability/ai-server/app/static/assets/landing-background.png
ai-observability/ai-server/app/grafana/
ai-observability/ai-server/tests/test_api.py
ai-observability/ai-server/tests/test_grafana.py
ai-observability/ai-server/tests/test_promql_inject.py
ai-observability/ai-server/tests/test_proxy_auth.py
ai-observability/dashboards/grafana/
./k8s/
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
.context/Task12.md
.context/Task13.md
.context/Task14.md
.context/Task17.md
.context/Task18.md
```

TASK-17 UI/docs local test result: `106 passed, 101 warnings` after landing, `/docs`, `/admin`, Grafana card, and dashboard polish.
