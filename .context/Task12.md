# TASK-12: Google OAuth Live Enablement and Admin Console Cleanup

## Goal

Finish the remaining product/admin work after TASK-11 UI hardening. The next focus is Google OAuth live activation and a first-class admin cleanup workflow. Validation and documentation are intentionally last so implementation issues can be closed before writing final runbooks.

## Current handoff state

- TASK-11 deploy/smoke is the immediate predecessor.
- Current local AI server/UI changes should use image tag:
  - `docker.io/leeon3345/compliance-ai-server:0.1.20`
- Google OAuth code exists but live login is still blocked until real Google Cloud OAuth credentials are available.
- Dev login remains expected while no `ai-google-oauth` Kubernetes secret exists.
- User Cluster Setup now has user-owned trash/restore plus planned permanent delete and 3-day retention behavior.
- Admin console still needs equivalent first-class cleanup controls and better filtering/search.

## P0: Google OAuth Live Activation

Implement and smoke-test the production login path once real Google credentials exist.

1. Create or receive real Google OAuth Client ID/Secret.
2. Configure authorized redirect URI for the public console URL:
   - `https://compliance-ai-console.shares.zrok.io/auth/google/callback`
3. Create the Kubernetes secret with real values only:

```bash
kubectl create secret generic ai-google-oauth \
  -n compliance-system \
  --from-literal=GOOGLE_CLIENT_ID='<real-client-id>' \
  --from-literal=GOOGLE_CLIENT_SECRET='<real-client-secret>'
```

4. Switch deployment environment for live OAuth:
   - `DEV_AUTH_ENABLED=false`
   - `SESSION_COOKIE_SECURE=true`
   - `PUBLIC_BASE_URL=https://compliance-ai-console.shares.zrok.io`
5. Roll out the current image and confirm:
   - Google login button appears
   - Google callback succeeds
   - session cookie persists
   - Runtime Detection, Cluster Setup, Violation Detail, AI Report, Slack settings all remain auth-scoped
   - logout clears the session

Do not create placeholder OAuth secrets. Fake credentials should fail clearly.

## P1: Admin Console Cleanup Update

Add admin UX for managing demo/test clusters and users without direct database edits.

1. Admin cluster table
   - Search/filter by user email, cluster name, kind, status, last seen, event count
   - Separate tabs or filters for active, disabled, deleted, demo, customer
   - Show deleted clusters clearly with `deleted_at`
2. Admin cluster lifecycle actions
   - Disable active clusters
   - Restore deleted clusters
   - Move clusters to trash
   - Permanently delete deleted clusters
   - Make destructive actions confirm clearly
3. Admin user drilldown
   - User detail section with owned clusters, event counts, last seen, Slack enabled state
   - Avoid mixing user operations, cluster operations, and event cleanup in one table
4. Admin API support
   - Add admin endpoints only where user endpoints are not sufficient
   - Preserve ownership checks and admin token checks
   - Keep user-facing cluster trash behavior scoped to the logged-in owner

## P2: Demo Data Cleanup

After admin cleanup exists, add a safe way to remove stale evaluator/demo data:

- old test clusters
- old runtime events tied to deleted clusters
- old policy apply history
- obsolete demo objects that should not appear in the evaluator path

Avoid broad deletes. Prefer filtered, reviewed cleanup actions.

## P3: Final Verification

Run this after OAuth and admin cleanup are implemented:

```bash
node --check ai-observability/ai-server/app/static/app.js
.venv/bin/python -m pytest ai-observability/ai-server/tests/
python3 -m json.tool ai-observability/dashboards/grafana/compliance-overview-classic.json >/tmp/compliance-classic.json
python3 -m json.tool ai-observability/dashboards/grafana/compliance-overview.json >/tmp/compliance-v2.json
python3 -m json.tool runtime-detection/manifests/grafana/runtime-dashboard.json >/tmp/runtime-dashboard.json
```

Smoke-test on VM:

1. Google login
2. Policy generation and fallback apply guide
3. Cluster trash/restore/permanent delete
4. Admin cleanup flow
5. Runtime event view
6. Violation Detail
7. AI Report PDF
8. Grafana dashboards

## P4: Final Docs

Write/update docs only after the flows above are stable:

- OAuth setup and rollback
- image build/deploy procedure
- zrok stabilization notes
- SQLite/Grafana backup and persistence
- Grafana dashboard apply commands
- demo data cleanup procedure
- user-cluster RBAC expectations for fallback apply

