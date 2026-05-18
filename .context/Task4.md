# TASK-04: Google OAuth Live + Publish TASK-03

## Current state

TASK-03 is implemented locally:
- per-user Slack webhook URL is persisted in SQLite
- Slack settings API supports get/save/test
- Slack test button behavior is implemented in the UI
- runtime Slack notifications are sent only for High/Critical events
- per-cluster Slack on/off toggle is implemented
- Slack settings show a login guide when the user is not authenticated
- `app/static/index.html` was intentionally not changed; Slack UI is injected by `app/static/app.js`
- tests: `48 passed, 32 warnings`

TASK-03 still needs publish/deploy unless already done after this handoff.

## Remaining task count

4 tasks remain after TASK-03:
1. Google OAuth live
2. Manifest fetch refactor
3. Admin cleanup controls
4. Ops docs

## Publish TASK-03

Run from project root unless noted.

### 1. Test

```bash
cd /Users/leeon/Documents/k8s-compliance-platform
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```

Expected result from local implementation:

```text
48 passed, 32 warnings
```

### 2. Git commit and push

Add only the files changed for TASK-03 plus context files.

```bash
cd /Users/leeon/Documents/k8s-compliance-platform
git add ai-observability/ai-server/app/storage.py \
  ai-observability/ai-server/app/main.py \
  ai-observability/ai-server/app/static/app.js \
  ai-observability/ai-server/tests/test_api.py \
  .context/CONTEXT.md \
  .context/Task4.md
git commit -m "feat(ai-server): add slack notifications" \
  -m "Add per-user Slack webhook settings, test delivery, and per-cluster notification toggles." \
  -m "Notify only high and critical runtime events from enabled clusters."
git push origin ai-observability-leeon
```

### 3. Docker build and push

Use `0.1.11`; `0.1.10` was already deployed.

```bash
cd /Users/leeon/Documents/k8s-compliance-platform
docker buildx build --platform linux/amd64 \
  -t docker.io/leeon3345/compliance-ai-server:0.1.11 \
  ai-observability/ai-server \
  --push
```

### 4. VM / cluster rollout commands

Run these on the VM or terminal that has `kubectl` access to the target cluster.

```bash
kubectl set image deploy/ai-classifier -n compliance-system \
  ai-classifier=docker.io/leeon3345/compliance-ai-server:0.1.11
kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s
```

### 5. Post-deploy smoke checks

```bash
kubectl get deploy/ai-classifier -n compliance-system
kubectl get pods -n compliance-system -l app=ai-classifier
```

Then open `/ui`, log in with dev login if enabled, and verify:
- Slack Notifications area appears in the Cluster Setup area
- unauthenticated users see a login guide
- webhook URL can be saved
- test button sends a Slack test message
- cluster Slack toggle can be switched on/off
- Warning events do not notify Slack
- High/Critical events notify Slack only when the cluster toggle is on

## TASK-04 Goal

Make Google OAuth live when Google Cloud billing/credential setup is ready:
- configure real Google OAuth client ID and secret
- configure authorized redirect URI for the public AI server URL
- set `DEV_AUTH_ENABLED=false` for production/demo-live mode
- keep dev login available only for local/dev deployments
- verify `/auth/google/login`, callback, session cookie, `/me`, and `/ui` authenticated state

## Scope guidance

Likely files or config areas to inspect or touch:
- Kubernetes deployment/env configuration for `ai-classifier`
- secret management for `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`
- `PUBLIC_BASE_URL` and `SESSION_COOKIE_SECURE`
- `app/main.py` only if OAuth behavior needs small fixes after live testing
- `tests/test_api.py` only if OAuth edge-case behavior changes
- ops docs if credential/deployment steps need to be recorded

Do not touch unless explicitly requested:
- manifest fetch refactor
- admin cleanup controls
- unrelated runtime-detection manifests
- SQLite replica/strategy decisions

## OAuth deployment checklist

Google Cloud Console:
- create or confirm OAuth 2.0 Web application credentials
- add authorized redirect URI:
  - `<PUBLIC_BASE_URL>/auth/google/callback`
- ensure OAuth consent screen is configured for the intended account type

Kubernetes environment:
- set `GOOGLE_CLIENT_ID`
- set `GOOGLE_CLIENT_SECRET`
- set `PUBLIC_BASE_URL` to the external HTTPS console URL
- set `SESSION_COOKIE_SECURE=true` if public URL is HTTPS
- set `DEV_AUTH_ENABLED=false` when switching away from demo/dev login

Smoke checks:
- `/me` reports `google_configured=true`
- `/ui` shows Google login instead of only dev login
- Google login redirects to Google
- callback returns to `/ui`
- `/me` reports authenticated user email/provider
- runtime, violation detail, AI report, cluster setup, and Slack settings remain gated to the logged-in user

## Test command

```bash
cd /Users/leeon/Documents/k8s-compliance-platform
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```
