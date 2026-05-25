# TASK-18: Account Deletion and Final Demo Hardening

## Why This Task Exists

The UI now has a polished landing page, `/docs`, user console, and admin console from TASK-17. One product/security decision remains intentionally deferred: user account deletion.

Do not add a casual "회원 탈퇴" button without defining what happens to clusters, ingest tokens, runtime events, reports, Slack settings, Grafana orgs, and audit-relevant data.

## Goals

### 1. User Account Deletion Flow

Add a safe self-service account deletion flow for logged-in users.

Recommended UX:

- Add a "회원 탈퇴" entry in a settings/account area, not in the primary navigation.
- Use a destructive confirmation modal.
- Require explicit typed confirmation, for example the user's email.
- Explain what will be deleted and what may be retained for audit/safety.
- After completion, clear the session and redirect to the landing page.

Backend decisions to make before implementation:

- Should deletion be soft-delete first, then purge after a retention window?
- Should cluster records be moved to `deleted` and ingest tokens revoked immediately?
- Should runtime events be anonymized, retained, or deleted?
- Should AI reports and policy apply history be deleted with the user?
- Should Slack webhook/config be deleted immediately?
- Should Grafana org/datasource/dashboard copies be deleted, disabled, or retained?

Minimum implementation expectation:

- Revoke or invalidate all cluster ingest tokens owned by the user.
- Prevent future runtime ingest from deleted-user clusters.
- Clear user session cookies.
- Mark the user deleted or disabled in storage.
- Do not expose deleted-user data in `/ui`.
- Admin should still be able to audit the deletion state.

### 2. Admin Cleanup Follow-up

Continue admin cleanup after TASK-17:

- Separate user operations from cluster operations more clearly.
- Add a dedicated user detail pane with clusters, event count, Slack status, and deletion state.
- Decide if admin can restore a soft-deleted user.
- Keep destructive actions visually distinct and confirmation-protected.

### 3. Final Demo / Deployment Hardening

Before final public demo:

- Rotate live `ai-classifier-admin` `ADMIN_TOKEN` away from `change-me-before-deploy`.
- Confirm `DEV_AUTH_ENABLED=false`.
- Confirm `SESSION_COOKIE_SECURE=true`.
- Verify `/docs`, `/ui`, `/admin`, `/grafana-ui/` paths after deploying the new image.
- Capture final screenshots after TASK-17 UI polish.

## Verification

Local:

```bash
node --check ai-observability/ai-server/app/static/app.js
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```

Manual browser smoke:

- Logged-out `/ui`
- `/docs` interactive sections
- Google login
- Logged-in dashboard
- Cluster Setup
- Violation Detail
- AI Report
- Grafana dashboard open
- `/admin` light/dark mode and cluster list
- Account deletion confirmation flow after it is implemented

## Do Not Regress

- Keep Grafana access behind `/grafana-ui/`.
- Keep user-scoped Prometheus datasource behavior.
- Keep Falco ingest as bearer-token machine-to-machine auth.
- Do not expose admin tokens or ingest tokens in ordinary user-facing pages.
- Do not turn account deletion into a hard delete until retention/audit behavior is decided.

