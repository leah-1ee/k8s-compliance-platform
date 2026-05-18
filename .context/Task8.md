# TASK-08: Pre-login Landing and User Login UX

## Current state

The AI server UI has been locally refactored into the `ComplianceOps` B2B Cloud Console:

- Vanilla HTML/CSS/JS only. Do not introduce React, Vue, TailwindCSS, Bootstrap, or other UI frameworks.
- Current UI files:
  - `ai-observability/ai-server/app/static/index.html`
  - `ai-observability/ai-server/app/static/styles.css`
  - `ai-observability/ai-server/app/static/app.js`
- The console now has:
  - fixed left sidebar navigation
  - responsive summary metric cards
  - Policy Generator split view
  - dark/light theme toggle using `data-theme`
  - polished Runtime Event cards/filters
  - polished Slack Notifications UI
  - refined spacing and badge styles across Dashboard, Cluster Setup, Violation Detail, and AI Report
- Existing auth behavior:
  - Google OAuth code exists but live credentials are not ready.
  - Dev login is available when `DEV_AUTH_ENABLED=true`.
  - Logged-in cluster/event/report APIs are user-scoped.
  - Policy creation remains public.
- Latest local validation after UI edits:
  - `node --check ai-observability/ai-server/app/static/app.js`
  - `.venv/bin/python -m pytest ai-observability/ai-server/tests/`
  - Result: `53 passed, 41 warnings`

## Problem

The app now looks like a cloud console after login, but the pre-login experience is still not productized:

- First-time visitors do not get a clear explanation of what `ComplianceOps` is before signing in.
- The login area is still mostly a utility control instead of an intentional entry point.
- A user should understand, at a glance:
  - this is a Kubernetes Policy-as-Code and runtime compliance platform
  - natural language can generate Gatekeeper policies
  - clusters can be registered and monitored through Falco Sidekick
  - runtime events can be analyzed with AI assistance
  - Google login is the intended production path, with dev login only for local/demo mode
- The pre-login screen must be responsive and should not break the existing authenticated console.

## Important non-goals

Do not work on:

- Google Console signup or OAuth credential creation
- creating or applying the real `ai-google-oauth` Kubernetes secret
- production OAuth smoke testing
- admin delete/archive controls
- backend auth redesign, passwords, workspaces, or multi-tenant organization models
- changing Falco Sidekick priority from `warning` to `notice`
- changing SQLite replica/strategy
- introducing frontend frameworks or build tooling

## TASK-08 Goal

Implement a responsive pre-login landing/intro experience and clearer login UX for `ComplianceOps`.

Target behavior:

- When the user is not authenticated:
  - show a polished intro/landing section explaining what `ComplianceOps` does
  - show clear primary login CTA(s):
    - Google login when `auth.google_configured=true`
    - Dev login when `auth.dev_enabled=true`
  - clearly distinguish dev login as local/demo mode
  - preserve access to public Policy Generator behavior if that is still desired
  - keep protected areas gated with friendly messages
- When the user is authenticated:
  - show the current console-first experience
  - preserve sidebar navigation, theme toggle, summary cards, and all current UI behavior
- The intro must be responsive:
  - desktop: clean hero/intro + concise capability cards
  - mobile: single-column layout with readable text and no overlap
- Use only:
  - vanilla HTML
  - pure CSS
  - vanilla JavaScript

## Suggested implementation shape

1. Inspect current auth rendering and gates.
   - Likely file: `ai-observability/ai-server/app/static/app.js`
   - Relevant functions:
     - `loadAuthStatus`
     - `renderAuthStatus`
     - `renderAuthGates`
     - `logout`

2. Add a pre-login intro section in `index.html`.
   - Suggested location: inside `main.main-shell`, above or near `workspace`.
   - Suggested ids/classes:
     - `landingIntro`
     - `landingLoginActions`
     - `landingFeatureGrid`
   - Avoid marketing fluff; make it concise and product-specific.

3. Add CSS for the intro.
   - Use existing CSS variables and dark/light theme system.
   - Must work in both `:root` light mode and `[data-theme="dark"]`.
   - Keep sidebar and console responsive.

4. Wire auth-dependent visibility in `app.js`.
   - Hide/show intro based on `authState.authenticated`.
   - Show/hide Google/dev login CTAs based on `/me` auth config.
   - Do not duplicate session logic.

5. Add/update focused tests if needed.
   - Existing `test_ui_is_served` checks static UI strings.
   - If adding new important static text or controls, update tests only if necessary.

## Validation commands

Run from project root:

```bash
node --check ai-observability/ai-server/app/static/app.js
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```

Manual local UI validation:

```bash
cd /Users/leeon/Documents/k8s-compliance-platform/ai-observability/ai-server
DEV_AUTH_ENABLED=true \
DEV_AUTH_EMAIL=demo@school.test \
/Users/leeon/Documents/k8s-compliance-platform/.venv/bin/python -m uvicorn app.main:app \
  --host 127.0.0.1 \
  --port 8002
```

Open:

```text
http://127.0.0.1:8002/ui
```

UI checks:

- Logged out state explains `ComplianceOps` clearly.
- Login CTAs match available auth config.
- Dev login still works locally.
- Logged-in console still renders Dashboard, Policy Generator, Cluster Setup, Violation Detail, AI Report.
- Theme toggle works before and after login.
- Mobile/narrow viewport does not overlap or truncate text.

## Image/version note

Current deployed image remains:

```text
docker.io/leeon3345/compliance-ai-server:0.1.13
```

This task changes frontend assets, so the next build/deploy image should be:

```text
docker.io/leeon3345/compliance-ai-server:0.1.14
```
