# TASK-20: Demo Scenario and Repository Cleanup

## Why This Task Exists

The core product is now feature-complete. The last stretch is to make the demo flow feel intentional end-to-end, then clean up folders, file names, and stale references so the repository reads like a finished project instead of an active scratchpad.

## Current State

- Public landing page, docs, policy generation, runtime analysis, admin audit log, and Grafana access are all in place and have the current UI/docs polish.
- Docs are public and do not require login.
- The remaining work is mostly presentation, consistency, demo narration, and repository hygiene.

## Goals

1. Lock the final demo scenario from landing page to the main user and admin flows.
2. Keep the initial screen polished, including the landing cues, button hierarchy, and visual rhythm.
3. Keep docs aligned with implemented features, including the public docs entry, the apply guide, and the remaining security notes.
4. Clean up folders, file names, and outdated references so current image tags, task notes, and screenshots stay aligned.
5. Update context notes and docs together so future changes do not reintroduce stale instructions.

## Suggested Demo Flow

- Open the public landing page.
- Click `Sign in` and reach the main console.
- Show Policy Generator, generated artifacts, and guardrails.
- Show the cluster apply guide and the kubectl troubleshooting flow for Assign / mutation policies.
- Show runtime analysis and AI Report.
- Open `/admin` and show audit log and cluster/admin controls.
- Open `/docs` as an unauthenticated user and show the public documentation.
- Finish with a short VM rollout and browser refresh check so the demo story matches the deployed image.

## Verification

- `node --check ai-observability/ai-server/app/static/app.js`
- `.venv/bin/python -m pytest ai-observability/ai-server/tests/`
- Manual browser check of `/`, `/docs`, `/ui`, and `/admin`
- VM rollout status check for the current image tag before capture

## Do Not Regress

- Keep `/docs` publicly accessible.
- Keep the landing `Sign in` flow and landing cues readable.
- Keep current guardrails and audit log behavior intact.
- Avoid introducing new unfinished features during cleanup.
