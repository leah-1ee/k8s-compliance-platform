# TASK-08: Runtime Event UI Usability

## Current state

TASK-07 is complete locally and VM-validated:
- Gatekeeper dry-run passed for templates, constraints, and mutations.
- Policy smoke passed:
  - `docker.io/leeon3345/compliance-ai-server:0.1.13` was admitted.
  - `nginx:latest` was denied by `allow-registries` and `block-latest-tag`.
- `falco` namespace was added to Gatekeeper validation/mutation exclusions because Falco/Falco Sidekick require privileged host-level access.
- Falco and Falco Sidekick were brought up successfully after policy exclusions.
- Falco dry-run loaded `/etc/falco/rules.d/compliance-rules.yaml` successfully with existing `evt.dir` deprecation warnings.
- AI Console showed newly ingested Falco runtime events from the `school-cloud` demo cluster.
- TASK-07 screenshot evidence is under `ai-observability/docs/ai-server-test/task7-policy-falco-hygiene/`.

## Problem found during TASK-07 smoke

Runtime detection works end-to-end, but the UI is hard to use during real Falco event flow:

- Repeated Falco events look identical in the runtime event list.
- Event cards do not show enough unique context to identify which event will open.
- Detail loading gives little confidence about which selected event is being displayed.
- The default `/runtime-events?limit=20` view can push older smoke events, such as TASK-06 evidence events, out of sight.
- Infra noise can dominate the list. During TASK-07, repeated `Contact K8S API Server From Container` events from `monitoring/monitoring-grafana-...` made the screen noisy.
- Lowering Falco Sidekick `minimumpriority` to `notice` is useful for end-to-end smoke, but too noisy for demo/ops UI. Default demo install should remain `warning`.

## Important non-goals

Do not work on:
- Google Console setup
- `ai-google-oauth` secret creation
- production OAuth smoke testing
- admin cluster delete/archive controls unless explicitly requested
- broad visual redesign
- changing Falco Sidekick default install priority from `warning` to `notice`
- changing SQLite replica/strategy

## TASK-08 Goal

Improve runtime event list/detail usability so repeated events are distinguishable and demo operators can quickly find the event they just generated.

Target behavior:
- Runtime event list cards show enough identifying metadata:
  - event time
  - event id or short id
  - rule
  - cluster and cluster kind
  - namespace / pod / container
  - image or image repository if available
  - source/action
- Selected event detail clearly shows the same event id/time/context as the list card.
- Runtime event filters make demo/ops use easier:
  - namespace filter, or
  - "hide infra namespaces" toggle for `kube-system`, `monitoring`, `gatekeeper-system`, `falco`, `local-path-storage`, CNI namespaces
- Repeated events are less confusing:
  - either group by `rule + namespace + pod + container` with count/latest time, or
  - keep individual events but make time/id visible and scan-friendly.
- Older smoke events should be reachable:
  - increase default limit, add "load more", or expose a limit control.

## Suggested implementation shape

1. Inspect current runtime event response fields and frontend rendering.
   - Likely files: `ai-observability/ai-server/app/main.py`, `app/static/app.js`, tests.
   - Avoid `app/static/index.html` unless a new static container/control is truly necessary.

2. Update the runtime event list card.
   - Add compact timestamp.
   - Add short event id.
   - Add namespace/pod/container/image context.
   - Preserve current cluster/kind/source filters.

3. Improve selected detail state.
   - Show selected event id and timestamp near the detail heading.
   - Ensure loading/error states mention the selected id or context.

4. Add filtering or noise control.
   - Prefer small, practical controls over a redesign.
   - A "hide infra namespaces" toggle is useful for demos.

5. Add tests proportional to the change.
   - Backend tests if API fields/filtering change.
   - Frontend smoke/manual verification if rendering only changes.

## Validation commands

If AI server code changes, run:

```bash
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```

Manual VM/UI validation:

```bash
kubectl get pods -n falco -o wide
kubectl logs -n compliance-system deploy/ai-classifier --tail=150 | grep -Ei 'POST /ingest/falco-events|runtime|falco|ingest'
```

UI checks:
- Dev login works.
- Runtime Detection list shows unique id/time/context for repeated events.
- Selecting a repeated event makes it clear which event was loaded.
- Infra noise can be hidden or filtered.
- Event detail and AI report still work for stored TASK-06 style manifest snapshot events when reachable.

## Image/version note

Current deployed image remains `docker.io/leeon3345/compliance-ai-server:0.1.13`.

If TASK-08 changes AI server code or frontend assets, build/push/deploy:

```text
docker.io/leeon3345/compliance-ai-server:0.1.14
```
