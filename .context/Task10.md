# TASK-10: Policy Apply Flow and Demo Hardening

## Goal

Finish the product-critical flow that connects generated policies to the live cluster: Policy Generator output must be safely applicable to a registered cluster, the dashboard must reflect live Gatekeeper constraints, and the demo path must prove policy generation, violation detection, AI analysis, reporting, and Grafana observability work together.

## Completed locally

- Renamed visible UI brand text and accessibility labels from `ComplianceOps` to `KubeOwl`.
- Replaced the previous `CO` brand mark with `/static/assets/kubeowl-logo.png`.
- Kept the existing vanilla HTML/CSS/JavaScript stack; no frontend frameworks or external libraries were added.
- Kept the pre-login behavior:
  - landing page uses top-navigation layout
  - Grafana button remains hidden while logged out
  - `공개 Policy Generator 열기` opens the public Policy Generator view
  - Falco rich hover card keeps the replaceable screenshot placeholder at `./assets/screenshot-falco.png`
- Swapped Grafana and Slack icons to CSS data-URL icon classes.
- Replaced hard-coded dashboard metrics with `/dashboard-summary`:
  - Active Policies: live Gatekeeper constraint count from Kubernetes API discovery
  - Recent Violations: stored user events in the last 24 hours
  - Runtime Events: total stored user events
  - Last Sync: latest cluster `last_seen_at`
- Clarified the `Active Policies` metric:
  - It counts live Gatekeeper `constraints.gatekeeper.sh/v1beta1` objects in the connected cluster.
  - Policy Generator output does not increment this number until the generated manifest is actually applied to the cluster.
  - Kubernetes `NetworkPolicy` and Gatekeeper mutation `Assign` resources may be applied by the platform, but they should be labeled separately because they are not validation constraints.
- Added user cluster trash/restore flow:
  - `DELETE /api/clusters/{cluster_id}` moves an owned cluster to `status=deleted`
  - `POST /api/clusters/{cluster_id}/restore` restores it as `status=disabled`
  - Cluster Setup UI has a `휴지통 보기` toggle and restore action
- Updated deploy manifests to reference `docker.io/leeon3345/compliance-ai-server:0.1.15`.

## Next session focus

Start here in a new Codex window. The branding/Grafana recovery work is already done; do not spend the next session redesigning the landing page or Grafana dashboards unless a blocker appears.

### P0: Policy Generator cluster apply flow

Implement first. This is the main missing product link.

The current Policy Generator creates YAML but does not yet apply it to a registered user cluster. This leaves the live `Active Policies` metric at `0` unless policies are manually applied with `kubectl`.

Suggested implementation shape:

1. Backend API:
   - Add an authenticated endpoint that applies a generated manifest to one owned cluster.
   - Reject logged-out requests.
   - Reject clusters not owned by the current user.
   - Reject deleted/disabled clusters.
   - Run server-side dry-run validation before applying.
   - Apply multi-document YAML in safe order: `ConstraintTemplate`, then Gatekeeper `Constraint`, then mutation `Assign` or Kubernetes `NetworkPolicy`.
   - Return structured per-resource results: kind, name, namespace, dry-run status, apply status, error.
2. Storage:
   - Store minimal apply history: user id, cluster id, policy type/name, manifest hash, status, error, created_at.
3. Frontend:
   - Keep public policy generation available.
   - Show `클러스터에 적용` only after login.
   - Let the user choose one of their active registered clusters.
   - Confirm before apply.
   - Show dry-run/apply results clearly.
   - Refresh `/dashboard-summary` after success.
4. Tests:
   - Unauthenticated apply returns `401`.
   - User cannot apply to another user's cluster.
   - Deleted/disabled cluster is rejected.
   - Multi-document YAML is ordered correctly.
   - Dry-run failure prevents real apply.
   - Successful Gatekeeper constraint apply is recorded.

Implementation note: if direct remote cluster Kubernetes API access is not currently available from the AI server, implement the UI/API contract and apply history first, then return a clear `not_configured` state with copyable `kubectl apply` fallback commands. Do not fake success.

UI copy should avoid implying all generated policies count as `Active Policies`; use wording such as `적용된 Gatekeeper 정책` or `Live Gatekeeper constraints`.

### P0: Demo scenario hardening

Verify and document one end-to-end evaluator path:

1. Generate a Gatekeeper validation policy.
2. Apply it to the selected cluster, or use the documented fallback command if API-side apply is not configured.
3. Trigger a known policy violation.
4. Confirm the violation or runtime event appears in the UI.
5. Open Violation Detail and confirm context cards are readable.
6. Generate AI Report and download PDF.
7. Open Grafana:
   - `Compliance Overview`
   - `Runtime Detection - Compliance Dashboard`
8. Confirm panels are either populated or intentionally display zero instead of confusing `No data` for missing series.

## Acceptance criteria

- `Active Policies` no longer looks disconnected from Policy Generator usage.
- Applying a generated Gatekeeper constraint can be demonstrated end to end, or the UI honestly explains why API-side apply is not configured and gives a safe fallback command.
- No generated policy is silently treated as applied.
- NetworkPolicy and Gatekeeper mutation policies are labeled distinctly from Gatekeeper validation constraints.
- Tests pass with:

```bash
node --check ai-observability/ai-server/app/static/app.js
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```

## Validation

Run from project root:

```bash
node --check ai-observability/ai-server/app/static/app.js
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```

Latest local result:

```text
57 passed, 50 warnings
```

## Image

Prepared image tag:

```text
docker.io/leeon3345/compliance-ai-server:0.1.15
```

Build/push command from project root:

```bash
docker buildx build \
  --platform linux/amd64 \
  -t docker.io/leeon3345/compliance-ai-server:0.1.15 \
  --push \
  ai-observability/ai-server
```

## VM rollout commands

Run on the VM/kubernetes admin host:

```bash
kubectl set image deploy/ai-classifier -n compliance-system \
  ai-classifier=docker.io/leeon3345/compliance-ai-server:0.1.15

kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s

kubectl get pods -n compliance-system -l app=ai-classifier
```

Optional smoke check:

```bash
kubectl logs deploy/ai-classifier -n compliance-system --tail=80
```
