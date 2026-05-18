# TASK-10: KubeOwl Branding and 0.1.15 Image Handoff

## Goal

Rename the AI server UI brand from `ComplianceOps` to `KubeOwl`, use the uploaded owl/Kubernetes logo as the primary site mark, and prepare the next AI server image tag for VM rollout.

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
- Added user cluster trash/restore flow:
  - `DELETE /api/clusters/{cluster_id}` moves an owned cluster to `status=deleted`
  - `POST /api/clusters/{cluster_id}/restore` restores it as `status=disabled`
  - Cluster Setup UI has a `휴지통 보기` toggle and restore action
- Updated deploy manifests to reference `docker.io/leeon3345/compliance-ai-server:0.1.15`.

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
