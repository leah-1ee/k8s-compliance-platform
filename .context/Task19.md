# TASK-19: Final Operations Readiness and Remaining Security Work

## Current State

Recent work added account deletion, admin Grafana links, Q&A documentation hardening, runtime event burst visibility, and admin cluster activation controls.

Latest pushed commits:

- `d12e9d0 Add account deletion and admin observability safeguards`
- `afb2f0a Fix admin cluster activation controls`

## UI Notes

### Account Deletion Button

The `회원 탈퇴` button is in the main `/ui` top bar, inside the auth action area.

Expected location:

- Logged-in state only
- Right side of the top navigation
- Immediately before `로그아웃`

Relevant files:

- `ai-observability/ai-server/app/static/index.html`
- `ai-observability/ai-server/app/static/app.js`
- `ai-observability/ai-server/app/static/styles.css`

If the button is not visible on VM:

- Pull `origin/ai-observability-leeon`
- Restart or redeploy the AI server
- Hard refresh browser cache
- Confirm `/me` returns `authenticated: true`

## VM Apply Checklist

```bash
cd ~/vscode/k8s-compliance-platform
git pull --ff-only origin ai-observability-leeon
```

For local uvicorn:

```bash
env DEV_AUTH_ENABLED=true DEV_AUTH_EMAIL=demo@school.test \
  .venv/bin/python -m uvicorn app.main:app \
  --app-dir ai-observability/ai-server \
  --host 127.0.0.1 \
  --port 8004
```

For Kubernetes image-based deployment, rebuild and redeploy the AI server image because FastAPI endpoints and static assets changed.

Grafana dashboard-only updates do not require rebuilding the AI server image, but do require applying the ConfigMap and restarting Grafana:

```bash
kubectl -n monitoring apply -f runtime-detection/manifests/grafana/dashboard-configmap.yaml
kubectl -n monitoring rollout restart deployment/grafana deployment/monitoring-grafana
```

## Remaining Work

### 1. RBAC and Authorization

KubeOwl still needs explicit platform roles.

Recommended roles:

- Viewer: can view dashboards, docs, reports, and runtime events
- Operator: can generate policies and run dry-run checks
- Security Admin: can apply cluster-wide Gatekeeper policies and manage clusters

Implementation direction:

- Add user role field or IdP group mapping
- Gate write endpoints by role
- Separate read-only report access from policy apply access
- Map KubeOwl roles to Kubernetes RBAC where possible

### 2. Platform Audit Trail

KubeOwl needs an audit log for its own write actions.

Track:

- Policy generation
- Policy apply / dry-run
- Cluster enable / disable / delete / restore
- Token rotation
- User account deletion / restore
- Admin Grafana access issuance

Recommended fields:

- actor user id
- actor email
- action
- target type
- target id
- before/after hash
- request id
- timestamp
- result

### 3. Policy Conflict Detection

Current Gatekeeper behavior is "all matching constraints are evaluated; deny wins if any deny constraint fails." KubeOwl still needs pre-deploy conflict detection.

Implementation direction:

- Maintain a policy registry
- Compare new policy target resource, namespace selector, label selector, and constrained fields
- Detect obvious allow/deny overlaps
- Run server-side dry-run or `gator test`
- Show conflict warnings before apply

### 4. System Namespace and Blast Radius Guard

Policies that block root, privileged containers, hostPath, or low ports can break system components.

Implementation direction:

- Default exclusion list for `kube-system`, `gatekeeper-system`, `monitoring`, CNI, storage, ingress
- Require confirmation when system namespaces are included
- Prefer `dryrun` or `warn` before `deny`
- Record exception reason

### 5. Compliance Mapping

The product name implies compliance coverage, but formal control mapping is still incomplete.

Implementation direction:

- Build a control catalog for CIS Kubernetes Benchmark, ISMS-P, and selected NIST controls
- Add control id, severity, evidence source, and remediation guide to policies
- Show violated controls in reports and docs

### 6. LLM Data Privacy

LLM calls must not become an infrastructure data leak.

Implementation direction:

- Add redaction before LLM requests
- Mask namespace, internal IP, secret-like values, env values, and private registry names
- Add private LLM endpoint support
- Add LLM-off deterministic mode for air-gap or sensitive environments

### 7. Prompt Injection Guardrails

Policy Generator should defend against jailbreak-style input.

Implementation direction:

- Classify destructive policy intent
- Add allowlist of supported policy families
- Require human approval for dangerous changes
- Run schema and Rego validation before display/apply
- Never let LLM output bypass backend validation

### 8. Secret Management

Avoid long-lived admin kubeconfig or broad cluster tokens.

Implementation direction:

- Use short-lived credentials where possible
- Store sensitive credentials in Kubernetes Secret, Vault, or cloud KMS
- Use least-privilege ServiceAccount for policy apply
- Rotate cluster ingest tokens
- Do not expose raw token values after initial creation

### 9. Grafana Alert Rules

The dashboard now surfaces event bursts, but alerting rules still need to be wired.

Recommended alerts:

- Runtime event burst by cluster
- HMAC failures
- Rate limit spikes
- Cluster last-seen delay
- Gatekeeper audit delay
- AI classifier error/fallback spike

### 10. Final Demo Smoke Test

Before the final presentation:

- `/ui` logged-out landing
- 개발 로그인 or Google login
- `회원 탈퇴` button visible when logged in
- Account deletion modal requires email confirmation
- `/admin` admin token works
- Disabled cluster shows `활성화`
- Admin Grafana links open
- Runtime Detection dashboard has `Event Burst 5m by Cluster`
- `/docs` Q&A list scrolls and does not show `Professor Questions`

## Verification Commands

```bash
perl -0ne 'while (m{<script>(.*?)</script>}sg) { print $1 }' ai-observability/ai-server/app/static/admin.html > /private/tmp/kubeowl-admin-inline.js
node --check /private/tmp/kubeowl-admin-inline.js
perl -0ne 'while (m{<script>(.*?)</script>}sg) { print $1 }' ai-observability/ai-server/app/static/docs.html > /private/tmp/kubeowl-docs-inline.js
node --check /private/tmp/kubeowl-docs-inline.js
node --check ai-observability/ai-server/app/static/app.js
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```
