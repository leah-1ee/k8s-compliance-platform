# TASK-11: VM Rollout, Grafana Dashboard Naming, and Demo Verification

## Goal

Finish the next deployment and verification pass after TASK-10 policy apply flow work. The focus is not a new redesign: deploy the current AI server/UI changes, apply provisioned Grafana dashboard title updates, verify `Active Policies` against live Gatekeeper constraints, and close the evaluator demo path.

## Current state

- Latest local commits before this handoff:
  - `71ae50a fix(ai-server): polish setup and notification layout`
  - `5252665 fix(ai-server): clarify policy fallback guidance`
  - `e4bd9f5 fix(ai-server): revised fallback format`
  - `827aeab feat(ai-server): add policy apply flow`
- Current VM deployment observed by user:
  - `deploy/ai-classifier -n compliance-system`
  - ServiceAccount: `ai-classifier`
  - Image: `docker.io/leeon3345/compliance-ai-server:0.1.17`
- Next AI server image target:
  - `docker.io/leeon3345/compliance-ai-server:0.1.18`
- Latest local validation:
  - `node --check ai-observability/ai-server/app/static/app.js`
  - `.venv/bin/python -m pytest ai-observability/ai-server/tests/`
  - Result: `62 passed, 56 warnings`

## Completed locally after TASK-10

- Policy apply flow was implemented and committed:
  - Authenticated `POST /api/clusters/{cluster_id}/policy-applies`
  - User ownership and active cluster checks
  - Multi-document policy ordering: `ConstraintTemplate`, Gatekeeper `Constraint`, then mutation/`NetworkPolicy`
  - Minimal apply history persistence
  - Honest `not_configured` fallback when server-side cluster apply is not configured
- Fallback command generation was fixed:
  - `ConstraintTemplate` and `Constraint` are split into separate heredocs
  - CRD `Established` wait is inserted between template and constraint apply
  - Fallback now includes permission checks, admin RBAC guidance, dry-run, and apply commands
- UI was polished:
  - Policy apply status uses pill-like state badge styling
  - Policy apply guidance is compact and less visually noisy
  - Cluster Setup / Sidekick install area has a cleaner card + terminal command block layout
  - Slack per-cluster notification copy and empty state spacing were tightened
  - EnforcementAction badge selected state is more visible
  - Dashboard tab now explains Grafana observability cards instead of raw PromQL snippets
- Grafana dashboard titles were renamed locally:
  - `Compliance Overview` -> `Gatekeeper Compliance Overview`
  - `Runtime Detection — Compliance Dashboard` -> `Runtime Detection`
  - UI card labels were aligned with those names

## P0: Deploy current image and ConfigMaps

Build/push AI server image:

```bash
docker buildx build \
  --platform linux/amd64 \
  -t docker.io/leeon3345/compliance-ai-server:0.1.18 \
  --push \
  ai-observability/ai-server
```

Roll out on VM:

```bash
kubectl set image deploy/ai-classifier -n compliance-system \
  ai-classifier=docker.io/leeon3345/compliance-ai-server:0.1.18

kubectl rollout status deploy/ai-classifier -n compliance-system --timeout=180s

kubectl get pods -n compliance-system -l app=ai-classifier
kubectl logs deploy/ai-classifier -n compliance-system --tail=80
```

Apply provisioned Grafana dashboards:

```bash
kubectl apply -f ai-observability/dashboards/grafana/compliance-overview-configmap.yaml
kubectl apply -f runtime-detection/manifests/grafana/dashboard-configmap.yaml
```

If Grafana does not refresh the provisioned dashboards, restart Grafana:

```bash
kubectl get deploy -n monitoring | grep grafana
kubectl rollout restart deploy/<grafana-deploy-name> -n monitoring
```

## P0: Fix/verify Active Policies count

`Active Policies` counts live Gatekeeper `constraints.gatekeeper.sh/v1beta1` objects from the cluster visible to the AI server pod.

Important: the deployment uses the `ai-classifier` ServiceAccount, not `default`.

Check:

```bash
kubectl get deploy ai-classifier -n compliance-system \
  -o jsonpath='{.spec.template.spec.serviceAccountName}{"\n"}{.spec.template.spec.containers[0].image}{"\n"}'

kubectl auth can-i list k8srequirenonroot.constraints.gatekeeper.sh \
  --as=system:serviceaccount:compliance-system:ai-classifier
```

If it is not `yes`, apply read-only Gatekeeper constraint RBAC:

```bash
kubectl apply -f - <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubeowl-gatekeeper-constraint-reader
rules:
  - apiGroups:
      - constraints.gatekeeper.sh
    resources:
      - "*"
    verbs:
      - get
      - list
      - watch
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubeowl-gatekeeper-constraint-reader
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: kubeowl-gatekeeper-constraint-reader
subjects:
  - kind: ServiceAccount
    name: ai-classifier
    namespace: compliance-system
EOF
```

Then restart the AI server deployment and refresh the UI.

## P0: Demo verification path

1. Login through dev-login or Google OAuth if live credentials exist.
2. Register/choose `school-cloud` cluster in Cluster Setup.
3. Generate a Gatekeeper validation policy from Policy Generator.
4. Apply with server-side flow if configured, otherwise use fallback commands in the selected cluster context.
5. Confirm the constraint exists:

```bash
kubectl get constrainttemplates
kubectl get constraints
kubectl get <constraint-kind>.constraints.gatekeeper.sh
```

6. Confirm `Active Policies` increases or shows a useful `active_policies_error`.
7. Trigger or inspect a known violation.
8. Confirm Runtime Detection event appears.
9. Open Violation Detail and verify context/readability.
10. Generate AI Report and download PDF.
11. Open Grafana and verify:
    - `Gatekeeper Compliance Overview`
    - `Runtime Detection`
    - Any remaining `Grafana Overview` dashboard is understood as external/default or cleaned up if not wanted.

## P1: Follow-up cleanup

- Decide what to do with the `Grafana Overview` dashboard visible in Grafana. It is not currently managed by the repo files changed in this task.
- Document user-cluster RBAC expectations clearly:
  - fallback apply requires the user's kubeconfig account to have Gatekeeper/NetworkPolicy apply permissions
  - central `Active Policies` for arbitrary user clusters needs a future agent/read-only connection model
- Stabilize zrok for demo:
  - zrok `502` can happen during longer policy apply requests
  - keep VM logs and rollout status commands handy during smoke tests
- Keep dashboard JSON/ConfigMap as source of truth; avoid editing provisioned dashboards in the Grafana UI.

## Validation

Run from project root:

```bash
node --check ai-observability/ai-server/app/static/app.js
.venv/bin/python -m pytest ai-observability/ai-server/tests/
python3 -m json.tool ai-observability/dashboards/grafana/compliance-overview-classic.json >/tmp/compliance-classic.json
python3 -m json.tool ai-observability/dashboards/grafana/compliance-overview.json >/tmp/compliance-v2.json
python3 -m json.tool runtime-detection/manifests/grafana/runtime-dashboard.json >/tmp/runtime-dashboard.json
```

