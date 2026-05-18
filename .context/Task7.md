# TASK-07: Policy/Falco Hygiene

## Status

Done locally.

No AI server code or UI files changed. No new AI server image tag is required.
VM Gatekeeper/Falco validation is left for the user to run on the target cluster.

## Current state

TASK-06 is complete locally and smoke-tested on the VM:
- `/ingest/falco-events` accepts `resource_manifest` snapshots from top-level payloads or nested `event.resource_manifest`.
- Runtime event detail and analysis use stored manifest snapshots through the owning user's cluster scope.
- Events without snapshots still fall back to TASK-05 kubectl guidance.
- Malformed scalar snapshots and snapshots over 200 KB degrade safely.
- Local tests: `53 passed, 41 warnings`.
- Deployed/smoke image: `docker.io/leeon3345/compliance-ai-server:0.1.13`.
- VM smoke used `school-cloud` demo cluster and verified `TASK-06 Manifest Snapshot Smoke`.
- Screenshot evidence is under `ai-observability/docs/ai-server-test/task6-manifest-snapshot/`.

## Important non-goals

Do not work on:
- Google Console setup
- `ai-google-oauth` secret creation
- fake or placeholder OAuth credentials
- production OAuth smoke testing
- admin cluster delete/archive controls
- SQLite replica/strategy changes
- broad UI redesign

Google OAuth live smoke remains intentionally deferred until the final task because real Google OAuth credentials do not exist yet.

## TASK-07 Goal

Clean up policy and Falco operational hygiene so the demo assets are easier to trust and maintain before treating them as stable ops assets.

Target behavior:
- Gatekeeper policy files duplicated between `cloud-deploy/policies` and `k8s-policy-engine` are compared and synchronized where appropriate.
- The source of truth for deployable constraints and mutations is decided and documented.
- Known drift is resolved or explicitly documented:
  - `cloud-deploy/policies` includes `local-path-storage` exclusions.
  - `cloud-deploy/policies` includes `docker.io/leeon3345/` allowed registry updates.
  - These updates are not fully mirrored in `k8s-policy-engine`.
- Falco rules are not expanded first; prefer validation/smoke-test documentation before adding more runtime rules.

## Completed changes

- Compared duplicated Gatekeeper policy files between `cloud-deploy/policies` and `k8s-policy-engine`.
- Synchronized demo-safe drift into `k8s-policy-engine`:
  - `local-path-storage` namespace exclusions
  - `falco` namespace exclusions for Falco/Falco Sidekick privileged host-level access
  - `docker.io/leeon3345/` allowed registry prefix
- Documented policy ownership:
  - `k8s-policy-engine/` is the development/validation source of truth.
  - `cloud-deploy/policies/` is the VM deployable copy.
  - Keep `templates/`, `constraints/`, and `mutations/` synchronized before deploy.
- Added Gatekeeper policy dry-run and allowed/denied image smoke commands.
- Added Falco validation/smoke notes without expanding Falco rules.

## Suggested implementation shape

1. Inventory policy files:
   - list files under `cloud-deploy/policies`
   - list comparable files under `k8s-policy-engine`
   - identify duplicated constraints, templates, and mutations

2. Compare drift:
   - registry allowlist differences
   - namespace exclusions such as `local-path-storage`
   - constraint names/kinds/API versions
   - deployability assumptions

3. Decide and document source of truth:
   - prefer one deployable policy tree as the operational source
   - document how the other tree should be synced or used
   - keep the explanation practical for future demo/ops work

4. Sync only the necessary policy drift:
   - avoid unrelated policy rewrites
   - preserve demo-safe exclusions that are already required
   - do not weaken policies beyond the known demo/runtime requirements

5. Add or update validation notes:
   - exact kubectl commands to apply/dry-run policies
   - exact smoke commands for allowed/disallowed image repos
   - Falco smoke validation commands if docs already have a natural place

## Likely files to inspect or touch

- `cloud-deploy/policies/**`
- `k8s-policy-engine/**`
- `runtime-detection/**` only for Falco validation docs, not broad rule expansion
- `ai-observability/docs/**` if policy/runtime smoke docs belong there
- `.context/CONTEXT.md`
- `.context/Task7.md`

Do not touch unless explicitly needed:
- Google OAuth manifests or secrets
- `app/static/index.html`
- AI server runtime code
- admin cleanup controls
- SQLite deployment strategy

## Test/validation commands

Server tests were not rerun because no AI server code changed. If future AI server code changes:

```bash
.venv/bin/python -m pytest ai-observability/ai-server/tests/
```

Policy tree drift check:

```bash
diff -rq -x README.md -x Makefile -x scripts -x tests -x helm -x .gitkeep \
  cloud-deploy/policies k8s-policy-engine
```

VM Gatekeeper dry-run:

```bash
kubectl apply --dry-run=server -f cloud-deploy/policies/templates/
kubectl apply --dry-run=server -f cloud-deploy/policies/constraints/
kubectl apply --dry-run=server -f cloud-deploy/policies/mutations/
```

Policy smoke:

```bash
kubectl run allowed-leeon-image \
  --image=docker.io/leeon3345/compliance-ai-server:0.1.13 \
  --restart=Never \
  --dry-run=server

kubectl run denied-latest-image \
  --image=nginx:latest \
  --restart=Never \
  --dry-run=server
```

Expected result: `allowed-leeon-image` is admitted; `denied-latest-image` is rejected by `block-latest-tag` or `allow-registries`.

Falco smoke:

```bash
sudo /usr/bin/falco -o engine.kind=modern_ebpf --dry-run
kubectl apply -f runtime-detection/manifests/falco-watchdog.yaml
kubectl port-forward -n compliance-system svc/response-server 5000:5000
curl -s localhost:5000/api/v1/falco/status
kubectl create namespace runtime-demo --dry-run=client -o yaml | kubectl apply -f -
kubectl run runtime-demo-target \
  -n runtime-demo \
  --image=docker.io/library/busybox:1.36 \
  --restart=Never \
  --command -- sh -c 'sleep 3600'
kubectl wait -n runtime-demo --for=condition=Ready pod/runtime-demo-target --timeout=90s
kubectl exec -n runtime-demo runtime-demo-target -- sh -lc 'whoami; id; cat /etc/passwd >/dev/null'
curl -s localhost:5000/api/v1/events/summary
```

## Handoff expectation

At the end of TASK-07:
- update `.context/CONTEXT.md`
- summarize which policy tree is the source of truth
- list exact local git commands
- list exact VM validation commands
- note whether a new AI server image tag is needed; if server/UI code is unchanged, no new AI server image should be required

## Local git commands

```bash
git status --short
git diff -- cloud-deploy/README.md \
  k8s-policy-engine/README.md \
  k8s-policy-engine/constraints \
  k8s-policy-engine/mutations \
  runtime-detection/README.md \
  .context/CONTEXT.md \
  .context/Task7.md
git add cloud-deploy/README.md \
  k8s-policy-engine/README.md \
  k8s-policy-engine/constraints \
  k8s-policy-engine/mutations \
  runtime-detection/README.md \
  .context/CONTEXT.md \
  .context/Task7.md
git commit -m "docs(policy): document Gatekeeper and Falco hygiene"
```
