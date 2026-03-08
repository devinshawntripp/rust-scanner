# Design: UI Deploy v1.14.6 + Grafana Fix + Scanner Verification

**Date:** 2026-03-08
**Status:** Approved

---

## Workstream 1: Deploy UI v1.14.6

### Goal
Deploy the new architecture docs page (committed to main) to the cluster.

### Steps
1. Build Docker image: `docker build --platform linux/amd64 -t devintripp/deltaguard-ui:v1.14.6 .`
2. Push to Docker Hub: `docker push devintripp/deltaguard-ui:v1.14.6`
3. Update `k8s/scanrook/deployment.yaml` image tag from `v1.14.5` → `v1.14.6`
4. Commit + push → ArgoCD auto-syncs

### Key Files
- `k8s/scanrook/deployment.yaml` (line 36: image tag)

---

## Workstream 2: Fix Grafana CrashLoopBackOff

### Root Cause
`grafana/grafana:11.5.2` with `imagePullPolicy: IfNotPresent` — the node cached a wrong-arch image. The container fails with `exec format error` (154 restarts).

### Fix
1. Change `imagePullPolicy` from `IfNotPresent` to `Always` in `k8s/scanrook/monitoring/grafana-deployment.yaml`
2. Also bump to latest stable `grafana/grafana:11.6.0` to get a fresh pull with correct multi-arch manifest
3. Commit + push → ArgoCD syncs → pod restarts with correct image

### Key Files
- `k8s/scanrook/monitoring/grafana-deployment.yaml` (line 193: image, line 194: imagePullPolicy)

---

## Workstream 3: Test Registry Scan (nginx:latest)

### Goal
Verify the dispatcher v6 init container fix works end-to-end.

### Steps
1. Submit registry scan via API: `POST /api/scan/from-registry` with `{image: "nginx:latest"}`
2. Monitor K8s Job creation and init container (registry-puller) execution
3. Verify scan completes with status `done`
4. Check SSE events stream correctly

---

## Workstream 4: Verify UI Features

### Goal
After v1.14.6 deploys, verify:
1. `/docs/architecture` renders with Mermaid diagrams
2. Dashboard expand row shows full tabbed view with SSE

---

## Execution Order
1. Grafana fix (commit) — immediate, independent
2. UI image build + push (takes ~5 min) — parallel with Grafana
3. Update deployment manifest + push — after image is ready
4. Registry scan test — after dispatcher v6 confirmed
5. UI verification — after ArgoCD syncs v1.14.6
