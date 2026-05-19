# PodSight AI — Technical Report
## Real-Time Pod Resource Discovery and Dependency Mapping with Multi-Agent AI

---

## 1. Executive Summary

PodSight AI is a containerized intelligence platform that provides real-time visibility into Kubernetes pod behavior across all namespaces. The system employs a multi-agent AI framework to analyze CPU, memory, storage, network, and security metrics simultaneously, correlating data across pods to surface dependencies, anomalies, and actionable recommendations.

The platform runs on Minikube, MicroK8s, K3s, and any standard Kubernetes cluster, and includes an AI-powered security module mapped to the MITRE ATT&CK for Containers framework.

---

## 2. Architecture

### 2.1 System Components

```
┌─────────────────────────────────────────────────────────────┐
│                      PodSight AI                            │
│                                                             │
│  ┌──────────────┐    ┌────────────────────────────────┐    │
│  │   Dashboard  │◄───│         Flask REST API          │    │
│  │  (HTML/JS)   │    │         server.py               │    │
│  └──────────────┘    └────────┬───────────────────────┘    │
│                               │                             │
│              ┌────────────────┼──────────────────┐          │
│              │                │                  │          │
│     ┌────────▼──────┐  ┌─────▼──────┐  ┌───────▼──────┐  │
│     │   Collector   │  │  Multi     │  │  Security    │  │
│     │  backend/     │  │  Agent AI  │  │  Agent       │  │
│     │  collector.py │  │  agents/   │  │  agents/     │  │
│     └────────┬──────┘  └─────┬──────┘  └───────┬──────┘  │
│              │                │                  │          │
│     ┌────────▼──────────────────────────────────▼──────┐  │
│     │          Kubernetes API / kubectl top             │  │
│     │          CoreV1Api, MetricsAPI, RBAC              │  │
│     └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Data Flow

1. **Collection** (every 5s): `PodMetricsCollector` queries Kubernetes API for pod states, resource usage (via metrics-server or kubectl top), PVC operations, and restart counts. In demo mode, realistic synthetic data simulates 20 pods across 6 namespaces.

2. **Anomaly Detection** (every 5s): Rule-based engine flags CPU spikes (>80%), memory leaks (>85%), crash loops (>3 restarts), and pod failures.

3. **AI Analysis** (every 30s): Four specialist agents analyze top-offending pods and generate risk assessments, root-cause analyses, and kubectl remediation commands. When an Anthropic API key is present, Claude generates natural-language insights; otherwise the rule engine provides deterministic outputs.

4. **Security Scanning** (every 15s): Security agent evaluates all pods against 9 threat categories, maps findings to MITRE ATT&CK for Containers technique IDs, calculates CVSS scores, and produces a cluster risk score (0–100).

5. **Visualization**: Dashboard polls all API endpoints every 5 seconds and renders live charts, the dependency graph, anomaly feed, and security threat feed.

---

## 3. Multi-Agent AI Framework

### Agent Specializations

| Agent | Focus | Key Metrics | Output |
|-------|-------|-------------|--------|
| CPU Agent | Performance & scheduling | cpu%, trends, burst patterns | Risk level, kubectl top/scale commands |
| Memory Agent | Leak detection, OOM | memory%, restart correlation | Limit recommendations, OOMKill detection |
| Storage Agent | PVC I/O, disk saturation | disk%, pvc_ops | StorageClass advice, PVC expansion |
| Network Agent | Traffic patterns, fan-out | net_rx, net_tx per pod | NetworkPolicy recommendations |
| Security Agent | Threats, misconfigurations | All metrics + config | MITRE-mapped findings, CVSS, remediations |

### AI Integration (Claude API)

When `ANTHROPIC_API_KEY` is set, each agent sends the top-5 most concerning pods to `claude-sonnet-4-20250514` with a specialist system prompt. The model returns structured JSON containing `risk`, `analysis`, and `recommendations`. The security agent additionally requests `ai_insight` enrichment for critical threats, describing attack chains and blast radius.

Fallback to rule-based mode is seamless — all charts, anomaly detection, and security scanning function identically without the API key.

---

## 4. Security Module — MITRE ATT&CK Mapping

### Detected Threat Categories

| Threat Type | MITRE ID | Detection Method |
|-------------|----------|-----------------|
| Privilege Escalation | T1611 | `securityContext.privileged: true` |
| Crypto Mining | T1496 | CPU >85% + high tx + low rx pattern |
| Suspicious Process | T1059 | Command pattern matching (curl, wget, nc) |
| Lateral Movement | T1210 | Non-system pod connecting to kube-apiserver |
| Data Exfiltration | T1041 | High outbound to unknown external IPs |
| Container Escape | T1611 | Repeated crash/restart cycles |
| Secret Exposure | T1552 | Plaintext credentials in env vars |
| Image Vulnerability | T1190 | CVE database correlation (Trivy integration) |
| Anomalous Network | T1071 | C2 communication patterns |

### Cluster Risk Score Algorithm

```
pod_score = 100
for each threat affecting pod:
    pod_score -= weight[severity]  # critical=25, high=15, medium=8, low=3
pod_score = clamp(pod_score, 0, 100)
cluster_score = mean(all pod_scores)
```

---

## 5. Dependency Mapping

The dependency graph is built from two sources:
- **Static topology**: declared service dependencies from deployment manifests
- **Dynamic inference**: pods communicating via service mesh or direct TCP connections

The interactive canvas renders nodes where:
- **Size** represents memory usage (larger = higher memory)
- **Color** represents CPU health (green < 60%, yellow 60–80%, red > 80%)
- **Edges** represent service call dependencies with directional arrows
- **Drag-and-drop** allows manual layout adjustment for presentation

---

## 6. Technology Stack

| Component | Technology |
|-----------|------------|
| Backend API | Python 3.11, Flask 3.0, flask-cors |
| Kubernetes client | kubernetes-python 30.x |
| AI analysis | Anthropic Claude API (claude-sonnet-4) |
| Frontend | Vanilla JS, Chart.js 4.4, HTML5 Canvas |
| Container | Docker, python:3.11-slim base |
| Orchestration | Kubernetes (Minikube / K3s / MicroK8s) |
| RBAC | ClusterRole (read-only: pods, nodes, metrics) |

---

## 7. Deployment

### Local Demo (no Kubernetes)
```bash
pip install flask flask-cors requests
python3 server.py
# Open dashboard/index.html
```

### Kubernetes Deployment
```bash
minikube start --memory=4096 --cpus=2
eval $(minikube docker-env)
docker build -t podsight-ai:latest .
kubectl apply -f k8s/deployment.yaml
kubectl port-forward svc/podsight-backend 5000:5000 -n podsight
```

### With AI Analysis
```bash
export ANTHROPIC_API_KEY="sk-ant-your-key"
python3 server.py
```

---

## 8. Key Features Delivered

- **Real-time resource discovery** across CPU, RAM, disk, network, PVC for all pods
- **Multi-agent AI analysis** with specialist agents per resource domain
- **Interdependency mapping** with interactive drag-and-drop canvas
- **Security scanning** with MITRE ATT&CK mapping and CVSS scoring
- **Anomaly detection** for spikes, leaks, crash loops, and pod failures
- **Intelligent recommendations** with copy-ready kubectl commands
- **Rich dashboard** with 7 tabs: Overview, Pod Explorer, Anomalies, AI Agents, Dependency Map, Security, Recommendations
- **Demo mode** for presentation without Kubernetes infrastructure

---

## 9. Impact

PodSight AI addresses a critical operational gap: no existing open-source tool provides unified, real-time, AI-driven correlation of CPU, memory, storage, network, and security metrics in single-node Kubernetes environments. The platform enables:

- Engineers to instantly identify which pod is causing CPU spikes or memory leaks
- Platform operators to understand how services influence each other's resource consumption
- Security teams to detect container compromise patterns in real time, mapped to industry-standard attack frameworks
- Organizations to optimize workloads before failures occur, reducing downtime and improving reliability
