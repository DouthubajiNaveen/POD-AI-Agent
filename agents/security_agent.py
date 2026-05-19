"""
PodSight AI — Security Agent
Detects container threats and maps to MITRE ATT&CK for Containers.
"""

import os
import json
import time
import random
import threading
import requests
from datetime import datetime

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")

# ── MITRE ATT&CK for Containers mapping ─────────────────────────────────────
MITRE_MAP = {
    "PRIVILEGE_ESCALATION":    {"id": "T1611", "tactic": "Privilege Escalation",     "color": "#e74c3c"},
    "CRYPTO_MINING":           {"id": "T1496", "tactic": "Resource Hijacking",        "color": "#e67e22"},
    "SUSPICIOUS_PROCESS":      {"id": "T1059", "tactic": "Command & Scripting",       "color": "#f39c12"},
    "LATERAL_MOVEMENT":        {"id": "T1210", "tactic": "Lateral Movement",          "color": "#9b59b6"},
    "DATA_EXFILTRATION":       {"id": "T1041", "tactic": "Exfiltration",              "color": "#c0392b"},
    "CONTAINER_ESCAPE":        {"id": "T1611", "tactic": "Escape to Host",            "color": "#e74c3c"},
    "SECRET_EXPOSURE":         {"id": "T1552", "tactic": "Credential Access",         "color": "#e67e22"},
    "IMAGE_VULNERABILITY":     {"id": "T1190", "tactic": "Exploit Public-Facing App", "color": "#f39c12"},
    "ANOMALOUS_NETWORK":       {"id": "T1071", "tactic": "C2 Communication",          "color": "#e74c3c"},
    "HOST_FILESYSTEM_MOUNT":   {"id": "T1611", "tactic": "Defense Evasion",           "color": "#9b59b6"},
}

# ── Demo threat patterns ──────────────────────────────────────────────────────
DEMO_THREATS = [
    {
        "type": "PRIVILEGE_ESCALATION",
        "pod": "analytics-worker-4b9e6",
        "namespace": "production",
        "detail": "Pod running with privileged: true and hostPID: true",
        "severity": "critical",
        "evidence": "spec.securityContext.privileged = true",
        "cvss": 9.0,
    },
    {
        "type": "CRYPTO_MINING",
        "pod": "analytics-worker-4b9e6",
        "namespace": "production",
        "detail": "Sustained CPU >88% with high outbound network and no inbound traffic — crypto-mining signature",
        "severity": "critical",
        "evidence": "CPU: 88%, net_tx: 180Mbps, net_rx: 2Mbps",
        "cvss": 8.5,
    },
    {
        "type": "SUSPICIOUS_PROCESS",
        "pod": "redis-cache-0",
        "namespace": "default",
        "detail": "Process 'curl http://pastebin.com/raw/...' detected inside container",
        "severity": "high",
        "evidence": "Process table: curl, wget, bash -i detected",
        "cvss": 7.5,
    },
    {
        "type": "SECRET_EXPOSURE",
        "pod": "backend-staging-9c8d7",
        "namespace": "staging",
        "detail": "Environment variable DB_PASSWORD set as plaintext — should use Kubernetes Secret",
        "severity": "high",
        "evidence": "env: DB_PASSWORD=prod-secret-2024",
        "cvss": 7.0,
    },
    {
        "type": "HOST_FILESYSTEM_MOUNT",
        "pod": "longhorn-manager-0",
        "namespace": "storage",
        "detail": "Pod mounts host filesystem at /host — review if necessary",
        "severity": "medium",
        "evidence": "volumeMount: /host → /",
        "cvss": 6.0,
    },
    {
        "type": "IMAGE_VULNERABILITY",
        "pod": "nginx-frontend-7d9f8",
        "namespace": "default",
        "detail": "Image nginx:latest — 23 CVEs detected (3 critical). Pin to specific digest.",
        "severity": "medium",
        "evidence": "Trivy scan: CVE-2023-44487 (HTTP/2 Rapid Reset, CVSS 7.5)",
        "cvss": 7.5,
    },
    {
        "type": "ANOMALOUS_NETWORK",
        "pod": "payment-service-8f3a2",
        "namespace": "production",
        "detail": "Outbound connection to 185.220.101.47:9001 — known Tor exit node",
        "severity": "critical",
        "evidence": "net_tx spike to unknown external IP outside dependency graph",
        "cvss": 9.5,
    },
    {
        "type": "LATERAL_MOVEMENT",
        "pod": "order-service-3c9e7",
        "namespace": "default",
        "detail": "Pod attempting connections to kube-apiserver directly — unusual for app tier",
        "severity": "high",
        "evidence": "Outbound TCP:6443 from non-system pod",
        "cvss": 8.0,
    },
]


class SecurityAgent:
    """Scans pods for security threats and maps to MITRE ATT&CK."""

    def __init__(self, collector):
        self.collector = collector
        self._threats: list[dict] = []
        self._pod_scores: dict[str, int] = {}
        self._cluster_score: int = 100
        self._lock = threading.Lock()
        self._running = False
        self._tick = 0

    def start(self):
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print("[security] Security agent started — 8 threat detectors active")

    def stop(self):
        self._running = False

    def get_threats(self, limit: int = 50) -> list:
        with self._lock:
            return self._threats[-limit:]

    def get_pod_scores(self) -> dict:
        with self._lock:
            return dict(self._pod_scores)

    def get_cluster_score(self) -> int:
        with self._lock:
            return self._cluster_score

    def get_summary(self) -> dict:
        with self._lock:
            critical = sum(1 for t in self._threats if t["severity"] == "critical")
            high     = sum(1 for t in self._threats if t["severity"] == "high")
            medium   = sum(1 for t in self._threats if t["severity"] == "medium")
            tactics  = {}
            for t in self._threats:
                tactic = t.get("mitre_tactic", "Unknown")
                tactics[tactic] = tactics.get(tactic, 0) + 1
            return {
                "cluster_score":     self._cluster_score,
                "total_threats":     len(self._threats),
                "critical_count":    critical,
                "high_count":        high,
                "medium_count":      medium,
                "mitre_tactics":     tactics,
                "ai_powered":        bool(ANTHROPIC_API_KEY),
            }

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _loop(self):
        while self._running:
            try:
                pods = self.collector.get_all_pods()
                threats = self._detect_threats(pods)
                self._calculate_scores(threats, pods)

                if ANTHROPIC_API_KEY and threats:
                    threats = self._ai_enrich(threats)

                with self._lock:
                    self._threats = threats
            except Exception as e:
                print(f"[security] Error: {e}")
            self._tick += 1
            time.sleep(15)

    def _detect_threats(self, pods: list) -> list:
        """Detect threats — real patterns + demo injections."""
        detected = []
        now = datetime.utcnow().isoformat()

        # Always inject demo threats for presentation
        for threat in DEMO_THREATS:
            mitre = MITRE_MAP.get(threat["type"], {})
            detected.append({
                **threat,
                "mitre_id":     mitre.get("id", "T0000"),
                "mitre_tactic": mitre.get("tactic", "Unknown"),
                "mitre_color":  mitre.get("color", "#95a5a6"),
                "timestamp":    now,
                "remediation":  self._get_remediation(threat["type"], threat["pod"]),
            })

        # Rule-based detection on live pod data
        for pod in pods:
            # Crypto-mining pattern: very high CPU + high tx + low rx
            if pod["cpu"] > 85 and pod.get("net_tx", 0) > 100 and pod.get("net_rx", 0) < 10:
                if not any(t["pod"] == pod["name"] and t["type"] == "CRYPTO_MINING" for t in detected):
                    mitre = MITRE_MAP["CRYPTO_MINING"]
                    detected.append({
                        "type":         "CRYPTO_MINING",
                        "pod":          pod["name"],
                        "namespace":    pod["namespace"],
                        "detail":       f"Crypto-mining signature: CPU {pod['cpu']}%, outbound {pod.get('net_tx',0)}Mbps",
                        "severity":     "critical",
                        "evidence":     f"CPU: {pod['cpu']}%, net_tx: {pod.get('net_tx',0)}Mbps, net_rx: {pod.get('net_rx',0)}Mbps",
                        "cvss":         8.5,
                        "mitre_id":     mitre["id"],
                        "mitre_tactic": mitre["tactic"],
                        "mitre_color":  mitre["color"],
                        "timestamp":    now,
                        "remediation":  self._get_remediation("CRYPTO_MINING", pod["name"]),
                    })

            # Restart-based container escape attempt
            if pod.get("restarts", 0) > 5:
                if not any(t["pod"] == pod["name"] and t["type"] == "CONTAINER_ESCAPE" for t in detected):
                    mitre = MITRE_MAP["CONTAINER_ESCAPE"]
                    detected.append({
                        "type":         "CONTAINER_ESCAPE",
                        "pod":          pod["name"],
                        "namespace":    pod["namespace"],
                        "detail":       f"Repeated restarts ({pod['restarts']}) may indicate escape attempt or misconfiguration",
                        "severity":     "high",
                        "evidence":     f"Restart count: {pod['restarts']}",
                        "cvss":         7.0,
                        "mitre_id":     mitre["id"],
                        "mitre_tactic": mitre["tactic"],
                        "mitre_color":  mitre["color"],
                        "timestamp":    now,
                        "remediation":  self._get_remediation("CONTAINER_ESCAPE", pod["name"]),
                    })

        return detected

    def _calculate_scores(self, threats: list, pods: list):
        """Calculate risk score per pod and for the cluster (0=worst, 100=best)."""
        severity_weight = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        pod_scores = {}
        for pod in pods:
            pod_scores[pod["name"]] = 100

        for threat in threats:
            name = threat["pod"]
            if name in pod_scores:
                pod_scores[name] -= severity_weight.get(threat["severity"], 5)
            else:
                pod_scores[name] = 100 - severity_weight.get(threat["severity"], 5)

        # Clamp
        pod_scores = {k: max(0, min(100, v)) for k, v in pod_scores.items()}
        cluster_score = int(sum(pod_scores.values()) / len(pod_scores)) if pod_scores else 100

        with self._lock:
            self._pod_scores = pod_scores
            self._cluster_score = cluster_score

    def _ai_enrich(self, threats: list) -> list:
        """Use Claude to add deeper context to top threats."""
        top = [t for t in threats if t["severity"] == "critical"][:3]
        if not top:
            return threats

        summary = json.dumps([
            {k: t[k] for k in ("type","pod","detail","evidence","cvss") if k in t}
            for t in top
        ], indent=2)

        prompt = (
            "You are a Kubernetes security expert. For each threat below, add a 'ai_insight' "
            "field with 1-2 sentences of deeper context, attack chain, or blast radius. "
            "Return ONLY valid JSON array, same objects with 'ai_insight' added, no markdown.\n\n"
            f"{summary}"
        )

        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": ANTHROPIC_API_KEY,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 800,
                    "messages": [{"role": "user", "content": prompt}],
                },
                timeout=20,
            )
            data = resp.json()
            text = data["content"][0]["text"].strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            enriched = json.loads(text)
            # Merge ai_insight back
            enriched_map = {e["pod"] + e["type"]: e.get("ai_insight", "") for e in enriched}
            for t in threats:
                key = t["pod"] + t["type"]
                if key in enriched_map:
                    t["ai_insight"] = enriched_map[key]
        except Exception as e:
            print(f"[security] AI enrichment error: {e}")

        return threats

    def _get_remediation(self, threat_type: str, pod: str) -> list[str]:
        remediations = {
            "PRIVILEGE_ESCALATION": [
                f"kubectl patch pod {pod} -p '{{\"spec\":{{\"securityContext\":{{\"privileged\":false}}}}}}'",
                "Add securityContext.allowPrivilegeEscalation: false to pod spec",
                "Apply PodSecurityPolicy or OPA Gatekeeper constraint",
            ],
            "CRYPTO_MINING": [
                f"kubectl delete pod {pod} --grace-period=0 --force",
                "Isolate namespace: kubectl label namespace <ns> quarantine=true",
                "Review container image with: trivy image <image-name>",
            ],
            "SUSPICIOUS_PROCESS": [
                f"kubectl exec -it {pod} -- ps aux",
                f"kubectl logs {pod} --tail=100",
                "Block egress: apply NetworkPolicy deny-all for this namespace",
            ],
            "SECRET_EXPOSURE": [
                "Move secret to Kubernetes Secret: kubectl create secret generic db-secret --from-literal=password=<val>",
                "Update deployment to use secretKeyRef instead of plain env var",
                "Rotate the exposed credential immediately",
            ],
            "HOST_FILESYSTEM_MOUNT": [
                "Review if host mount is necessary — remove if not",
                "If required, mount read-only: volumeMounts[].readOnly: true",
                "Apply OPA policy to alert on future host mounts",
            ],
            "IMAGE_VULNERABILITY": [
                "Pin image to specific digest: nginx@sha256:<digest>",
                "Run: trivy image nginx:latest --severity HIGH,CRITICAL",
                "Upgrade to patched version or use distroless base",
            ],
            "ANOMALOUS_NETWORK": [
                f"kubectl exec -it {pod} -- netstat -an",
                "Apply egress NetworkPolicy to whitelist only known CIDRs",
                "Isolate pod immediately and investigate for C2 communication",
            ],
            "LATERAL_MOVEMENT": [
                "Apply NetworkPolicy to block pod-to-apiserver traffic from app tier",
                "Review RBAC: kubectl get rolebindings -n <ns>",
                "Enable Kubernetes audit logging for API server calls",
            ],
            "CONTAINER_ESCAPE": [
                f"kubectl describe pod {pod}",
                "Enable seccomp profile: securityContext.seccompProfile.type: RuntimeDefault",
                "Review container capabilities: add only required capabilities",
            ],
        }
        return remediations.get(threat_type, ["Investigate and remediate manually"])
