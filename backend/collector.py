"""
PodSight AI — Backend Metrics Collector
Collects pod metrics, detects anomalies, maps dependencies.
Works in DEMO mode (no K8s needed) or LIVE mode (with kubectl/k8s API).
"""

import os
import time
import math
import random
import threading
import subprocess
import json
from datetime import datetime, timedelta
from collections import defaultdict, deque

# ── Try to import kubernetes client (optional) ──────────────────────────────
try:
    from kubernetes import client, config
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False

# ── Constants ────────────────────────────────────────────────────────────────
DEMO_MODE = os.environ.get("DEMO_MODE", "true").lower() != "false"
HISTORY_LEN = 60          # keep 60 data-points per metric (~5 min @ 5s interval)
ANOMALY_CPU_THRESHOLD = 80.0
ANOMALY_MEM_THRESHOLD = 85.0
ANOMALY_RESTART_THRESHOLD = 3

# ── Simulated namespace + pod topology ──────────────────────────────────────
DEMO_TOPOLOGY = [
    # (namespace, pod_name, service_type, deps)
    ("default",      "nginx-frontend-7d9f8",    "nginx",      ["api-gateway-6bc4d"]),
    ("default",      "api-gateway-6bc4d",        "node",       ["user-service-5a2b1","order-service-3c9e7"]),
    ("default",      "user-service-5a2b1",       "python",     ["postgres-primary-0","redis-cache-0"]),
    ("default",      "order-service-3c9e7",      "java",       ["postgres-primary-0","rabbitmq-0"]),
    ("default",      "postgres-primary-0",        "postgres",   []),
    ("default",      "redis-cache-0",             "redis",      []),
    ("default",      "rabbitmq-0",                "rabbitmq",   []),
    ("monitoring",   "prometheus-0",              "prometheus", []),
    ("monitoring",   "grafana-7b6c9",             "grafana",    ["prometheus-0"]),
    ("monitoring",   "alertmanager-0",            "alertmanager",["prometheus-0"]),
    ("kube-system",  "coredns-5d78c9",            "coredns",    []),
    ("kube-system",  "kube-proxy-xk2p9",          "kube-proxy", []),
    ("ingress",      "ingress-nginx-controller",  "nginx",      ["nginx-frontend-7d9f8"]),
    ("storage",      "longhorn-manager-0",        "longhorn",   []),
    ("storage",      "minio-0",                   "minio",      []),
    ("production",   "payment-service-8f3a2",     "go",         ["postgres-primary-0","redis-cache-0"]),
    ("production",   "notification-svc-2d7c1",    "node",       ["rabbitmq-0"]),
    ("production",   "analytics-worker-4b9e6",    "python",     ["redis-cache-0","minio-0"]),
    ("staging",      "frontend-staging-1a2b3",    "nginx",      []),
    ("staging",      "backend-staging-9c8d7",     "python",     ["postgres-primary-0"]),
]


class MetricsHistory:
    """Rolling window of the last N metric values for a pod."""
    def __init__(self):
        self.cpu    = deque(maxlen=HISTORY_LEN)
        self.memory = deque(maxlen=HISTORY_LEN)
        self.disk   = deque(maxlen=HISTORY_LEN)
        self.net_rx = deque(maxlen=HISTORY_LEN)
        self.net_tx = deque(maxlen=HISTORY_LEN)
        self.timestamps = deque(maxlen=HISTORY_LEN)


class PodMetricsCollector:
    """Core collector — runs as a background thread."""

    def __init__(self):
        self.pods: dict[str, dict] = {}          # pod_name → latest metrics dict
        self.history: dict[str, MetricsHistory] = {}
        self.anomalies: list[dict] = []          # last 200 anomaly events
        self.dependencies: dict[str, list] = {}  # pod_name → [pod_name, ...]
        self.namespaces: set[str] = set()
        self._lock = threading.Lock()
        self._running = False
        self._tick = 0                           # used for realistic wave patterns

        # Initialise demo topology
        for ns, name, svc, deps in DEMO_TOPOLOGY:
            self.dependencies[name] = deps
            self.namespaces.add(ns)
            self.history[name] = MetricsHistory()

        # Try to connect to real cluster
        self._k8s_core = None
        self._k8s_metrics = None
        if K8S_AVAILABLE and not DEMO_MODE:
            try:
                config.load_incluster_config()
                self._k8s_core = client.CoreV1Api()
                print("[collector] Running in LIVE Kubernetes mode")
            except Exception:
                try:
                    config.load_kube_config()
                    self._k8s_core = client.CoreV1Api()
                    print("[collector] Running in LIVE kubeconfig mode")
                except Exception:
                    print("[collector] K8s unavailable — falling back to DEMO mode")

    # ── Public interface ─────────────────────────────────────────────────────

    def start(self):
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print("[collector] Background collection started")

    def stop(self):
        self._running = False

    def get_all_pods(self) -> list:
        with self._lock:
            return list(self.pods.values())

    def get_pod(self, name: str) -> dict | None:
        with self._lock:
            return self.pods.get(name)

    def get_history(self, name: str) -> dict:
        with self._lock:
            h = self.history.get(name)
            if not h:
                return {}
            return {
                "timestamps": list(h.timestamps),
                "cpu":        list(h.cpu),
                "memory":     list(h.memory),
                "disk":       list(h.disk),
                "net_rx":     list(h.net_rx),
                "net_tx":     list(h.net_tx),
            }

    def get_anomalies(self, limit: int = 50) -> list:
        with self._lock:
            return self.anomalies[-limit:]

    def get_dependencies(self) -> dict:
        with self._lock:
            return dict(self.dependencies)

    def get_summary(self) -> dict:
        with self._lock:
            pods = list(self.pods.values())
            if not pods:
                return {}
            return {
                "total_pods":       len(pods),
                "namespaces":       list(self.namespaces),
                "namespace_count":  len(self.namespaces),
                "avg_cpu":          round(sum(p["cpu"] for p in pods) / len(pods), 1),
                "avg_memory":       round(sum(p["memory"] for p in pods) / len(pods), 1),
                "critical_pods":    [p["name"] for p in pods if p["cpu"] > ANOMALY_CPU_THRESHOLD
                                     or p["memory"] > ANOMALY_MEM_THRESHOLD],
                "anomaly_count":    len(self.anomalies),
                "total_restarts":   sum(p.get("restarts", 0) for p in pods),
                "healthy_pods":     sum(1 for p in pods if p["status"] == "Running"
                                     and p["cpu"] < ANOMALY_CPU_THRESHOLD
                                     and p["memory"] < ANOMALY_MEM_THRESHOLD),
            }

    # ── Collection loop ──────────────────────────────────────────────────────

    def _loop(self):
        while self._running:
            try:
                if self._k8s_core:
                    self._collect_live()
                else:
                    self._collect_demo()
                self._detect_anomalies()
            except Exception as e:
                print(f"[collector] Error in loop: {e}")
            self._tick += 1
            time.sleep(5)

    # ── Demo mode (no K8s) ───────────────────────────────────────────────────

    def _collect_demo(self):
        t = self._tick
        now = datetime.utcnow().isoformat()
        new_pods = {}

        for ns, name, svc, deps in DEMO_TOPOLOGY:
            # Realistic waves: base load + service-specific patterns + noise
            base_cpu = self._base_cpu(name, svc, t)
            base_mem = self._base_mem(name, svc, t)

            cpu    = round(max(0, min(100, base_cpu + random.gauss(0, 2))), 1)
            memory = round(max(0, min(100, base_mem + random.gauss(0, 1.5))), 1)
            disk   = round(max(0, min(100, self._base_disk(name, t) + random.gauss(0, 0.5))), 1)
            net_rx = round(max(0, self._base_net(name, t) + random.gauss(0, 5)), 1)
            net_tx = round(max(0, net_rx * 0.6 + random.gauss(0, 3)), 1)

            restarts = self._restart_count(name, t)

            pod = {
                "name":        name,
                "namespace":   ns,
                "service":     svc,
                "status":      "Running" if random.random() > 0.02 else "CrashLoopBackOff",
                "cpu":         cpu,
                "memory":      memory,
                "disk":        disk,
                "net_rx":      net_rx,
                "net_tx":      net_tx,
                "restarts":    restarts,
                "pvc_ops":     round(random.uniform(0, 50) if svc in ("postgres","longhorn","minio") else 0, 1),
                "uptime":      self._uptime(name),
                "image":       f"{svc}:latest",
                "node":        "minikube",
                "timestamp":   now,
                "dependencies": deps,
            }
            new_pods[name] = pod

            # Update rolling history
            h = self.history[name]
            h.cpu.append(cpu)
            h.memory.append(memory)
            h.disk.append(disk)
            h.net_rx.append(net_rx)
            h.net_tx.append(net_tx)
            h.timestamps.append(now)

        with self._lock:
            self.pods = new_pods

    def _base_cpu(self, name: str, svc: str, t: int) -> float:
        # Inject anomalies for a dramatic demo
        if name == "analytics-worker-4b9e6":
            # Bursty every 40 ticks
            if t % 40 < 10:
                return 88 + 5 * math.sin(t * 0.3)
        if name == "redis-cache-0":
            # Gradual leak pattern
            leak = min(30, t * 0.3)
            return 20 + leak + 10 * math.sin(t * 0.1)
        if name == "payment-service-8f3a2":
            # Normal load with occasional spikes
            return 30 + 20 * math.sin(t * 0.07) + (40 if t % 60 == 0 else 0)

        base_map = {
            "nginx":       15, "node": 35, "python": 40, "java": 55,
            "postgres":    25, "redis": 20, "rabbitmq": 18, "go": 28,
            "prometheus":  30, "grafana": 20, "alertmanager": 10,
            "coredns":     8,  "kube-proxy": 5, "longhorn": 15,
            "minio":       12,
        }
        base = base_map.get(svc, 25)
        return base + 10 * math.sin(t * 0.05 + hash(name) % 10)

    def _base_mem(self, name: str, svc: str, t: int) -> float:
        if name == "redis-cache-0":
            return min(92, 40 + t * 0.4)        # memory leak for demo
        if name == "postgres-primary-0":
            return 55 + 8 * math.sin(t * 0.03)
        mem_map = {
            "nginx":       20, "node": 45, "python": 50, "java": 65,
            "postgres":    55, "redis": 40, "rabbitmq": 35, "go": 38,
            "prometheus":  50, "grafana": 35, "alertmanager": 25,
            "coredns":     15, "kube-proxy": 12, "longhorn": 20,
            "minio":       30,
        }
        base = mem_map.get(svc, 40)
        return base + 5 * math.sin(t * 0.04 + hash(name) % 7)

    def _base_disk(self, name: str, t: int) -> float:
        if "postgres" in name or "minio" in name or "longhorn" in name:
            return 40 + t * 0.05
        return random.uniform(5, 25)

    def _base_net(self, name: str, t: int) -> float:
        if "frontend" in name or "gateway" in name:
            return 80 + 40 * math.sin(t * 0.08)
        if "analytics" in name or "worker" in name:
            return 120 + 60 * abs(math.sin(t * 0.1))
        return random.uniform(5, 40)

    def _restart_count(self, name: str, t: int) -> int:
        if name == "redis-cache-0" and t > 20:
            return int(t / 15)
        if "staging" in name:
            return random.randint(0, 2)
        return 0

    def _uptime(self, name: str) -> str:
        days = random.randint(1, 30)
        hours = random.randint(0, 23)
        return f"{days}d {hours}h"

    # ── Anomaly detection ────────────────────────────────────────────────────

    def _detect_anomalies(self):
        with self._lock:
            pods = list(self.pods.values())

        for pod in pods:
            if pod["cpu"] > ANOMALY_CPU_THRESHOLD:
                self._add_anomaly("CPU_SPIKE", pod["name"], pod["namespace"],
                                  f"CPU at {pod['cpu']}% exceeds threshold {ANOMALY_CPU_THRESHOLD}%",
                                  severity="high" if pod["cpu"] > 90 else "medium")

            if pod["memory"] > ANOMALY_MEM_THRESHOLD:
                self._add_anomaly("MEMORY_LEAK", pod["name"], pod["namespace"],
                                  f"Memory at {pod['memory']}% — possible leak detected",
                                  severity="critical" if pod["memory"] > 92 else "high")

            if pod.get("restarts", 0) >= ANOMALY_RESTART_THRESHOLD:
                self._add_anomaly("CRASH_LOOP", pod["name"], pod["namespace"],
                                  f"Pod restarted {pod['restarts']} times — CrashLoopBackOff risk",
                                  severity="critical")

            if pod["status"] == "CrashLoopBackOff":
                self._add_anomaly("POD_FAILURE", pod["name"], pod["namespace"],
                                  "Pod is in CrashLoopBackOff state",
                                  severity="critical")

    def _add_anomaly(self, anomaly_type: str, pod: str, ns: str, msg: str, severity: str = "medium"):
        # Deduplicate within the last 30 seconds
        now = datetime.utcnow()
        with self._lock:
            for existing in self.anomalies[-10:]:
                if (existing["type"] == anomaly_type and existing["pod"] == pod
                        and (now - datetime.fromisoformat(existing["timestamp"])).seconds < 30):
                    return
            event = {
                "type":      anomaly_type,
                "pod":       pod,
                "namespace": ns,
                "message":   msg,
                "severity":  severity,
                "timestamp": now.isoformat(),
            }
            self.anomalies.append(event)
            if len(self.anomalies) > 200:
                self.anomalies = self.anomalies[-200:]

    # ── Live K8s collection ──────────────────────────────────────────────────

    def _collect_live(self):
        """Collect from real Kubernetes cluster via API."""
        try:
            pods_list = self._k8s_core.list_pod_for_all_namespaces()
            now = datetime.utcnow().isoformat()
            new_pods = {}

            for item in pods_list.items:
                name = item.metadata.name
                ns   = item.metadata.namespace
                status = item.status.phase or "Unknown"
                restarts = sum(
                    cs.restart_count for cs in (item.status.container_statuses or [])
                )
                # metrics-server call via kubectl top (if available)
                cpu_val, mem_val = self._kubectl_top(name, ns)

                pod = {
                    "name":      name,
                    "namespace": ns,
                    "service":   name.split("-")[0],
                    "status":    status,
                    "cpu":       cpu_val,
                    "memory":    mem_val,
                    "disk":      0.0,
                    "net_rx":    0.0,
                    "net_tx":    0.0,
                    "restarts":  restarts,
                    "pvc_ops":   0.0,
                    "uptime":    "unknown",
                    "image":     (item.spec.containers[0].image if item.spec.containers else "unknown"),
                    "node":      item.spec.node_name or "unknown",
                    "timestamp": now,
                    "dependencies": [],
                }
                new_pods[name] = pod
                self.namespaces.add(ns)

                if name not in self.history:
                    self.history[name] = MetricsHistory()
                h = self.history[name]
                h.cpu.append(cpu_val)
                h.memory.append(mem_val)
                h.timestamps.append(now)

            with self._lock:
                self.pods = new_pods
        except Exception as e:
            print(f"[collector] Live collection error: {e}")

    def _kubectl_top(self, pod: str, ns: str) -> tuple[float, float]:
        try:
            out = subprocess.check_output(
                ["kubectl", "top", "pod", pod, "-n", ns, "--no-headers"],
                timeout=5, stderr=subprocess.DEVNULL
            ).decode()
            parts = out.split()
            # parts: [name, cpu(m), memory(Mi)]
            cpu_m   = float(parts[1].rstrip("m"))
            mem_mi  = float(parts[2].rstrip("Mi"))
            cpu_pct = round(cpu_m / 1000 * 100, 1)   # rough %
            mem_pct = round(mem_mi / 512 * 100, 1)    # assume 512Mi limit
            return min(cpu_pct, 100), min(mem_pct, 100)
        except Exception:
            return random.uniform(5, 40), random.uniform(20, 60)


# Singleton instance
collector = PodMetricsCollector()
