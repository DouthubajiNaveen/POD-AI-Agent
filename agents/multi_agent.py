"""
PodSight AI — Multi-Agent Analysis Framework
Four specialist AI agents: CPU, Memory, Storage, Network.
Uses Claude API when key is set; falls back to rule-based analysis.
"""

import os
import json
import time
import threading
import requests
from datetime import datetime

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODEL = "claude-sonnet-4-20250514"
ANALYSIS_INTERVAL = 30   # seconds between full AI analysis runs


def call_claude(system_prompt: str, user_message: str, max_tokens: int = 600) -> str:
    """Call Claude API. Returns empty string if no key or on error."""
    if not ANTHROPIC_API_KEY:
        return ""
    try:
        resp = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": ANTHROPIC_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            },
            json={
                "model": CLAUDE_MODEL,
                "max_tokens": max_tokens,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_message}],
            },
            timeout=20,
        )
        data = resp.json()
        if "content" in data and data["content"]:
            return data["content"][0].get("text", "")
    except Exception as e:
        print(f"[claude] API error: {e}")
    return ""


# ── Rule-based fallback analysis ─────────────────────────────────────────────

def rule_based_cpu(pods: list) -> dict:
    critical = [p for p in pods if p["cpu"] > 80]
    high     = [p for p in pods if 60 < p["cpu"] <= 80]
    avg      = sum(p["cpu"] for p in pods) / len(pods) if pods else 0

    if critical:
        risk = "critical"
        analysis = (
            f"{len(critical)} pod(s) exceed 80% CPU: {', '.join(p['name'] for p in critical[:3])}. "
            "Immediate scaling or optimization required. Check for runaway loops or missing CPU limits."
        )
        recs = [
            f"kubectl top pod {critical[0]['name']} -n {critical[0]['namespace']}",
            f"kubectl scale deployment {critical[0]['name'].rsplit('-',2)[0]} --replicas=3",
            "Add CPU limits in pod spec: resources.limits.cpu: '500m'",
        ]
    elif high:
        risk = "high"
        analysis = (
            f"Cluster avg CPU {avg:.1f}%. {len(high)} pods approaching limits. "
            "Consider horizontal pod autoscaling."
        )
        recs = [
            "kubectl autoscale deployment <name> --min=2 --max=5 --cpu-percent=70",
            "Review CPU requests vs limits ratio",
        ]
    else:
        risk = "low"
        analysis = f"CPU healthy. Cluster avg {avg:.1f}%. All pods within safe thresholds."
        recs = ["Continue monitoring. Set up HPA for production workloads."]

    return {
        "agent": "CPU Agent",
        "risk":  risk,
        "analysis": analysis,
        "recommendations": recs,
        "metrics": {"avg_cpu": round(avg, 1), "critical_count": len(critical)},
    }


def rule_based_memory(pods: list) -> dict:
    leaking  = [p for p in pods if p["memory"] > 85]
    growing  = [p for p in pods if 70 < p["memory"] <= 85]
    avg      = sum(p["memory"] for p in pods) / len(pods) if pods else 0

    if leaking:
        risk = "critical"
        analysis = (
            f"Memory pressure detected. {len(leaking)} pod(s) above 85%: "
            f"{', '.join(p['name'] for p in leaking[:3])}. Possible memory leak — "
            "monitor heap growth and restart cycles."
        )
        recs = [
            f"kubectl describe pod {leaking[0]['name']} -n {leaking[0]['namespace']}",
            "Add memory limits: resources.limits.memory: '512Mi'",
            "kubectl rollout restart deployment <name>",
        ]
    elif growing:
        risk = "medium"
        analysis = f"{len(growing)} pod(s) between 70-85% memory. Watch for OOMKill events."
        recs = ["kubectl get events --field-selector reason=OOMKilling", "Increase memory requests"]
    else:
        risk = "low"
        analysis = f"Memory healthy. Avg {avg:.1f}%. No leak patterns detected."
        recs = ["Set resource requests/limits for all pods as best practice."]

    return {
        "agent": "Memory Agent",
        "risk":  risk,
        "analysis": analysis,
        "recommendations": recs,
        "metrics": {"avg_memory": round(avg, 1), "leak_suspects": len(leaking)},
    }


def rule_based_storage(pods: list) -> dict:
    pvc_pods  = [p for p in pods if p.get("pvc_ops", 0) > 20]
    high_disk = [p for p in pods if p.get("disk", 0) > 70]

    if high_disk:
        risk = "high"
        analysis = (
            f"{len(high_disk)} pod(s) with disk > 70%: "
            f"{', '.join(p['name'] for p in high_disk[:3])}. PVC saturation risk."
        )
        recs = [
            "kubectl get pvc --all-namespaces",
            "kubectl exec -it <pod> -- df -h",
            "Consider PVC expansion: kubectl patch pvc <name> -p '{\"spec\":{\"resources\":{\"requests\":{\"storage\":\"20Gi\"}}}}'",
        ]
    elif pvc_pods:
        risk = "medium"
        analysis = f"{len(pvc_pods)} pod(s) with elevated PVC I/O. Monitor for throttling."
        recs = ["Check StorageClass IOPS limits", "Use ReadWriteMany PVC for shared access"]
    else:
        risk = "low"
        analysis = "Storage metrics normal. PVC I/O within acceptable bounds."
        recs = ["Implement regular PVC backup with Velero."]

    return {
        "agent": "Storage Agent",
        "risk":  risk,
        "analysis": analysis,
        "recommendations": recs,
        "metrics": {"high_disk_pods": len(high_disk), "active_pvc_pods": len(pvc_pods)},
    }


def rule_based_network(pods: list) -> dict:
    high_rx = [p for p in pods if p.get("net_rx", 0) > 150]
    high_tx = [p for p in pods if p.get("net_tx", 0) > 100]

    if high_rx or high_tx:
        risk = "medium"
        analysis = (
            f"Elevated network traffic: {len(high_rx)} pod(s) high inbound, "
            f"{len(high_tx)} pod(s) high outbound. Check for fan-out calls or DDoS."
        )
        recs = [
            "kubectl exec -it <pod> -- netstat -an | grep ESTABLISHED | wc -l",
            "Apply NetworkPolicy to restrict east-west traffic",
            "Consider Istio rate limiting for ingress pods",
        ]
    else:
        risk = "low"
        analysis = "Network traffic normal across all pods. No unusual patterns."
        recs = ["Implement NetworkPolicy for namespace isolation as security best practice."]

    total_rx = sum(p.get("net_rx", 0) for p in pods)
    total_tx = sum(p.get("net_tx", 0) for p in pods)

    return {
        "agent": "Network Agent",
        "risk":  risk,
        "analysis": analysis,
        "recommendations": recs,
        "metrics": {"total_rx_mbps": round(total_rx, 1), "total_tx_mbps": round(total_tx, 1)},
    }


# ── Claude-powered versions ───────────────────────────────────────────────────

AGENT_SYSTEM = {
    "cpu": (
        "You are a Kubernetes CPU performance expert. Analyze pod CPU metrics and provide: "
        "1) Concise root-cause analysis (2-3 sentences), 2) Risk level (low/medium/high/critical), "
        "3) Three specific kubectl remediation commands. Be precise and actionable. "
        "Reply in JSON: {risk, analysis, recommendations: [str, str, str]}"
    ),
    "memory": (
        "You are a Kubernetes memory and OOM expert. Analyze pod memory metrics and provide: "
        "1) Concise analysis of leak/pressure patterns (2-3 sentences), 2) Risk level, "
        "3) Three kubectl commands. Reply in JSON: {risk, analysis, recommendations: [str, str, str]}"
    ),
    "storage": (
        "You are a Kubernetes storage and PVC expert. Analyze disk and PVC metrics. "
        "Reply in JSON: {risk, analysis, recommendations: [str, str, str]}"
    ),
    "network": (
        "You are a Kubernetes networking expert. Analyze pod network traffic patterns. "
        "Reply in JSON: {risk, analysis, recommendations: [str, str, str]}"
    ),
}


def ai_analyze(agent_type: str, pods: list, fallback_fn) -> dict:
    """Run AI analysis or fall back to rule-based."""
    rule_result = fallback_fn(pods)

    if not ANTHROPIC_API_KEY:
        rule_result["mode"] = "rule-based"
        return rule_result

    # Build compact metric summary for Claude
    top5 = sorted(pods, key=lambda p: p.get(agent_type.replace("network","net_rx"), p.get("cpu",0)), reverse=True)[:5]
    summary = json.dumps([
        {k: p[k] for k in ("name","namespace","cpu","memory","disk","net_rx","net_tx","restarts")
         if k in p}
        for p in top5
    ], indent=2)

    ai_text = call_claude(
        AGENT_SYSTEM[agent_type],
        f"Analyze these top pods by {agent_type} usage:\n{summary}"
    )

    if ai_text:
        try:
            # Strip markdown code fences if present
            clean = ai_text.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
            parsed = json.loads(clean)
            return {
                "agent": rule_result["agent"],
                "risk":  parsed.get("risk", rule_result["risk"]),
                "analysis": parsed.get("analysis", rule_result["analysis"]),
                "recommendations": parsed.get("recommendations", rule_result["recommendations"]),
                "metrics": rule_result["metrics"],
                "mode": "ai-powered",
            }
        except json.JSONDecodeError:
            pass

    rule_result["mode"] = "rule-based"
    return rule_result


# ── Agent Orchestrator ────────────────────────────────────────────────────────

class AgentOrchestrator:
    """Runs all agents on a schedule and caches results."""

    def __init__(self, collector):
        self.collector = collector
        self._results: dict[str, dict] = {}
        self._lock = threading.Lock()
        self._running = False

    def start(self):
        self._running = True
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()
        print(f"[agents] Orchestrator started — 4 agents active (AI={'yes' if ANTHROPIC_API_KEY else 'no, rule-based'})")

    def stop(self):
        self._running = False

    def get_results(self) -> dict:
        with self._lock:
            return dict(self._results)

    def _loop(self):
        while self._running:
            try:
                pods = self.collector.get_all_pods()
                if pods:
                    results = {
                        "cpu":     ai_analyze("cpu",     pods, rule_based_cpu),
                        "memory":  ai_analyze("memory",  pods, rule_based_memory),
                        "storage": ai_analyze("storage", pods, rule_based_storage),
                        "network": ai_analyze("network", pods, rule_based_network),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    with self._lock:
                        self._results = results
                    print(f"[agents] Analysis complete at {results['timestamp']}")
            except Exception as e:
                print(f"[agents] Error: {e}")
            time.sleep(ANALYSIS_INTERVAL)
