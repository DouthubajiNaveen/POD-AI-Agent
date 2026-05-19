#!/usr/bin/env bash
set -e

echo "============================================"
echo "  PodSight AI — Quick Start"
echo "============================================"

# Check Python
python3 --version || { echo "ERROR: Python 3 not found"; exit 1; }

# Install dependencies
echo "[1/3] Installing Python dependencies…"
pip install flask flask-cors requests kubernetes --quiet

# Optional: set API key
if [[ -n "$ANTHROPIC_API_KEY" ]]; then
  echo "[✓] Anthropic API key found — AI mode enabled"
else
  echo "[i] No ANTHROPIC_API_KEY — running in rule-based mode"
  echo "    To enable AI: export ANTHROPIC_API_KEY=sk-ant-your-key"
fi

# Create __init__ files
touch backend/__init__.py agents/__init__.py 2>/dev/null || true

echo "[2/3] Starting PodSight AI backend on port 5000…"
echo "[3/3] Open dashboard/index.html in your browser"
echo ""
echo "  Dashboard: file://$(pwd)/dashboard/index.html"
echo "  API:       http://localhost:5000/api/summary"
echo ""

python3 server.py
