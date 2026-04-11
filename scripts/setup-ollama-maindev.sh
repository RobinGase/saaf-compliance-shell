#!/usr/bin/env bash
# Set up Ollama + Nemotron 8B on maindev for local inference.
# Run this on maindev (Windows — use Git Bash or WSL).
# Usage: bash scripts/setup-ollama-maindev.sh

set -euo pipefail

echo "=== saaf-compliance-shell: Ollama setup on maindev ==="
echo ""

# 1. Check Ollama is installed
if ! command -v ollama &>/dev/null; then
    echo "FAIL: Ollama not installed"
    echo "      Download from: https://ollama.com/download"
    exit 1
fi
echo "OK: Ollama found at $(which ollama)"

# 2. Check GPU
echo ""
echo "--- GPU check ---"
if command -v nvidia-smi &>/dev/null; then
    nvidia-smi --query-gpu=name,memory.total --format=csv,noheader
else
    echo "WARN: nvidia-smi not found — Ollama may fall back to CPU"
fi

# 3. Pull the model
echo ""
echo "--- Pulling Nemotron 8B ---"
ollama pull Randomblock1/nemotron-nano:8b

# 4. Configure Ollama to listen on all interfaces (for Tailscale access)
echo ""
echo "--- Configuration ---"
echo "To allow fedoraserver to reach Ollama over Tailscale, set:"
echo ""
echo "  OLLAMA_HOST=0.0.0.0:8000"
echo ""
echo "On Windows, set this as a system environment variable, then restart Ollama."
echo "On Linux, add to /etc/systemd/system/ollama.service or your shell profile."
echo ""

# 5. Quick test
echo "--- Quick test ---"
echo "Testing model locally..."
RESPONSE=$(ollama run Randomblock1/nemotron-nano:8b "Reply with only: OK" 2>/dev/null | head -1)
echo "Model response: $RESPONSE"

echo ""
echo "=== Setup complete ==="
echo ""
echo "Next steps:"
echo "  1. Set OLLAMA_HOST=0.0.0.0:8000 and restart Ollama"
echo "  2. From fedoraserver, test: curl http://100.87.245.60:8000/v1/models"
echo "  3. Firewall port 8000 to Tailscale interface only"
