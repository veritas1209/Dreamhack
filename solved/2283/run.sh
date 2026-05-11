#!/usr/bin/env bash
# Usage: ./run.sh [port]
set -euo pipefail

PORT="${1:-8000}"                       # default port is 8000 unless the user provides one
DOC_ROOT="$(cd "$(dirname "$0")" && pwd)"

cd "$DOC_ROOT"

echo "------------------------------------------------------------"
echo "Launching local HTTP server ..."
echo
echo "  ▶  Open your browser and navigate to:"
echo "        http://localhost:${PORT}"
echo
echo "  The WebAssembly environment (index.html + wasm) will load"
echo "  automatically. Press Ctrl+C to stop the server at any time."
echo "------------------------------------------------------------"

# Run the server in the foreground so Ctrl+C stops both script & server
exec python3 -m http.server "${PORT}"
