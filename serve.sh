#!/usr/bin/env bash
PORT="${1:-8000}"
echo "→ Serving on http://localhost:$PORT (Ctrl+C to stop)"
if command -v python3 >/dev/null 2>&1; then
  python3 -m http.server "$PORT"
elif command -v python >/dev/null 2>&1; then
  python -m SimpleHTTPServer "$PORT"
else
  echo "✗ Python not found."
  exit 1
fi
