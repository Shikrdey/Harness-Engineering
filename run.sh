#!/usr/bin/env bash
# Start the classifier server on http://127.0.0.1:8000 (run inside WSL).
cd "$(dirname "$0")" || exit 1
exec ./venv/bin/uvicorn main:app --host 127.0.0.1 --port "${PORT:-8000}"
