#!/usr/bin/env bash
# Local pip-audit snapshot for XFreeRDP-Manager
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "XFreeRDP-Manager — supply chain status"
echo "Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
echo

docker run --rm -v "${ROOT}:/app" -w /app python:3.11-slim \
  sh -c "pip install -q pip-audit && pip-audit -r requirements.txt --desc on 2>&1 || true"

echo
echo "Track ongoing alerts: GitHub → Security → Dependabot / Code scanning"
