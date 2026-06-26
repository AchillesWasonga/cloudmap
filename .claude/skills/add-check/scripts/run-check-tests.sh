#!/usr/bin/env bash
# Run ramwingu's scanner unit tests. Claude should RUN this (per SKILL.md), not
# read it — only the output uses tokens.
#
# Scoped to tests/tests_*.py (the scanner suites) on purpose: the full
# `unittest discover` also pulls in tests/test_utils.py, a known pre-existing
# failure unrelated to scanners.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$ROOT"

# Prefer the project venv (has boto3 + azure SDKs); fall back to python3/python.
if [[ -x "$ROOT/env/bin/python" ]]; then
  PY="$ROOT/env/bin/python"
elif command -v python3 >/dev/null 2>&1; then
  PY="python3"
else
  PY="python"
fi

modules=()
for f in tests/tests_*.py; do
  [[ -e "$f" ]] || continue
  base="$(basename "$f" .py)"
  modules+=("tests.$base")
done

if [[ ${#modules[@]} -eq 0 ]]; then
  echo "No tests/tests_*.py scanner suites found."
  exit 0
fi

echo "Running scanner tests with $PY: ${modules[*]}"
exec "$PY" -m unittest "${modules[@]}"
