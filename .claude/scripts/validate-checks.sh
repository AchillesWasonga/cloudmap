#!/usr/bin/env bash
# Ramwingu structural validator. Enforces the project's design rules that can be
# checked mechanically, so a violation is caught before it reaches a teammate
# rather than in review.
#
# Usage:
#   .claude/scripts/validate-checks.sh        # validate the whole tree
#
# Exit code: 0 = clean, 1 = at least one ERROR. Warnings never fail the run.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SCANNERS_DIR="$ROOT/ramwingu/scanners"
TESTS_DIR="$ROOT/tests"

errors=0
warns=0
err()  { printf '  \033[31mERROR\033[0m %s\n' "$1"; errors=$((errors+1)); }
warn() { printf '  \033[33mWARN \033[0m %s\n' "$1"; warns=$((warns+1)); }
ok()   { printf '  \033[32mok   \033[0m %s\n' "$1"; }

# Names of all scanner modules (aws, azure, gcp, ...), excluding __init__.
scanner_names=()
while IFS= read -r -d '' f; do
  base="$(basename "$f" .py)"
  [[ "$base" == "__init__" ]] && continue
  scanner_names+=("$base")
done < <(find "$SCANNERS_DIR" -maxdepth 1 -name '*.py' -print0 2>/dev/null)

# ---------------------------------------------------------------------------
# Rule 1: no shared cross-platform check-logic module.
# ---------------------------------------------------------------------------
printf '\nstandalone scanners\n'
shared_hit=0
for forbidden in shared common base core checks helpers utils; do
  if [[ -f "$SCANNERS_DIR/$forbidden.py" ]]; then
    err "scanners/$forbidden.py exists — no shared cross-platform check module is allowed"
    shared_hit=1
  fi
done
[[ $shared_hit -eq 0 ]] && ok "no shared cross-platform check module"

# ---------------------------------------------------------------------------
# Rule 2: a scanner must not import another scanner.
# ---------------------------------------------------------------------------
for name in "${scanner_names[@]}"; do
  scanner="$SCANNERS_DIR/$name.py"
  cross=0
  for other in "${scanner_names[@]}"; do
    [[ "$other" == "$name" ]] && continue
    if grep -Eq "(^|[^_])import[[:space:]]+.*\b$other\b|from[[:space:]]+.*scanners[[:space:]]+import[[:space:]]+.*\b$other\b|from[[:space:]]+\.?\b$other\b[[:space:]]+import" "$scanner"; then
      err "scanner $name.py imports sibling scanner '$other' — scanners must stand alone"
      cross=1
    fi
  done
  [[ $cross -eq 0 ]] && ok "$name.py does not import a sibling scanner"
done

# ---------------------------------------------------------------------------
# Rule 3: every scanner has a test module, and every check_* is covered there.
# ---------------------------------------------------------------------------
printf '\ncheck coverage\n'
for name in "${scanner_names[@]}"; do
  scanner="$SCANNERS_DIR/$name.py"
  testfile="$TESTS_DIR/tests_$name.py"
  if [[ ! -f "$testfile" ]]; then
    err "scanner $name.py has no test module (expected tests/tests_$name.py)"
    continue
  fi
  # Public check functions defined in the scanner.
  while IFS= read -r fn; do
    [[ -z "$fn" ]] && continue
    if grep -q "\b$fn\b" "$testfile"; then
      ok "$name: $fn is covered by tests_$name.py"
    else
      err "$name: $fn is not referenced in tests_$name.py — every check needs tests"
    fi
  done < <(grep -oE '^def (check_[A-Za-z0-9_]+)' "$scanner" | sed 's/^def //')
done

# ---------------------------------------------------------------------------
# Rule 4: credential handling must not store/log/transmit secrets.
# ---------------------------------------------------------------------------
printf '\ncredential safety\n'
creds="$ROOT/ramwingu/credentials.py"
if [[ -f "$creds" ]]; then
  # Patterns that would mean creds leave memory: file writes, network, pickling.
  if grep -nEi '\bopen[[:space:]]*\(|\.write[[:space:]]*\(|json\.dump|pickle|requests\.|urllib|socket|http\.client|smtplib' "$creds"; then
    err "credentials.py contains a file/network/serialization pattern — creds must stay in memory only"
  else
    ok "credentials.py has no obvious persistence/exfil pattern"
  fi
else
  warn "ramwingu/credentials.py not found"
fi

printf '\n— %d error(s), %d warning(s) —\n' "$errors" "$warns"
[[ $errors -eq 0 ]]
