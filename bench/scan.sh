#!/usr/bin/env bash
# Run a full Orion vulnerability scan on the current (Grendel) build.
# Pipeline: build graph (Joern -> Neo4j) -> semantic index (GPU) -> 4-shape discovery fleet ->
# independent verifier -> ranked report. Writes findings JSON + a report log under bench/runs/.
#
#   bash bench/scan.sh /path/to/target/repo [--no-semantic] [extra `orion scan` args...]
#
# Prereqs: bench/setup.sh has run, and the Claude CLI is authenticated (see bench/README.md).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# shellcheck source=/dev/null
[ -f bench/env.sh ] && source bench/env.sh || {
  echo "bench/env.sh not found — run bench/setup.sh first." >&2; exit 1; }

TARGET="${1:-}"
[ -n "$TARGET" ] || { echo "usage: bash bench/scan.sh /path/to/target/repo [args]" >&2; exit 2; }
[ -d "$TARGET" ] || { echo "not a directory: $TARGET" >&2; exit 2; }
shift
TARGET="$(cd "$TARGET" && pwd)"

# --no-semantic => keep the GPU/embedding out of it (graph-only discovery). Everything else passes
# straight through to `orion scan` (e.g. --language jssrc, --queue-size N).
EXTRA=(); SEMANTIC=1
for a in "$@"; do
  if [ "$a" = "--no-semantic" ]; then SEMANTIC=0; else EXTRA+=("$a"); fi
done
[ "$SEMANTIC" = "0" ] && export CUDA_VISIBLE_DEVICES=""   # hide GPU -> embed on CPU is skipped/slow

OUT="$REPO_ROOT/bench/runs/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$OUT"

echo "== Orion full scan =="
echo "  target : $TARGET"
echo "  out    : $OUT"
echo "  claude : $(command -v claude)  $(claude --version 2>&1 | head -1)"
echo "  gpu    : $([ "$SEMANTIC" = 1 ] && echo 'semantic index on GPU' || echo 'graph-only (--no-semantic)')"
echo

# Orion's CLI writes its live progress log under .orion/runs/<scan_id>/<ts>/progress.jsonl and
# prints the ranked report at the end. bench/orion_scan.py applies the transformers alias, then
# runs `orion scan`. --json writes the machine-readable verdicts.
./.venv/bin/python bench/orion_scan.py "$TARGET" \
  --json "$OUT/findings.json" "${EXTRA[@]:-}" \
  2> >(tee "$OUT/scan.stderr.log" >&2) | tee "$OUT/report.log"

echo
echo "== done =="
echo "  findings : $OUT/findings.json   (CONFIRM/REJECT/INCONCLUSIVE per lead)"
echo "  report   : $OUT/report.log"
echo "  live log : .orion/runs/*/*/progress.jsonl"
