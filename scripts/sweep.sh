#!/usr/bin/env bash
# Differential sweep — run diff_runner across a corpus of fixtures, log any
# divergences. Usage: ./sweep.sh <harness> <fixture-dir> [max-files]
#
# harness: instr_execute, txn_execute, vm_interp, vm_syscall_execute,
#          elf_loader, block_execute, txn_cost, gossip_decode
#
# Examples:
#   ./sweep.sh instr_execute /workspaces/test-vectors/instr/fixtures 500
#   ./sweep.sh txn_execute   /workspaces/test-vectors/txn/fixtures
#   ./sweep.sh elf_loader    /workspaces/test-vectors/elf_loader/fixtures

set -uo pipefail

HARNESS=${1:?harness required}
DIR=${2:?fixture dir required}
MAX=${3:-0}

cd "$(dirname "$0")/.."  # firedancer root

OUT=/tmp/sweep-$HARNESS-$(date +%s)
mkdir -p "$OUT/divergent"
SUMMARY=$OUT/summary.txt

> "$SUMMARY"

echo "Sweep starting: harness=$HARNESS dir=$DIR max=$MAX out=$OUT" | tee -a "$SUMMARY"

n=0
matches=0
divergent=0
errors=0
start=$(date +%s)

while IFS= read -r fix; do
  n=$((n+1))
  if [ "$MAX" -gt 0 ] && [ "$n" -gt "$MAX" ]; then break; fi

  # Quick run; suppress log noise from the harness
  result=$( LD_LIBRARY_PATH=. ./diff_runner "$HARNESS" "$fix" 2>&1 | grep -E "^(MATCH|DIVERGENCE|harness=)" )
  rc=$?

  if echo "$result" | grep -q "^MATCH"; then
    matches=$((matches+1))
  elif echo "$result" | grep -q "^DIVERGENCE"; then
    divergent=$((divergent+1))
    # Save divergent fixture + full output for forensics
    cp "$fix" "$OUT/divergent/$(basename "$fix")"
    {
      echo "=== DIVERGENCE on $fix ==="
      LD_LIBRARY_PATH=. ./diff_runner "$HARNESS" "$fix" 2>&1
      echo ""
    } >> "$OUT/divergent/divergences.log"
    echo "  [$n] DIVERGENCE: $(basename "$fix")" | tee -a "$SUMMARY"
  else
    errors=$((errors+1))
    if [ "$errors" -le 3 ]; then
      echo "  [$n] ERROR rc=$rc on $fix" | tee -a "$SUMMARY"
      echo "$result" | head -3 >> "$SUMMARY"
    fi
  fi

  if [ $((n % 50)) -eq 0 ]; then
    elapsed=$(( $(date +%s) - start ))
    echo "  progress: n=$n match=$matches diverge=$divergent err=$errors elapsed=${elapsed}s" | tee -a "$SUMMARY"
  fi
done < <(find "$DIR" -name '*.fix' -type f 2>/dev/null | sort)

elapsed=$(( $(date +%s) - start ))
{
  echo ""
  echo "=== sweep complete ==="
  echo "harness:    $HARNESS"
  echo "dir:        $DIR"
  echo "total:      $n"
  echo "matches:    $matches"
  echo "divergent:  $divergent"
  echo "errors:     $errors"
  echo "elapsed:    ${elapsed}s"
  echo "out:        $OUT/"
} | tee -a "$SUMMARY"

if [ "$divergent" -gt 0 ]; then
  echo ""
  echo "DIVERGENCES FOUND. Check $OUT/divergent/ for fixtures + logs."
  exit 100
fi
exit 0
