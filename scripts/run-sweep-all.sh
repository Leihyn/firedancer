#!/usr/bin/env bash
# One-shot sweep driver. Runs:
#  1. Quick 50-fixture sanity sweep on instr_execute
#  2. If clean, full sweeps on all 5 corpora (instr, txn, syscall, elf_loader, block)
#  3. Auto-keeps Codespace alive
#  4. Aggregates divergences from all sweeps into /tmp/sweep-RESULTS.md
#
# Run this from /workspaces/firedancer:
#   nohup bash scripts/run-sweep-all.sh > /tmp/run-sweep-all.log 2>&1 &
#   tail -f /tmp/run-sweep-all.log

set -uo pipefail
cd /workspaces/firedancer

LOG=/tmp/run-sweep-all.log
RESULTS=/tmp/sweep-RESULTS.md
TV=/workspaces/test-vectors

# Anti-idle keepalive (kills self when this script ends)
( while [ -e /proc/$$ ]; do sleep 60; done ) >/dev/null 2>&1 &
ANTI_IDLE_PID=$!
trap 'kill $ANTI_IDLE_PID 2>/dev/null' EXIT

{
  echo "=== Differential sweep run started $(date -u) ==="
  echo "PID: $$"
  echo "Anti-idle PID: $ANTI_IDLE_PID"
  echo ""

  # Sanity check binaries
  if [ ! -f diff_runner ]; then
    echo "ERROR: ./diff_runner missing. Run: gcc -O2 scripts/diff_runner.c -ldl -o diff_runner"
    exit 1
  fi
  if [ ! -f build/native/gcc/lib/libfd_exec_sol_compat.so ]; then
    echo "ERROR: libfd_exec_sol_compat.so missing"; exit 1
  fi
  if [ ! -f /workspaces/fuzz/solfuzz-agave/target/release/libsolfuzz_agave.so ]; then
    echo "ERROR: libsolfuzz_agave.so missing"; exit 1
  fi
  if [ ! -d "$TV" ]; then
    echo "ERROR: test-vectors corpus missing at $TV"; exit 1
  fi

  echo "=== Phase 1: 50-fixture sanity (instr_execute) ==="
  bash scripts/sweep.sh instr_execute "$TV/instr/fixtures" 50 2>&1
  PHASE1_RC=$?
  echo "Phase 1 exit: $PHASE1_RC"
  echo ""

  if [ $PHASE1_RC -gt 100 ]; then
    echo "Phase 1 errored badly (rc=$PHASE1_RC). Stopping."
    exit $PHASE1_RC
  fi

  # Phase 2: full sweeps in parallel-pairs (2 cores, two harnesses at a time)
  echo "=== Phase 2: full corpus sweeps ==="
  declare -A PAIRS=(
    [instr_execute]="$TV/instr/fixtures"
    [txn_execute]="$TV/txn/fixtures"
    [vm_syscall_execute]="$TV/syscall/fixtures"
    [elf_loader]="$TV/elf_loader/fixtures"
    [block_execute]="$TV/block/fixtures"
  )

  for harness in "${!PAIRS[@]}"; do
    dir="${PAIRS[$harness]}"
    if [ ! -d "$dir" ]; then
      echo "  SKIP $harness: $dir not found"
      continue
    fi
    count=$(find "$dir" -name '*.fix' 2>/dev/null | wc -l)
    echo "  Running $harness over $count fixtures from $dir"
    # Run sequentially to avoid CPU/RAM pressure on 4-core Codespace
    bash scripts/sweep.sh "$harness" "$dir" 0 2>&1
    echo ""
  done

  # Aggregate results
  echo ""
  echo "=== Phase 3: aggregating divergences ==="
  {
    echo "# Differential sweep results"
    echo ""
    echo "Generated: $(date -u)"
    echo ""
    for d in /tmp/sweep-*/; do
      [ -d "$d" ] || continue
      echo "## $(basename "$d")"
      echo ""
      if [ -f "$d/summary.txt" ]; then
        cat "$d/summary.txt"
      fi
      if [ -d "$d/divergent" ] && [ -n "$(ls -A "$d/divergent" 2>/dev/null)" ]; then
        echo ""
        echo "### Divergent fixtures:"
        ls -la "$d/divergent/" | head -30
        if [ -f "$d/divergent/divergences.log" ]; then
          echo ""
          echo "### Divergence details (first 100 lines):"
          echo '```'
          head -100 "$d/divergent/divergences.log"
          echo '```'
        fi
      fi
      echo ""
      echo "---"
      echo ""
    done
  } > "$RESULTS"

  TOTAL_DIVERGENT=$(find /tmp/sweep-*/divergent -name '*.fix' 2>/dev/null | wc -l)
  echo "Total divergent fixtures across all sweeps: $TOTAL_DIVERGENT"
  echo ""
  echo "Full results: $RESULTS"
  echo ""
  if [ "$TOTAL_DIVERGENT" -gt 0 ]; then
    echo "🎯 POTENTIAL FINDINGS — review $RESULTS and dedupe against intel/known-issues-dump.md"
  else
    echo "No divergences in this run."
  fi
  echo "=== run-sweep-all complete $(date -u) ==="
} 2>&1 | tee "$LOG"
