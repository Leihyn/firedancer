#!/usr/bin/env bash
# Launch AFL++ against one harness. Usage: run-afl.sh <harness> [duration_sec]
# harness: instr_execute | txn_execute | vm_syscall_execute | elf_loader | block_execute
# duration_sec: optional time budget (default: unlimited; use Ctrl+C to stop)
set -euo pipefail

HARNESS=${1:?harness required}
DURATION=${2:-0}

OUT=/workspaces/fuzz/findings/$HARNESS
mkdir -p "$OUT"

export AFL_HARNESS=$HARNESS

# Codespace container has read-only /proc/sys/kernel/core_pattern.
# We can't fix the host, so we tell AFL to ignore the check. Crashes will
# still be saved, just with slightly less reliable timeout discrimination.
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
# Codespaces also expose CPU governor as 'powersave' which AFL warns about
export AFL_SKIP_CPUFREQ=1
# Don't try to bind to a specific core (Codespace shares CPUs)
export AFL_NO_AFFINITY=1
# Don't let the harness's first-run abort kill AFL during init
export AFL_SKIP_CRASHES=1

CMD=(
  afl-fuzz
  -i /workspaces/fuzz/corpus/$HARNESS
  -o "$OUT"
  -m none
)

if [ "$DURATION" -gt 0 ]; then
  CMD+=( -V "$DURATION" )
fi

CMD+=( -- /workspaces/fuzz/fuzz_diff )

echo "Launching AFL++ on $HARNESS, output -> $OUT"
echo "  cmd: ${CMD[*]}"
exec "${CMD[@]}"
