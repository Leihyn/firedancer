#!/usr/bin/env bash
# Differential fuzzing via solfuzz-agave's built-in libFuzzer harness.
#
# Why this beats raw AFL: solfuzz-agave already exports an
# LLVMFuzzerTestOneInput entry point with protobuf-aware mutation. libFuzzer
# gets sancov coverage feedback from the WHOLE Agave-side runtime AND from
# our Firedancer-side harness library when we LD_PRELOAD it. Mutations stay
# protobuf-valid → both sides actually execute the input → divergences surface.
#
# Usage:
#   bash run-libfuzzer.sh <harness>            # run forever (Ctrl+C to stop)
#   bash run-libfuzzer.sh <harness> 3600       # run for 1 hour
#
# harness ∈ instr_execute, txn_execute, vm_interp, vm_syscall_execute,
#           elf_loader, shred_parse, pack_compute_budget
set -euo pipefail

HARNESS=${1:?harness required}
DURATION=${2:-0}

CORPUS_DIR=/workspaces/fuzz/libfuzzer-corpus/$HARNESS
CRASH_DIR=/workspaces/fuzz/libfuzzer-findings/$HARNESS
mkdir -p "$CORPUS_DIR" "$CRASH_DIR"

# Seed corpus from test-vectors (only on first run; libFuzzer prunes dups)
if [ -z "$(ls -A "$CORPUS_DIR" 2>/dev/null)" ]; then
  case $HARNESS in
    instr_execute)        src=/workspaces/test-vectors/instr/fixtures ;;
    txn_execute)          src=/workspaces/test-vectors/txn/fixtures ;;
    vm_syscall_execute)   src=/workspaces/test-vectors/syscall/fixtures ;;
    vm_interp)            src=/workspaces/test-vectors/syscall/fixtures ;;
    elf_loader)           src=/workspaces/test-vectors/elf_loader/fixtures ;;
    *)                    src= ;;
  esac
  if [ -n "$src" ] && [ -d "$src" ]; then
    echo "Seeding corpus from $src..."
    n=0
    while IFS= read -r f; do
      cp "$f" "$CORPUS_DIR/$(basename "$f")"
      n=$((n+1))
      if [ "$n" -ge 500 ]; then break; fi
    done < <(find "$src" -name '*.fix' 2>/dev/null | sort)
    echo "  seeded $n fixtures"
  fi
fi

cd /workspaces/fuzz/solfuzz-agave

# Build the libFuzzer harness for this entrypoint.
#   solfuzz-agave's Cargo.toml exposes the protobuf entrypoint as a fuzz target
#   under fuzz_targets/<harness>.rs.  cargo-fuzz handles LLVM pass + linker
#   flags automatically.
if ! command -v cargo-fuzz >/dev/null 2>&1; then
  echo "Installing cargo-fuzz..."
  cargo install cargo-fuzz 2>&1 | tail -5
fi

# Detect the actual fuzz target name. solfuzz-agave names them per harness.
if [ -d fuzz/fuzz_targets ]; then
  TARGET_NAME=$HARNESS
  if [ ! -f "fuzz/fuzz_targets/$HARNESS.rs" ]; then
    # Fallback: list available targets and pick the closest
    echo "No fuzz_targets/$HARNESS.rs; available targets:"
    ls fuzz/fuzz_targets/ 2>&1 | head -10
    echo "Override TARGET_NAME env var to pick one."
    TARGET_NAME=${TARGET_NAME_OVERRIDE:-}
    if [ -z "$TARGET_NAME" ]; then exit 2; fi
  fi
else
  echo "ERROR: solfuzz-agave/fuzz/fuzz_targets dir missing — repo layout changed."
  exit 1
fi

# Pass corpus dir + crash dir + duration to cargo-fuzz
ARGS=(
  run "$TARGET_NAME"
  "$CORPUS_DIR"
  --release
  --
  -artifact_prefix="$CRASH_DIR/"
  -timeout=10
  -rss_limit_mb=4096
  -print_pcs=1
  -print_corpus_stats=1
)
if [ "$DURATION" -gt 0 ]; then
  ARGS+=( -max_total_time="$DURATION" )
fi

echo "Launching libFuzzer on $HARNESS"
echo "  corpus: $CORPUS_DIR"
echo "  crashes -> $CRASH_DIR"
echo "  cmd: cargo fuzz ${ARGS[*]}"
exec cargo fuzz "${ARGS[@]}"
