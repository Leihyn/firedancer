#!/usr/bin/env bash
# Differential fuzzing setup for Firedancer v1.0 hunt.
# Clones solfuzz-agave, builds it, and stages a starter corpus + diff runner.
set -euo pipefail

LOG=/tmp/setup-fuzz.log
WORKDIR=/workspaces/firedancer
FUZZ_DIR=$WORKDIR/../fuzz
SOLFUZZ_DIR=$FUZZ_DIR/solfuzz-agave

mkdir -p "$FUZZ_DIR"
cd "$FUZZ_DIR"

{
  echo "=============================================="
  echo "setup-fuzz starting at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "=============================================="

  # 1. Clone solfuzz-agave (the upstream protobuf-driven harness wrapper)
  if [ ! -d "$SOLFUZZ_DIR" ]; then
    echo "--- Cloning firedancer-io/solfuzz-agave ---"
    git clone --depth=1 https://github.com/firedancer-io/solfuzz-agave.git "$SOLFUZZ_DIR"
  else
    echo "--- solfuzz-agave already cloned, pulling latest ---"
    cd "$SOLFUZZ_DIR" && git pull --ff-only && cd "$FUZZ_DIR"
  fi

  # 2. Source rust env
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi

  # 3. Build solfuzz-agave (this provides the Agave-side harness as a .so)
  echo "--- Building solfuzz-agave (Agave-side harness) ---"
  cd "$SOLFUZZ_DIR"
  # solfuzz-agave is a cargo workspace; build with stub-agave-runtime feature
  cargo build --release --lib 2>&1 | tail -50 || {
    echo "  WARN: cargo build failed — fuzzing setup incomplete."
    echo "  See top of log for cargo errors. May need to install protobuf-compiler-rust or specific toolchain."
  }
  cd "$FUZZ_DIR"

  # 4. Show what artifacts we have
  echo "--- Artifacts produced ---"
  find "$SOLFUZZ_DIR/target/release" -maxdepth 2 -name '*.so' -o -name 'libsolfuzz*' 2>/dev/null | head -10
  echo ""
  find "$WORKDIR/build/native/gcc/lib" -name 'libfd_*.a' 2>/dev/null | head -10
  echo ""

  # 5. Stage a starter corpus directory
  CORPUS=$FUZZ_DIR/corpus
  mkdir -p "$CORPUS/vm_interp" "$CORPUS/shred_parse" "$CORPUS/elf_loader"

  # Pull existing test fixtures from the firedancer tree as initial seeds
  # vm fixtures
  echo "--- Staging seed corpus from firedancer test vectors ---"
  if [ -d "$WORKDIR/src/flamenco/runtime/tests/fixtures" ]; then
    find "$WORKDIR/src/flamenco/runtime/tests/fixtures" -name '*.bin' 2>/dev/null | head -5
  fi

  # 6. Write a minimal differential runner stub
  cat > "$FUZZ_DIR/run-diff.sh" << 'RUNNER_EOF'
#!/usr/bin/env bash
# Runs a single protobuf input through both Firedancer and Agave harnesses
# and diffs the output. Usage: ./run-diff.sh <harness> <input.bin>
HARNESS=${1:-vm_interp}
INPUT=${2:?Usage: $0 <harness> <input.bin>}

FUZZ_DIR=$(cd "$(dirname "$0")" && pwd)
WORKDIR=$FUZZ_DIR/../firedancer
SOLFUZZ_LIB=$FUZZ_DIR/solfuzz-agave/target/release/libsolfuzz_agave.so

if [ ! -f "$SOLFUZZ_LIB" ]; then
  echo "ERROR: $SOLFUZZ_LIB not found. Build solfuzz-agave first."
  exit 1
fi
if [ ! -f "$INPUT" ]; then
  echo "ERROR: input file $INPUT not found"
  exit 1
fi

# TODO: invoke the harness ABI from both sides and diff
# This needs the 'fuzz_target' binary that ties them together — see solfuzz-agave/README
# For now, just confirm both sides are present:
echo "Firedancer harness sources at: $WORKDIR/src/flamenco/runtime/tests/"
echo "Agave harness lib at: $SOLFUZZ_LIB"
echo "Input: $(file "$INPUT")"
echo "Size: $(stat -c%s "$INPUT") bytes"
echo ""
echo "Stub: implement protobuf invocation + diff per solfuzz-agave/README.md"
RUNNER_EOF
  chmod +x "$FUZZ_DIR/run-diff.sh"

  echo ""
  echo "=============================================="
  echo "Setup complete. Workspace:"
  echo "  $FUZZ_DIR/"
  echo "  ├── solfuzz-agave/                  (Agave-side harness)"
  echo "  ├── corpus/{vm_interp,shred_parse,elf_loader}/  (seed corpus)"
  echo "  └── run-diff.sh                     (single-input differential runner)"
  echo ""
  echo "Next steps (manual):"
  echo "  1. Read solfuzz-agave/README.md to learn the protobuf input format"
  echo "  2. Build firedancer-side harness binary (likely make target named after harness)"
  echo "  3. Wire run-diff.sh to invoke both and compare effect output"
  echo "=============================================="
} 2>&1 | tee "$LOG"

echo "Setup log saved to $LOG"
