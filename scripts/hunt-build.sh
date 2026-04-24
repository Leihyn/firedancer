#!/usr/bin/env bash
# Auto-build script v2 for Firedancer v1.0 hunt — fixes deps.sh interactive read.
set -o pipefail

LOG=/tmp/hunt-build.log
MARKER=/tmp/hunt-build.done

if [ -f "$MARKER" ]; then
  echo "Build already completed previously. See $LOG for output."
  exit 0
fi

{
  echo "=============================================="
  echo "Firedancer hunt-build v2 starting"
  echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "OS: $(cat /etc/os-release 2>/dev/null | head -3 | tr '\n' ' ')"
  echo "Branch: $(git branch --show-current 2>/dev/null)"
  echo "Commit: $(git rev-parse --short HEAD 2>/dev/null)"
  echo "CPU: $(nproc) cores"
  echo "Memory: $(free -h 2>/dev/null | head -2 | tail -1)"
  echo "=============================================="
  echo ""

  echo "--- Stage 1: verify prerequisites ---"
  for cmd in gcc make git curl patch bc xxd cmake clang; do
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "  ok: $cmd"
    else
      echo "  MISSING: $cmd"
    fi
  done
  echo ""

  echo "--- Stage 2: rust toolchain ---"
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  if ! command -v rustup >/dev/null 2>&1; then
    echo "  rustup not found, installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --no-modify-path
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  echo "  rustc: $(rustc --version 2>&1)"
  echo "  cargo: $(cargo --version 2>&1)"
  echo ""

  echo "--- Stage 3: git submodules ---"
  git submodule update --init --recursive 2>&1 | tail -10
  echo ""

  echo "--- Stage 4: ./deps.sh +dev (auto-yes piped in) ---"
  if [ -x ./deps.sh ]; then
    # deps.sh has an interactive `read` prompt — pipe 'y' newlines to auto-confirm.
    # Use yes(1) for safety in case it asks multiple times.
    yes | ./deps.sh +dev 2>&1 | tail -200
    DEPS_RC=${PIPESTATUS[1]}
    echo "  deps.sh exit code: $DEPS_RC"
    if [ "$DEPS_RC" -ne 0 ]; then
      echo "  WARN: deps.sh returned $DEPS_RC — checking opt/ anyway..."
    fi
  else
    echo "  ERROR: ./deps.sh missing or not executable"
    exit 1
  fi
  echo ""
  echo "--- opt/ contents after deps.sh ---"
  ls opt/ 2>/dev/null || echo "  no opt/ dir"
  ls opt/lib/ 2>/dev/null | head -20 || echo "  no opt/lib/"
  echo ""

  echo "--- Stage 5: make -j2 fdctl solana ---"
  J=2
  MEMKB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  if [ "$MEMKB" -gt 20000000 ]; then J=4; fi
  echo "  using -j$J on $(nproc) cores"
  make -j$J fdctl solana 2>&1 | tail -200
  MAKE_RC=${PIPESTATUS[0]}
  echo ""

  if [ "$MAKE_RC" -eq 0 ]; then
    echo "=============================================="
    echo "BUILD SUCCEEDED"
    echo "Binary: $(find build -name fdctl -type f 2>/dev/null | head -1)"
    find build -name 'fdctl' -o -name 'firedancer' -type f 2>/dev/null
    echo "=============================================="
    touch "$MARKER"
  else
    echo "=============================================="
    echo "BUILD FAILED (rc=$MAKE_RC)"
    echo "=============================================="
    exit "$MAKE_RC"
  fi
} > "$LOG" 2>&1

echo "Build complete. Full log at $LOG"
tail -40 "$LOG"
