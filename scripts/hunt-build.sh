#!/usr/bin/env bash
# Auto-build script for Firedancer v1.0 hunt — runs on Codespace start.
# Outputs everything to /tmp/hunt-build.log for the user to paste back on failure.

set -o pipefail

LOG=/tmp/hunt-build.log
MARKER=/tmp/hunt-build.done

# Idempotent: if already done, exit.
if [ -f "$MARKER" ]; then
  echo "Build already completed previously. See $LOG for output."
  exit 0
fi

{
  echo "=============================================="
  echo "Firedancer hunt-build starting"
  echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "OS: $(cat /etc/os-release 2>/dev/null | head -3 | tr '\n' ' ')"
  echo "Branch: $(git branch --show-current 2>/dev/null)"
  echo "Commit: $(git rev-parse --short HEAD 2>/dev/null)"
  echo "CPU: $(nproc) cores"
  echo "Memory: $(free -h 2>/dev/null | head -2 | tail -1)"
  echo "Disk free: $(df -h / 2>/dev/null | tail -1 | awk '{print $4}')"
  echo "=============================================="
  echo ""

  # Stage 1: Ensure we have what we need
  echo "--- Stage 1: verify prerequisites ---"
  for cmd in gcc make git curl patch bc xxd cmake clang; do
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "  ok: $cmd -> $(command -v $cmd)"
    else
      echo "  MISSING: $cmd"
    fi
  done
  echo ""

  # Stage 2: ensure rust toolchain
  echo "--- Stage 2: rust toolchain ---"
  if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  if ! command -v rustup >/dev/null 2>&1; then
    echo "  rustup not found, installing..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    # shellcheck disable=SC1091
    source "$HOME/.cargo/env"
  fi
  echo "  rustc: $(rustc --version 2>&1)"
  echo "  cargo: $(cargo --version 2>&1)"
  echo ""

  # Stage 3: submodules
  echo "--- Stage 3: git submodules ---"
  git submodule update --init --recursive 2>&1 | tail -20
  echo ""

  # Stage 4: ./deps.sh +dev
  echo "--- Stage 4: ./deps.sh +dev (builds zstd, blst, rocksdb, openssl, s2n-bignum, etc.) ---"
  if [ -x ./deps.sh ]; then
    ./deps.sh +dev 2>&1 | tail -100
  else
    echo "  ERROR: ./deps.sh missing or not executable"
    exit 1
  fi
  echo ""

  # Stage 5: make
  echo "--- Stage 5: make -j2 fdctl solana ---"
  J=2
  # If we have > 16 GB RAM, try j4
  MEMKB=$(awk '/MemTotal/ {print $2}' /proc/meminfo 2>/dev/null || echo 0)
  if [ "$MEMKB" -gt 20000000 ]; then J=4; fi
  echo "  using -j$J"
  make -j$J fdctl solana 2>&1 | tail -200
  MAKE_RC=${PIPESTATUS[0]}
  echo ""

  if [ "$MAKE_RC" -eq 0 ]; then
    echo "=============================================="
    echo "BUILD SUCCEEDED"
    echo "Binary: $(find build -name fdctl -type f 2>/dev/null | head -1)"
    echo "=============================================="
    touch "$MARKER"
  else
    echo "=============================================="
    echo "BUILD FAILED (rc=$MAKE_RC). See above tail for errors."
    echo "Paste the contents of $LOG back to Claude."
    echo "=============================================="
    exit "$MAKE_RC"
  fi
} > "$LOG" 2>&1

echo "Build complete. Full log at $LOG"
tail -40 "$LOG"
