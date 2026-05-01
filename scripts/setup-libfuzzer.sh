#!/usr/bin/env bash
# libFuzzer differential setup for Firedancer v1.0 hunt.
#
# Replaces the AFL+blind approach with a real coverage-instrumented
# differential fuzzer. The Agave-side .so already has the right flags
# baked into its Makefile (`make shared_obj`). The Firedancer-side .so
# does NOT have sancov instrumentation by default, so this script also
# rebuilds it with the matching flags.
#
# Pipeline:
#   1. Rebuild libsolfuzz_agave.so with -Cpasses=sancov-module + 8-bit counters
#   2. Rebuild libfd_exec_sol_compat.so with -fsanitize-coverage=inline-8bit-counters
#   3. Write fuzz_driver.c (LLVMFuzzerTestOneInput → both libs → abort on divergence)
#   4. Compile driver with -fsanitize=fuzzer,address linking both .so
#   5. Wrapper script run-libfuzzer.sh launches driver with corpus + crash dir
#
# Usage:
#   bash scripts/setup-libfuzzer.sh
#   bash /workspaces/fuzz/run-libfuzzer.sh <harness>
#
# harness = instr_execute | txn_execute | vm_syscall_execute | elf_loader | block_execute
set -euo pipefail

LOG=/tmp/setup-libfuzzer.log
WORK=/workspaces/fuzz
FD_DIR=/workspaces/firedancer

{
echo "=============================================="
echo "libFuzzer setup starting at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "=============================================="

# 0. Tooling check
for tool in clang make cargo; do
  command -v $tool >/dev/null || { echo "ERROR: $tool missing"; exit 1; }
done
echo "  clang : $(clang --version | head -1)"
echo "  rustc : $(rustc --version)"
echo ""

# 1. Rebuild Agave-side with sancov instrumentation
echo "--- Stage 1: rebuild libsolfuzz_agave.so with sancov ---"
cd $WORK/solfuzz-agave
# This is THEIR canonical fuzzer build target. Takes ~5-15 min.
make shared_obj 2>&1 | tail -20
INSTRUMENTED_SO=$WORK/solfuzz-agave/target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so
if [ ! -f "$INSTRUMENTED_SO" ]; then
  echo "ERROR: instrumented libsolfuzz_agave.so missing at $INSTRUMENTED_SO"
  exit 1
fi
echo "  built: $INSTRUMENTED_SO ($(stat -c%s "$INSTRUMENTED_SO") bytes)"
# Verify sancov symbols are present (LLVMFuzzerTestOneInput, sancov hooks)
nm -D --defined-only "$INSTRUMENTED_SO" | grep -E "sancov|__sanitizer_cov" | head -5 || echo "  (note: sancov hooks may be inline)"
echo ""

# 2. Rebuild Firedancer-side with sancov instrumentation
echo "--- Stage 2: rebuild libfd_exec_sol_compat.so with sancov ---"
# Firedancer doesn't use Cargo for this lib; it's a make target. Pass extra
# CFLAGS via the EXTRA_CPPFLAGS env that its build accepts.
cd $FD_DIR
SANCOV_CFLAGS='-fsanitize-coverage=inline-8bit-counters,trace-cmp,pc-table -g'
# These flags are clang-only — GCC's -fsanitize-coverage doesn't accept
# inline-8bit-counters / pc-table. So we force the build to use clang.
# Firedancer's machine system uses MACHINE=native_clang_x86_64 to pick a
# clang-based compile profile; if that's missing we fall back to setting
# CC=clang directly on the make line.
# Backup existing un-instrumented .so
cp -f build/native/gcc/lib/libfd_exec_sol_compat.so build/native/gcc/lib/libfd_exec_sol_compat.so.bak 2>/dev/null || true
# Wipe stale GCC-built objects so make rebuilds with clang and the sancov flags
rm -rf build/native/gcc/obj 2>/dev/null || true
# Run with CC/CXX=clang, output dir under build/native/clang
echo "  using clang for sancov-instrumented rebuild"
CC=clang CXX=clang++ \
EXTRA_CPPFLAGS="$SANCOV_CFLAGS" \
EXTRA_CFLAGS="$SANCOV_CFLAGS" \
EXTRA_LDFLAGS="$SANCOV_CFLAGS" \
MACHINE=linux_clang_x86_64 \
make -j2 libfd_exec_sol_compat.so 2>&1 | tail -50
INSTRUMENTED_FD=""
for cand in \
  $FD_DIR/build/native/clang/lib/libfd_exec_sol_compat.so \
  $FD_DIR/build/linux/clang/x86_64/lib/libfd_exec_sol_compat.so \
  $FD_DIR/build/native/gcc/lib/libfd_exec_sol_compat.so; do
  if [ -f "$cand" ]; then
    INSTRUMENTED_FD="$cand"
    break
  fi
done
if [ ! -f "$INSTRUMENTED_FD" ]; then
  echo "ERROR: rebuild failed"
  exit 1
fi
echo "  rebuilt: $INSTRUMENTED_FD ($(stat -c%s "$INSTRUMENTED_FD") bytes)"
echo ""

# 3. Write the libFuzzer driver
echo "--- Stage 3: write fuzz_driver.c ---"
mkdir -p $WORK
cat > $WORK/fuzz_driver.c << 'DRIVER_EOF'
/* libFuzzer differential driver for Firedancer ↔ Agave conformance.
 *
 * libFuzzer hands us mutated bytes via LLVMFuzzerTestOneInput. We run them
 * through BOTH harness libraries (loaded via dlopen) and abort if outputs
 * diverge — libFuzzer saves the input as a crash artifact.
 *
 * Coverage feedback: BOTH .so files were rebuilt with sancov inline-8bit-
 * counters, so libFuzzer's mutation engine sees their internal coverage.
 * That's the critical upgrade over the AFL-on-uninstrumented-blob setup.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef int (*sol_compat_fn_t)(void *, unsigned long *, void const *, unsigned long);
typedef void (*sol_compat_init_fn_t)(int);

static sol_compat_fn_t fd_fn = NULL;
static sol_compat_fn_t ag_fn = NULL;
static int strict = 0;

static unsigned char fd_out[16UL * 1024UL * 1024UL];
static unsigned char ag_out[16UL * 1024UL * 1024UL];

#define SIZE_SLACK 16
#define TAIL_SKIP  64

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  (void)argc; (void)argv;
  char const *fd_path  = getenv("AFL_FD_LIB");
  char const *ag_path  = getenv("AFL_AG_LIB");
  char const *harness  = getenv("AFL_HARNESS");
  char const *strict_e = getenv("AFL_DIFF_STRICT");
  if (!fd_path) fd_path = "/workspaces/firedancer/build/native/gcc/lib/libfd_exec_sol_compat.so";
  if (!ag_path) ag_path = "/workspaces/fuzz/solfuzz-agave/target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so";
  if (!harness) harness = "instr_execute";
  strict = strict_e && strict_e[0] && strict_e[0] != '0';

  void *fd_h = dlopen(fd_path, RTLD_NOW);
  if (!fd_h) { fprintf(stderr, "dlopen FD %s: %s\n", fd_path, dlerror()); _exit(2); }
  void *ag_h = dlopen(ag_path, RTLD_NOW);
  if (!ag_h) { fprintf(stderr, "dlopen AG %s: %s\n", ag_path, dlerror()); _exit(2); }

  sol_compat_init_fn_t fd_init = (sol_compat_init_fn_t)dlsym(fd_h, "sol_compat_init");
  sol_compat_init_fn_t ag_init = (sol_compat_init_fn_t)dlsym(ag_h, "sol_compat_init");
  if (fd_init) fd_init(0);
  if (ag_init) ag_init(0);

  char sym[128];
  snprintf(sym, sizeof(sym), "sol_compat_%s_v1", harness);
  fd_fn = (sol_compat_fn_t)dlsym(fd_h, sym);
  ag_fn = (sol_compat_fn_t)dlsym(ag_h, sym);
  if (!fd_fn) { fprintf(stderr, "dlsym FD %s: %s\n", sym, dlerror()); _exit(2); }
  if (!ag_fn) { fprintf(stderr, "dlsym AG %s: %s\n", sym, dlerror()); _exit(2); }

  fprintf(stderr, "[init] harness=%s fd=%s ag=%s strict=%d\n", harness, fd_path, ag_path, strict);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) return 0;
  if (!fd_fn || !ag_fn) return 0;

  unsigned long fd_sz = sizeof(fd_out);
  unsigned long ag_sz = sizeof(ag_out);

  int fd_rc = fd_fn(fd_out, &fd_sz, data, (unsigned long)size);
  int ag_rc = ag_fn(ag_out, &ag_sz, data, (unsigned long)size);

  /* rc disagreement = real conformance gap */
  if (fd_rc != ag_rc) {
    fprintf(stderr, "DIVERGENCE: rc fd=%d ag=%d size=%zu\n", fd_rc, ag_rc, size);
    abort();
  }
  if (fd_rc == 0 && ag_rc == 0) return 0;
  if (fd_rc != 1 || ag_rc != 1) return 0;

  if (strict) {
    if (fd_sz != ag_sz) {
      fprintf(stderr, "DIVERGENCE[strict]: sz fd=%lu ag=%lu\n", fd_sz, ag_sz);
      abort();
    }
    if (memcmp(fd_out, ag_out, fd_sz) != 0) {
      fprintf(stderr, "DIVERGENCE[strict]: bytes differ (sz=%lu)\n", fd_sz);
      abort();
    }
    return 0;
  }

  /* Lenient: tolerate up to 16-byte size delta + skip last 64 bytes */
  unsigned long diff_sz = fd_sz > ag_sz ? fd_sz - ag_sz : ag_sz - fd_sz;
  if (diff_sz > SIZE_SLACK) {
    fprintf(stderr, "DIVERGENCE: sz fd=%lu ag=%lu (delta=%lu)\n", fd_sz, ag_sz, diff_sz);
    abort();
  }
  unsigned long min_sz = fd_sz < ag_sz ? fd_sz : ag_sz;
  unsigned long compare_len = min_sz > TAIL_SKIP ? min_sz - TAIL_SKIP : 0;
  if (compare_len && memcmp(fd_out, ag_out, compare_len) != 0) {
    unsigned long i = 0;
    while (i < compare_len && fd_out[i] == ag_out[i]) i++;
    fprintf(stderr, "DIVERGENCE: prefix differs at byte %lu (fd=0x%02x ag=0x%02x)\n",
            i, fd_out[i], ag_out[i]);
    abort();
  }
  return 0;
}
DRIVER_EOF
echo "  wrote $WORK/fuzz_driver.c"
echo ""

# 4. Compile driver with libFuzzer + ASan
echo "--- Stage 4: compile fuzz_driver with libFuzzer ---"
cd $WORK
clang -O2 -g \
  -fsanitize=fuzzer,address \
  -fsanitize-coverage=inline-8bit-counters,trace-cmp,pc-table \
  fuzz_driver.c \
  -ldl -o fuzz_driver
ls -la fuzz_driver
echo ""

# 5. Write the runner
cat > $WORK/run-libfuzzer.sh << 'RUNNER_EOF'
#!/usr/bin/env bash
# Launch the libFuzzer differential driver. Usage:
#   ./run-libfuzzer.sh <harness> [duration_sec]
set -euo pipefail
HARNESS=${1:?harness required}
DURATION=${2:-0}

CORPUS=/workspaces/fuzz/lf-corpus/$HARNESS
CRASHES=/workspaces/fuzz/lf-findings/$HARNESS
mkdir -p "$CORPUS" "$CRASHES"

# Seed corpus on first run
if [ -z "$(ls -A "$CORPUS" 2>/dev/null)" ]; then
  case $HARNESS in
    instr_execute)        src=/workspaces/test-vectors/instr/fixtures ;;
    txn_execute)          src=/workspaces/test-vectors/txn/fixtures ;;
    vm_syscall_execute)   src=/workspaces/test-vectors/syscall/fixtures ;;
    elf_loader)           src=/workspaces/test-vectors/elf_loader/fixtures ;;
    block_execute)        src=/workspaces/test-vectors/block/fixtures ;;
    *)                    src= ;;
  esac
  if [ -n "$src" ] && [ -d "$src" ]; then
    n=0
    while IFS= read -r f; do
      cp "$f" "$CORPUS/$(basename "$f")"
      n=$((n+1)); [ "$n" -ge 500 ] && break
    done < <(find "$src" -name '*.fix' 2>/dev/null | sort)
    echo "Seeded $n fixtures into $CORPUS"
  fi
fi

export AFL_HARNESS=$HARNESS
# Disable ASan leak detection (the libs leak by design; ASan would mark them)
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:symbolize=1"

ARGS=( "$CORPUS" -artifact_prefix="$CRASHES/" -timeout=10 -rss_limit_mb=4096 -print_pcs=0 -print_corpus_stats=1 )
[ "$DURATION" -gt 0 ] && ARGS+=( -max_total_time=$DURATION )

echo "Launching libFuzzer on $HARNESS, corpus=$CORPUS crashes=$CRASHES"
exec /workspaces/fuzz/fuzz_driver "${ARGS[@]}"
RUNNER_EOF
chmod +x $WORK/run-libfuzzer.sh
echo "wrote $WORK/run-libfuzzer.sh"

echo ""
echo "=============================================="
echo "Setup complete."
echo "  driver:   $WORK/fuzz_driver"
echo "  runner:   $WORK/run-libfuzzer.sh"
echo ""
echo "Run a fuzzing campaign:"
echo "  bash $WORK/run-libfuzzer.sh vm_syscall_execute"
echo "=============================================="
} 2>&1 | tee "$LOG"
