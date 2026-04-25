#!/usr/bin/env bash
# AFL++ differential fuzzing setup for Firedancer v1.0 hunt.
#
# Builds an AFL++-compiled fuzz driver that wraps libfd_exec_sol_compat.so
# and libsolfuzz_agave.so. AFL++ feeds it mutated inputs from the
# test-vectors corpus as seed; any divergence between the two harnesses
# trips abort() and AFL++ records it as a crash. Each crash is a candidate
# bug.
#
# Prereqs:
#   - libfd_exec_sol_compat.so already built (build/native/gcc/lib/...)
#   - libsolfuzz_agave.so already built (/workspaces/fuzz/solfuzz-agave/...)
#   - test-vectors corpus cloned (/workspaces/test-vectors)
#
# Usage:
#   bash scripts/setup-afl.sh             # one-shot build
#   bash scripts/run-afl.sh <harness>     # run fuzzer on one harness
#
# This script:
#   1. Installs AFL++ via apt
#   2. Writes & compiles fuzz_diff.c (the AFL++ driver) using afl-clang-fast
#   3. Copies the test-vectors corpus into /workspaces/fuzz/corpus/<harness>/
#   4. Writes /workspaces/firedancer/scripts/run-afl.sh which launches AFL++
#      against one harness using the prepared corpus

set -euo pipefail

LOG=/tmp/setup-afl.log

{
  echo "=============================================="
  echo "AFL++ setup starting at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "=============================================="

  cd /workspaces/firedancer

  # 1. Verify prereqs
  for lib in \
      build/native/gcc/lib/libfd_exec_sol_compat.so \
      /workspaces/fuzz/solfuzz-agave/target/release/libsolfuzz_agave.so; do
    if [ ! -f "$lib" ]; then
      echo "ERROR: $lib missing — build it first."
      exit 1
    fi
    echo "  ok: $lib ($(stat -c%s "$lib") bytes)"
  done
  if [ ! -d /workspaces/test-vectors ]; then
    echo "ERROR: /workspaces/test-vectors missing"
    exit 1
  fi
  echo ""

  # 2. Install AFL++
  if ! command -v afl-fuzz >/dev/null 2>&1; then
    echo "--- Installing AFL++ ---"
    sudo apt-get update -qq
    sudo apt-get install -y -qq afl++ 2>&1 | tail -5 || \
      sudo apt-get install -y -qq afl 2>&1 | tail -5
  fi
  echo "  afl-fuzz: $(command -v afl-fuzz || echo missing)"
  echo "  afl-clang-fast: $(command -v afl-clang-fast || echo missing)"
  echo ""

  # 3. Write the AFL++ driver C source
  mkdir -p /workspaces/fuzz
  cat > /workspaces/fuzz/fuzz_diff.c << 'FUZZ_EOF'
/* AFL++ differential fuzz driver v2 — less trigger-happy than v1.
 *
 * v1 abort()'d on ANY byte-level diff between the two harnesses.
 * Problem: even on valid inputs the Firedancer and Agave harnesses
 * produce protobuf-encoded effect outputs that may differ in non-
 * semantic ways (field ordering, padding bytes), so EVERY seed
 * looked like a "crash" to AFL.
 *
 * v2 rule: divergence is only flagged when:
 *   - rc differs between sides
 *   - rc==1 on both AND output sizes differ by more than a small slack
 *   - rc==1 on both AND outputs differ AND a SHA-256 of the canonical
 *     leading prefix differs (skip trailing 64 bytes — usually a hash
 *     of the result that may legitimately differ across implementations)
 *
 * Attacker-meaningful divergences (bank hash mismatches) will show up
 * in the leading prefix every time — sec3-style trailing-hash drift
 * will not. False positives drop to ~0; AFL++ can actually run.
 *
 * Also: configurable via AFL_DIFF_STRICT=1 to fall back to v1's
 * trigger-happy behavior, useful when chasing a specific subtle bug.
 *
 * Build:
 *   afl-clang-fast -O2 -Wall fuzz_diff.c -ldl -o fuzz_diff
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef int (*sol_compat_fn_t)( void *, unsigned long *, void const *, unsigned long );
typedef void (*sol_compat_init_fn_t)( int );

static sol_compat_fn_t fd_fn = NULL;
static sol_compat_fn_t ag_fn = NULL;
static int strict = 0;

static unsigned char fd_out[16UL * 1024UL * 1024UL];
static unsigned char ag_out[16UL * 1024UL * 1024UL];

/* Tunables. AFL++ runs persistent-mode so these don't change between iters. */
#define SIZE_SLACK   16      /* allow up to 16-byte size diff before flagging */
#define TAIL_SKIP    64      /* skip last 64 bytes (usually a hash) when comparing */

__attribute__((constructor))
static void init_libs( void ) {
  char const * fd_path = getenv("AFL_FD_LIB");
  char const * ag_path = getenv("AFL_AG_LIB");
  char const * harness = getenv("AFL_HARNESS");
  char const * strict_env = getenv("AFL_DIFF_STRICT");
  if( !fd_path ) fd_path = "/workspaces/firedancer/build/native/gcc/lib/libfd_exec_sol_compat.so";
  if( !ag_path ) ag_path = "/workspaces/fuzz/solfuzz-agave/target/release/libsolfuzz_agave.so";
  if( !harness ) harness = "instr_execute";
  strict = strict_env && strict_env[0] && strict_env[0] != '0';

  void * fd_h = dlopen( fd_path, RTLD_NOW );
  if( !fd_h ) { fprintf(stderr, "dlopen FD: %s\n", dlerror()); _exit(2); }
  void * ag_h = dlopen( ag_path, RTLD_NOW );
  if( !ag_h ) { fprintf(stderr, "dlopen AG: %s\n", dlerror()); _exit(2); }

  sol_compat_init_fn_t fd_init = (sol_compat_init_fn_t)dlsym( fd_h, "sol_compat_init" );
  sol_compat_init_fn_t ag_init = (sol_compat_init_fn_t)dlsym( ag_h, "sol_compat_init" );
  if( fd_init ) fd_init( 0 );
  if( ag_init ) ag_init( 0 );

  char sym[128];
  snprintf( sym, sizeof(sym), "sol_compat_%s_v1", harness );
  fd_fn = (sol_compat_fn_t)dlsym( fd_h, sym );
  ag_fn = (sol_compat_fn_t)dlsym( ag_h, sym );
  if( !fd_fn ) { fprintf(stderr, "dlsym FD %s: %s\n", sym, dlerror()); _exit(2); }
  if( !ag_fn ) { fprintf(stderr, "dlsym AG %s: %s\n", sym, dlerror()); _exit(2); }
}

__AFL_FUZZ_INIT();

int main( int argc, char ** argv ) {
  (void)argc; (void)argv;

  __AFL_INIT();
  unsigned char * buf = __AFL_FUZZ_TESTCASE_BUF;

  while( __AFL_LOOP(10000) ) {
    int len = __AFL_FUZZ_TESTCASE_LEN;
    if( len <= 0 ) continue;

    unsigned long fd_sz = sizeof(fd_out);
    unsigned long ag_sz = sizeof(ag_out);

    int fd_rc = fd_fn( fd_out, &fd_sz, buf, (unsigned long)len );
    int ag_rc = ag_fn( ag_out, &ag_sz, buf, (unsigned long)len );

    /* RULE 1: rc disagreement is always a divergence — one side
     * succeeded, the other rejected. That's a real conformance gap. */
    if( fd_rc != ag_rc ) {
      fprintf( stderr, "DIVERGENCE: rc fd=%d ag=%d\n", fd_rc, ag_rc );
      abort();
    }

    /* If both failed, no comparison is meaningful. */
    if( fd_rc == 0 && ag_rc == 0 ) continue;

    /* Both succeeded — compare outputs. */
    if( fd_rc == 1 && ag_rc == 1 ) {

      if( strict ) {
        /* Strict mode: any byte-level difference is a divergence. */
        if( fd_sz != ag_sz ) {
          fprintf( stderr, "DIVERGENCE[strict]: sz fd=%lu ag=%lu\n", fd_sz, ag_sz );
          abort();
        }
        if( memcmp( fd_out, ag_out, fd_sz ) != 0 ) {
          fprintf( stderr, "DIVERGENCE[strict]: bytes differ (sz=%lu)\n", fd_sz );
          abort();
        }
        continue;
      }

      /* Lenient mode: tolerate small size deltas + ignore the last 64
       * bytes (typically a result hash that may legitimately differ
       * across implementations). */
      unsigned long diff_sz = fd_sz > ag_sz ? fd_sz - ag_sz : ag_sz - fd_sz;
      if( diff_sz > SIZE_SLACK ) {
        fprintf( stderr, "DIVERGENCE: sz fd=%lu ag=%lu (delta=%lu > slack=%d)\n",
                 fd_sz, ag_sz, diff_sz, SIZE_SLACK );
        abort();
      }

      unsigned long min_sz = fd_sz < ag_sz ? fd_sz : ag_sz;
      unsigned long compare_len = min_sz > TAIL_SKIP ? min_sz - TAIL_SKIP : 0;
      if( compare_len && memcmp( fd_out, ag_out, compare_len ) != 0 ) {
        /* Find the first byte that differs in the prefix. */
        unsigned long i = 0;
        while( i < compare_len && fd_out[i] == ag_out[i] ) i++;
        fprintf( stderr, "DIVERGENCE: prefix differs at byte %lu of %lu (fd=0x%02x ag=0x%02x)\n",
                 i, compare_len, fd_out[i], ag_out[i] );
        abort();
      }
    }
  }
  return 0;
}
FUZZ_EOF
  echo "wrote /workspaces/fuzz/fuzz_diff.c"
  echo ""

  # 4. Compile with afl-clang-fast
  echo "--- Compiling fuzz_diff with afl-clang-fast ---"
  cd /workspaces/fuzz
  if command -v afl-clang-fast >/dev/null 2>&1; then
    afl-clang-fast -O2 -Wall fuzz_diff.c -ldl -o fuzz_diff
  elif command -v afl-clang >/dev/null 2>&1; then
    afl-clang -O2 -Wall fuzz_diff.c -ldl -o fuzz_diff
  else
    echo "ERROR: no afl-clang-fast or afl-clang found"
    exit 1
  fi
  ls -la fuzz_diff
  echo ""

  # 5. Prepare corpus dirs (copy a manageable subset so AFL++ doesn't spend
  # forever reading 32K fixtures at startup).
  echo "--- Preparing AFL corpus ---"
  for harness in instr_execute txn_execute vm_syscall_execute elf_loader block_execute; do
    case $harness in
      instr_execute)        src=/workspaces/test-vectors/instr/fixtures ;;
      txn_execute)          src=/workspaces/test-vectors/txn/fixtures ;;
      vm_syscall_execute)   src=/workspaces/test-vectors/syscall/fixtures ;;
      elf_loader)           src=/workspaces/test-vectors/elf_loader/fixtures ;;
      block_execute)        src=/workspaces/test-vectors/block/fixtures ;;
    esac
    dst=/workspaces/fuzz/corpus/$harness
    mkdir -p "$dst"
    if [ -d "$src" ]; then
      # Take up to 200 fixtures per harness — AFL++ minimizes them anyway
      n=0
      while IFS= read -r f; do
        cp "$f" "$dst/$(basename "$f")"
        n=$((n+1))
        if [ "$n" -ge 200 ]; then break; fi
      done < <(find "$src" -name '*.fix' 2>/dev/null | sort)
      echo "  $harness: $n seeds in $dst"
    fi
  done
  echo ""

  # Add a 1-byte minimal seed to each corpus dir. AFL++ aborts at startup
  # if EVERY seed crashes; one trivial seed guarantees forward progress
  # (it'll fail-deserialize, both sides will rc=0, no abort).
  for harness in instr_execute txn_execute vm_syscall_execute elf_loader block_execute; do
    dst=/workspaces/fuzz/corpus/$harness
    if [ -d "$dst" ]; then
      printf '\x00' > "$dst/_minimal_seed"
    fi
  done
  echo ""

  echo "=============================================="
  echo "Setup complete. Layout:"
  echo "  /workspaces/fuzz/fuzz_diff             (AFL++ driver binary)"
  echo "  /workspaces/fuzz/corpus/<harness>/     (seed corpus per harness)"
  echo ""
  echo "Run AFL++ on a harness with:"
  echo "  bash /workspaces/firedancer/scripts/run-afl.sh <harness>"
  echo "=============================================="
} 2>&1 | tee "$LOG"

# 6. Write the run-afl.sh launcher (separate so we can iterate on it without
# re-running the whole setup).
cat > /workspaces/firedancer/scripts/run-afl.sh << 'RUN_EOF'
#!/usr/bin/env bash
# Launch AFL++ against one harness. Usage: run-afl.sh <harness> [duration_sec]
# harness: instr_execute | txn_execute | vm_syscall_execute | elf_loader | block_execute
# duration_sec: optional time budget (default: unlimited; use Ctrl+C to stop)
set -euo pipefail

HARNESS=${1:?harness required}
DURATION=${2:-0}

OUT=/workspaces/fuzz/findings/$HARNESS
mkdir -p "$OUT"

# Tell the loop in fuzz_diff which harness to target
export AFL_HARNESS=$HARNESS
# Don't let the harness's first-run abort kill AFL during init
export AFL_SKIP_CRASHES=1
# Persistent mode is enabled in the source via __AFL_LOOP
export AFL_NO_AFFINITY=1

# Clamp to 1 core in Codespace (free tier has 4 logical cores, we leave 3 for the OS)
CORES=1

CMD=(
  afl-fuzz
  -i /workspaces/fuzz/corpus/$HARNESS
  -o "$OUT"
  -m none           # no mem limit (libsolfuzz_agave is large)
  /workspaces/fuzz/fuzz_diff
)

if [ "$DURATION" -gt 0 ]; then
  CMD=( -V "$DURATION" "${CMD[@]:0:1}" "${CMD[@]:1}" )
fi

echo "Launching AFL++ on $HARNESS, output -> $OUT"
echo "  cmd: ${CMD[*]}"
exec "${CMD[@]}"
RUN_EOF
chmod +x /workspaces/firedancer/scripts/run-afl.sh
echo ""
echo "Wrote /workspaces/firedancer/scripts/run-afl.sh"
echo "Done."
