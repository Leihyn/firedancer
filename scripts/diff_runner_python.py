#!/usr/bin/env python3
"""
Subprocess-isolated differential runner for Firedancer ↔ Agave conformance.

This is the simpler alternative to libFuzzer that we fall back to after
hitting:
  - AFL: blind, 0 coverage, no novel paths discovered
  - libFuzzer + ASan: process-crashes on harness FD_TEST aborts even with
    ignore_crashes (those abort the whole process before libFuzzer's
    handler can save the input)
  - libFuzzer + fork: segfaults during fork (sancov shadow-mem collision)

Approach: we run each input in a forked child via subprocess. The child
loads both .so files via dlopen, calls each harness, and writes either:
  - "MATCH"      to stdout  → no divergence
  - "RC_DIFF:fd_rc=X ag_rc=Y"
  - "SZ_DIFF:fd_sz=X ag_sz=Y delta=Z"
  - "BYTE_DIFF:byte=N fd=0x.. ag=0x.."
  - "ABORT" if either side aborted (parent reads child rc != 0)

The parent reads stdout/rc per child, classifies, records divergent
inputs to a findings dir. Children dying from FD_TEST aborts are normal
and don't kill the parent.

Mutation: starts from the test-vectors corpus. For each iteration:
  - Pick a random fixture
  - Apply random byte-level mutations (flip, insert, delete, splice)
  - Run differential
  - Save if divergent

Usage:
    python3 diff_runner_python.py vm_syscall_execute --duration 3600

Output: /workspaces/fuzz/py-findings/<harness>/{divergent,abort,error}/
"""

import argparse
import ctypes
import os
import random
import shutil
import subprocess
import sys
import time
from pathlib import Path


FD_LIB = "/workspaces/firedancer/build/linux/clang/x86_64/lib/libfd_exec_sol_compat.so"
AG_LIB = "/workspaces/fuzz/solfuzz-agave/target/x86_64-unknown-linux-gnu/release/libsolfuzz_agave.so"

# We compile a tiny standalone C runner once; it dlopens both libs in a child
# process and prints the diff. Standalone so a harness abort doesn't kill us.
CHILD_RUNNER_SRC = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

typedef int (*fn_t)(void *, unsigned long *, void const *, unsigned long);
typedef void (*init_t)(int);

static unsigned char fd_out[16UL * 1024UL * 1024UL];
static unsigned char ag_out[16UL * 1024UL * 1024UL];

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s <harness> <input-file> [fd_lib] [ag_lib]\n", argv[0]);
        return 1;
    }
    char const *harness = argv[1];
    char const *input_path = argv[2];
    char const *fd_path = getenv("FD_LIB");
    char const *ag_path = getenv("AG_LIB");
    if (!fd_path) fd_path = argv[3];
    if (!ag_path && argc > 4) ag_path = argv[4];

    /* Load input */
    FILE *f = fopen(input_path, "rb");
    if (!f) { fprintf(stderr, "open input: %s\n", strerror(errno)); return 2; }
    fseek(f, 0, SEEK_END);
    long file_sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *file_buf = malloc(file_sz > 0 ? file_sz : 1);
    if (file_sz > 0 && fread(file_buf, 1, file_sz, f) != (size_t)file_sz) {
        fprintf(stderr, "read input failed\n"); return 3;
    }
    fclose(f);

    /* Unwrap FixtureContainer if present.
     *
     * test-vectors fixtures are wrapped: field 1 (tag=0x0a) = metadata,
     * field 2 (tag=0x12) = the actual harness input. Find tag 0x12 and
     * use its inner bytes.
     *
     * If we don't see a container, treat raw input as the payload. */
    unsigned char *buf = file_buf;
    long sz = file_sz;
    {
        long off = 0;
        int found_inner = 0;
        while (off < file_sz) {
            unsigned char tag = file_buf[off++];
            /* Decode varint length */
            unsigned long len = 0;
            unsigned shift = 0;
            while (off < file_sz && shift < 64) {
                unsigned char b = file_buf[off++];
                len |= ((unsigned long)(b & 0x7F)) << shift;
                if ((b & 0x80) == 0) break;
                shift += 7;
            }
            if (off + (long)len > file_sz) break;
            if (tag == 0x12) {  /* field 2, wire type 2 (length-delimited) */
                buf = file_buf + off;
                sz = (long)len;
                found_inner = 1;
                break;
            }
            off += (long)len;
        }
        (void)found_inner;
    }

    /* dlopen both libs */
    void *fd_h = dlopen(fd_path, RTLD_NOW);
    if (!fd_h) { fprintf(stderr, "dlopen FD: %s\n", dlerror()); return 4; }
    void *ag_h = dlopen(ag_path, RTLD_NOW);
    if (!ag_h) { fprintf(stderr, "dlopen AG: %s\n", dlerror()); return 5; }

    init_t fd_init = (init_t)dlsym(fd_h, "sol_compat_init");
    init_t ag_init = (init_t)dlsym(ag_h, "sol_compat_init");
    if (fd_init) fd_init(0);
    if (ag_init) ag_init(0);

    char sym[128];
    snprintf(sym, sizeof sym, "sol_compat_%s_v1", harness);
    fn_t fd_fn = (fn_t)dlsym(fd_h, sym);
    fn_t ag_fn = (fn_t)dlsym(ag_h, sym);
    if (!fd_fn || !ag_fn) {
        fprintf(stderr, "dlsym %s missing\n", sym);
        return 6;
    }

    unsigned long fd_sz = sizeof fd_out;
    unsigned long ag_sz = sizeof ag_out;
    int fd_rc = fd_fn(fd_out, &fd_sz, buf, (unsigned long)sz);
    int ag_rc = ag_fn(ag_out, &ag_sz, buf, (unsigned long)sz);

    /* Compare and emit a single line on stdout */
    if (fd_rc != ag_rc) {
        printf("RC_DIFF fd_rc=%d ag_rc=%d\n", fd_rc, ag_rc);
        return 0;
    }
    if (fd_rc != 1) { printf("MATCH\n"); return 0; }

    if (fd_sz != ag_sz) {
        long delta = (long)fd_sz - (long)ag_sz;
        if (delta < 0) delta = -delta;
        if (delta > 16) {
            printf("SZ_DIFF fd_sz=%lu ag_sz=%lu\n", fd_sz, ag_sz);
            return 0;
        }
    }
    unsigned long min_sz = fd_sz < ag_sz ? fd_sz : ag_sz;
    unsigned long compare_len = min_sz > 64 ? min_sz - 64 : 0;
    if (compare_len && memcmp(fd_out, ag_out, compare_len) != 0) {
        unsigned long i = 0;
        while (i < compare_len && fd_out[i] == ag_out[i]) i++;
        printf("BYTE_DIFF byte=%lu fd=0x%02x ag=0x%02x\n", i, fd_out[i], ag_out[i]);
        return 0;
    }

    printf("MATCH\n");
    return 0;
}
"""


def ensure_child_runner(workdir: Path) -> Path:
    """Compile child_runner.c if not already present. Returns path to binary."""
    src = workdir / "child_runner.c"
    bin_path = workdir / "child_runner"
    if not bin_path.exists() or src.stat().st_mtime > bin_path.stat().st_mtime:
        src.write_text(CHILD_RUNNER_SRC)
        rc = subprocess.run(
            ["gcc", "-O2", "-Wall", str(src), "-ldl", "-o", str(bin_path)],
            check=False, capture_output=True, text=True,
        )
        if rc.returncode != 0:
            print("compile child_runner failed:", rc.stderr, file=sys.stderr)
            sys.exit(1)
    return bin_path


def mutate_bytes(data: bytes, max_ops: int = 8) -> bytes:
    """Apply 1..max_ops byte-level mutations."""
    out = bytearray(data)
    if not out:
        return bytes(os.urandom(random.randint(1, 32)))
    n_ops = random.randint(1, max_ops)
    for _ in range(n_ops):
        op = random.randint(0, 5)
        if op == 0 and out:  # flip a byte
            i = random.randint(0, len(out) - 1)
            out[i] = (out[i] + random.randint(1, 255)) & 0xFF
        elif op == 1 and out:  # set byte to interesting value
            i = random.randint(0, len(out) - 1)
            out[i] = random.choice([0, 1, 0x7F, 0x80, 0xFF])
        elif op == 2:  # insert byte
            i = random.randint(0, len(out))
            out.insert(i, random.randint(0, 255))
        elif op == 3 and out:  # delete byte
            i = random.randint(0, len(out) - 1)
            del out[i]
        elif op == 4 and len(out) >= 4:  # zero a 4-byte int
            i = random.randint(0, len(out) - 4)
            out[i:i+4] = b"\x00\x00\x00\x00"
        elif op == 5 and len(out) >= 4:  # max-out a 4-byte int
            i = random.randint(0, len(out) - 4)
            out[i:i+4] = b"\xff\xff\xff\xff"
    return bytes(out)


def run_one(child_bin: Path, harness: str, input_path: Path,
            fd_lib: str, ag_lib: str, timeout: float = 10.0) -> tuple[str, str]:
    """Returns (status, detail). Status one of:
       MATCH | RC_DIFF | SZ_DIFF | BYTE_DIFF | ABORT | TIMEOUT | ERROR"""
    try:
        proc = subprocess.run(
            [str(child_bin), harness, str(input_path), fd_lib, ag_lib],
            capture_output=True, text=True, timeout=timeout,
            env={**os.environ, "FD_LIB": fd_lib, "AG_LIB": ag_lib,
                 "FD_LOG_PATH": "", "FD_LOG_LEVEL_LOGFILE": "0", "FD_LOG_LEVEL_STDERR": "0"},
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", ""
    except Exception as e:
        return "ERROR", str(e)

    if proc.returncode != 0:
        # Child aborted (e.g. FD_TEST). Not a divergence — just a harness assert.
        return "ABORT", f"rc={proc.returncode}"

    out = proc.stdout.strip()
    if out.startswith("MATCH"):
        return "MATCH", ""
    elif out.startswith("RC_DIFF"):
        return "RC_DIFF", out
    elif out.startswith("SZ_DIFF"):
        return "SZ_DIFF", out
    elif out.startswith("BYTE_DIFF"):
        return "BYTE_DIFF", out
    return "ERROR", out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("harness", help="harness name e.g. vm_syscall_execute")
    ap.add_argument("--corpus", default=None, help="seed corpus dir")
    ap.add_argument("--findings", default=None, help="output findings dir")
    ap.add_argument("--duration", type=int, default=0, help="seconds (0 = forever)")
    ap.add_argument("--max-iters", type=int, default=0, help="iterations cap (0 = unlimited)")
    ap.add_argument("--fd-lib", default=FD_LIB)
    ap.add_argument("--ag-lib", default=AG_LIB)
    ap.add_argument("--workdir", default="/workspaces/fuzz/py-runner")
    args = ap.parse_args()

    workdir = Path(args.workdir)
    workdir.mkdir(parents=True, exist_ok=True)
    child_bin = ensure_child_runner(workdir)

    corpus_dir = Path(args.corpus or f"/workspaces/fuzz/lf-corpus/{args.harness}")
    findings_dir = Path(args.findings or f"/workspaces/fuzz/py-findings/{args.harness}")
    for sub in ("divergent", "abort", "error"):
        (findings_dir / sub).mkdir(parents=True, exist_ok=True)

    seeds = sorted(p for p in corpus_dir.glob("*") if p.is_file())
    if not seeds:
        print(f"ERROR: corpus {corpus_dir} is empty. Seed it first.", file=sys.stderr)
        sys.exit(1)
    print(f"loaded {len(seeds)} seeds from {corpus_dir}", flush=True)

    counts = {"MATCH": 0, "RC_DIFF": 0, "SZ_DIFF": 0, "BYTE_DIFF": 0,
              "ABORT": 0, "TIMEOUT": 0, "ERROR": 0}
    start = time.monotonic()
    iters = 0
    last_print = start
    tmp_input = workdir / "current_input.bin"

    while True:
        if args.duration > 0 and time.monotonic() - start > args.duration:
            break
        if args.max_iters > 0 and iters >= args.max_iters:
            break

        seed = random.choice(seeds)
        original = seed.read_bytes()
        mutated = mutate_bytes(original)
        tmp_input.write_bytes(mutated)

        status, detail = run_one(child_bin, args.harness, tmp_input,
                                  args.fd_lib, args.ag_lib)
        counts[status] += 1
        iters += 1

        # Save divergent / interesting inputs
        if status in ("RC_DIFF", "SZ_DIFF", "BYTE_DIFF"):
            sub = "divergent"
            name = f"{status}_{iters:08d}_{seed.name}"
            (findings_dir / sub / name).write_bytes(mutated)
            print(f"  [iter {iters}] {status}: {detail} (saved {name})", flush=True)
        elif status == "ABORT":
            # Save first 100 aborts only — they tend to all be the same
            # FD_TEST hits at the harness boundary
            if counts["ABORT"] <= 100:
                name = f"abort_{iters:08d}_{seed.name}"
                (findings_dir / "abort" / name).write_bytes(mutated)

        # Progress every 5 seconds
        now = time.monotonic()
        if now - last_print >= 5.0:
            elapsed = int(now - start)
            rate = iters / max(elapsed, 1)
            print(f"  [t={elapsed}s n={iters}] {dict(counts)} ({rate:.1f}/s)", flush=True)
            last_print = now

    elapsed = int(time.monotonic() - start)
    print(f"\n=== done in {elapsed}s, {iters} iterations ===")
    for k, v in counts.items():
        print(f"  {k}: {v}")
    print(f"\nFindings: {findings_dir}")


if __name__ == "__main__":
    main()
