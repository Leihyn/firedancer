/* Differential harness runner for Firedancer v1.0 hunt.
 *
 * Loads both libfd_exec_sol_compat.so (Firedancer-side) and libsolfuzz_agave.so
 * (Agave-side), calls each with the same protobuf input, and compares the
 * effect output. Any byte-level divergence indicates a conformance bug ==
 * potential bank-hash-mismatch == High severity per Immunefi rewards table.
 *
 * Build:
 *   gcc -O2 -Wall diff_runner.c -ldl -o diff_runner
 *
 * Run:
 *   LD_LIBRARY_PATH=. ./diff_runner <harness> <input.bin>
 *
 *   harness: instr_execute | txn_execute | vm_interp | vm_syscall_execute |
 *            elf_loader | shred_parse | pack_compute_budget | block_execute |
 *            txn_cost | gossip_decode
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

/* sol_compat_*_v1 ABI signature, per solfuzz-agave & firedancer harnesses:
 *   int fn( void * out_ptr, ulong * out_psz, void const * in_ptr, ulong in_sz );
 * Returns 1 on success (out written), 0 otherwise.
 */
typedef int (*sol_compat_fn_t)( void *, unsigned long *, void const *, unsigned long );
typedef void (*sol_compat_init_fn_t)( int );
typedef void (*sol_compat_fini_fn_t)( void );

static void *
must_dlsym( void * handle, char const * sym ) {
  void * p = dlsym( handle, sym );
  if( !p ) { fprintf( stderr, "dlsym(%s): %s\n", sym, dlerror() ); exit( 2 ); }
  return p;
}

static void *
must_dlopen( char const * path ) {
  void * h = dlopen( path, RTLD_NOW | RTLD_LOCAL );
  if( !h ) { fprintf( stderr, "dlopen(%s): %s\n", path, dlerror() ); exit( 2 ); }
  return h;
}

static void *
slurp( char const * path, unsigned long * out_sz ) {
  FILE * f = fopen( path, "rb" );
  if( !f ) { perror( path ); exit( 3 ); }
  struct stat st;
  if( fstat( fileno(f), &st ) ) { perror( "fstat" ); exit( 3 ); }
  void * buf = malloc( (size_t)st.st_size );
  if( !buf ) { fprintf( stderr, "oom\n" ); exit( 3 ); }
  if( fread( buf, 1, (size_t)st.st_size, f ) != (size_t)st.st_size ) { perror( "fread" ); exit( 3 ); }
  fclose( f );
  *out_sz = (unsigned long)st.st_size;
  return buf;
}

int
main( int argc, char ** argv ) {
  if( argc != 3 ) {
    fprintf( stderr, "usage: %s <harness> <input.bin>\n", argv[0] );
    fprintf( stderr, "  harness: instr_execute, txn_execute, vm_interp, vm_syscall_execute,\n" );
    fprintf( stderr, "           elf_loader, shred_parse, pack_compute_budget, block_execute,\n" );
    fprintf( stderr, "           txn_cost, gossip_decode\n" );
    return 1;
  }
  char const * harness  = argv[1];
  char const * inp_path = argv[2];

  char fd_lib[] = "build/native/gcc/lib/libfd_exec_sol_compat.so";
  char ag_lib[] = "/workspaces/fuzz/solfuzz-agave/target/release/libsolfuzz_agave.so";

  void * fd_h = must_dlopen( fd_lib );
  void * ag_h = must_dlopen( ag_lib );

  /* Build symbol name from harness string. */
  char sym[128];
  snprintf( sym, sizeof(sym), "sol_compat_%s_v1", harness );

  sol_compat_init_fn_t fd_init = (sol_compat_init_fn_t)must_dlsym( fd_h, "sol_compat_init" );
  sol_compat_init_fn_t ag_init = (sol_compat_init_fn_t)must_dlsym( ag_h, "sol_compat_init" );
  sol_compat_fini_fn_t fd_fini = (sol_compat_fini_fn_t)must_dlsym( fd_h, "sol_compat_fini" );
  sol_compat_fini_fn_t ag_fini = (sol_compat_fini_fn_t)must_dlsym( ag_h, "sol_compat_fini" );
  sol_compat_fn_t      fd_fn   = (sol_compat_fn_t)must_dlsym( fd_h, sym );
  sol_compat_fn_t      ag_fn   = (sol_compat_fn_t)must_dlsym( ag_h, sym );

  fd_init( 0 );
  ag_init( 0 );

  unsigned long in_sz = 0;
  void * in_buf = slurp( inp_path, &in_sz );

  /* Allocate generous output buffers. solfuzz outputs are typically <1MB.  */
  unsigned long const OUT_CAP = 16UL * 1024UL * 1024UL;
  void * fd_out = malloc( OUT_CAP );
  void * ag_out = malloc( OUT_CAP );
  unsigned long fd_sz = OUT_CAP;
  unsigned long ag_sz = OUT_CAP;

  int fd_rc = fd_fn( fd_out, &fd_sz, in_buf, in_sz );
  int ag_rc = ag_fn( ag_out, &ag_sz, in_buf, in_sz );

  printf( "harness=%s input=%s in_sz=%lu\n", harness, inp_path, in_sz );
  printf( "fd:    rc=%d out_sz=%lu\n", fd_rc, fd_sz );
  printf( "agave: rc=%d out_sz=%lu\n", ag_rc, ag_sz );

  int divergent = 0;
  if( fd_rc != ag_rc ) {
    printf( "DIVERGENCE: rc differs (%d vs %d)\n", fd_rc, ag_rc );
    divergent = 1;
  } else if( fd_rc == 1 && ag_rc == 1 ) {
    if( fd_sz != ag_sz ) {
      printf( "DIVERGENCE: out_sz differs (%lu vs %lu)\n", fd_sz, ag_sz );
      divergent = 1;
    } else if( memcmp( fd_out, ag_out, fd_sz ) != 0 ) {
      printf( "DIVERGENCE: out bytes differ (size=%lu)\n", fd_sz );
      /* find first differing byte */
      for( unsigned long i=0; i<fd_sz; i++ ) {
        if( ((unsigned char *)fd_out)[i] != ((unsigned char *)ag_out)[i] ) {
          printf( "  first diff at byte %lu: fd=0x%02x ag=0x%02x\n", i,
                  ((unsigned char *)fd_out)[i], ((unsigned char *)ag_out)[i] );
          break;
        }
      }
      divergent = 1;
    }
  }

  if( !divergent ) printf( "MATCH\n" );

  fd_fini();
  ag_fini();
  free( in_buf );
  free( fd_out );
  free( ag_out );
  dlclose( fd_h );
  dlclose( ag_h );
  return divergent ? 100 : 0;
}
