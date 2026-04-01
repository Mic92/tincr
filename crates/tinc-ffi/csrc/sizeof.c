/*
 * The one TU that includes the real sptps.h.
 *
 * shim.c treats sptps_t as opaque, but it has to allocate one. Rather
 * than hardcoding sizeof (which differs across builds: ecdsa_t is a
 * different struct under OpenSSL/gcrypt) we let the compiler tell us.
 *
 * This file IS compiled with -include shim.h (it needs PACKED/STATIC_ASSERT/
 * the libc headers) and WITH the guard-define suppression. The guard for
 * sptps.h itself is left undefined so the struct body is visible. Linker
 * stitches the answer back to shim.c.
 *
 * To make sptps.h compile we need TINC_ECDSA_INTERNAL set and an ecdsa_t
 * defined before the include — sptps.h's `ecdsa_t *mykey` field needs
 * the type to exist. The pointer doesn't care about the layout, so a
 * dummy suffices.
 */

/* shim.h (force-included) already gave us `typedef struct ecdsa ecdsa_t`
   — that's enough for the sptps_t pointer field. ecdh.h is unsuppressed
   so its forward typedef comes through normally. */

/* sptps.h pulls chacha-poly1305.h which is self-contained (no system.h).
   It supplies CHACHA_POLY1305_KEYLEN and the ctx forward typedef — both
   needed for the sptps_key_t union and the cipher pointers. We let it
   through; the guard-defines we set don't touch CHACHA_POLY1305_H. */

#include "../../../src/sptps.h"

const size_t SPTPS_T_SIZE = sizeof(sptps_t);
