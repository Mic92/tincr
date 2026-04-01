/*
 * Shim system.h for KAT generation.
 *
 * The vendored crypto in src/{chacha-poly1305,ed25519,nolegacy} pulls in
 * "../system.h" which transitively wants meson-generated config (have.h).
 * We compile with -Ikat so that <../system.h> resolves to this file instead,
 * giving the crypto code just enough libc to build standalone.
 *
 * The crypto sources themselves are pure computation — no syscalls, no
 * platform code — so this shim is the entire porting surface.
 */
#ifndef KAT_SYSTEM_H
#define KAT_SYSTEM_H

/* ge.c defines a static `select()` which collides with libc's select(2)
   that <stdlib.h> drags in transitively. Suppress that one header before
   including anything. */
#define _SYS_SELECT_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stddef.h>

/* tinc's have.h gates alloca; nolegacy/prf.c uses it unconditionally. */
#ifdef _WIN32
#  include <malloc.h>
#else
#  include <alloca.h>
#endif

/* Attribute macros tinc sprinkles on declarations. No-ops are fine here. */
#define ATTR_MALLOC
#define ATTR_DEALLOCATOR(x)
#define ATTR_FORMAT(a,b,c)
#define ATTR_NONNULL
#define PACKED(decl) decl __attribute__((__packed__))
#define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/* xalloc.h symbols used by chacha-poly1305.c. Bodies live in gen_kat.c. */
void *xzalloc(size_t n);
void  xzfree(void *p, size_t n);

/* utils.h symbols used by chacha-poly1305.c (tag comparison). */
bool mem_eq(const void *a, const void *b, size_t n);

/* Some sources include "../utils.h" / "../xalloc.h" directly. We don't ship
   shims for those — instead we tell cc to remap them to this file via
   -include or the makefile sed. See kat/Makefile. */

#endif /* KAT_SYSTEM_H */
