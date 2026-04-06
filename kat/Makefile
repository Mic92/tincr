# Build the KAT generator and emit vectors.
#
# We compile the vendored crypto sources directly, but suppress the real
# tinc headers (system.h, utils.h, xalloc.h, prf.h) by predefining their
# include guards. Our shim system.h is force-included to provide the few
# symbols those sources actually use.
#
# This is fragile by design: if upstream renames a guard, this breaks
# loudly at compile time, which is exactly when we want to know.

CC      ?= cc
CFLAGS  ?= -O0 -g -Wall

# Guard defines: make the real headers turn into no-ops.
SUPPRESS = \
	-DTINC_SYSTEM_H \
	-DTINC_UTILS_H \
	-DTINC_XALLOC_H \
	-DTINC_PRF_H

SHIM = -include kat/system.h

SRCS = \
	kat/gen_kat.c \
	kat/kat_b64.c \
	tinc-c/src/chacha-poly1305/chacha.c \
	tinc-c/src/chacha-poly1305/chacha-poly1305.c \
	tinc-c/src/chacha-poly1305/poly1305.c \
	tinc-c/src/ed25519/fe.c \
	tinc-c/src/ed25519/ge.c \
	tinc-c/src/ed25519/sc.c \
	tinc-c/src/ed25519/sha512.c \
	tinc-c/src/ed25519/keypair.c \
	tinc-c/src/ed25519/key_exchange.c \
	tinc-c/src/ed25519/sign.c \
	tinc-c/src/ed25519/verify.c \
	tinc-c/src/nolegacy/prf.c

OUT_BIN  = kat/gen_kat
OUT_JSON = crates/tinc-crypto/tests/kat/vectors.json

.PHONY: all clean

all: $(OUT_JSON)

$(OUT_BIN): $(SRCS) kat/system.h
	$(CC) $(CFLAGS) $(SUPPRESS) $(SHIM) -o $@ $(SRCS)

$(OUT_JSON): $(OUT_BIN)
	mkdir -p $(dir $@)
	$(OUT_BIN) > $@.tmp
	mv $@.tmp $@
	@echo "KAT vectors written to $@"

clean:
	rm -f $(OUT_BIN) $(OUT_JSON)
