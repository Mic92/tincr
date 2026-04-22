# Vendored Poly1305 aarch64 kernel

`poly1305-armv8-{apple,elf}.S` are pregenerated from OpenSSL 3.5.0's
`crypto/poly1305/asm/poly1305-armv8.pl` (CRYPTOGAMS, Andy Polyakov;
dual Apache-2.0 / OpenSSL licence — see file headers). Regenerate with:

```sh
perl poly1305-armv8.pl ios64   poly1305-armv8-apple.S
perl poly1305-armv8.pl linux64 poly1305-armv8-elf.S
```

`arm_arch.h` is a minimal local stand-in (only the four macros the asm
references). `poly1305_glue.c` supplies `OPENSSL_armcap_P` and the
one-shot `tinc_poly1305()` wrapper.

## Why this exists

SPTPS uses the OpenSSH-style ChaCha20-Poly1305 construction:
`tag = Poly1305(ct)` with no AAD/pad/length suffix. `ring` and
`aws-lc` only ship aarch64 asm for the *fused* RFC 8439 AEAD
(`chacha20_poly1305_armv8.S`), whose MAC framing is incompatible.
Their standalone `CRYPTO_poly1305_*` falls back to portable C on
aarch64 — same speed as the `poly1305` crate's soft backend. This
kernel is the only readily-available NEON Poly1305 that can be driven
with arbitrary framing.
