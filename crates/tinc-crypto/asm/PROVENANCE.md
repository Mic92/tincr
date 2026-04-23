# Provenance — vendored Poly1305 aarch64 kernel

Supply-chain pin for the files in this directory. The checksums below
are enforced by `tests/asm_provenance.rs`; edit both together.

## Upstream

| File | Origin |
| ---- | ------ |
| `poly1305-armv8-apple.S` | Generated: `perl crypto/poly1305/asm/poly1305-armv8.pl ios64` |
| `poly1305-armv8-elf.S`   | Generated: `perl crypto/poly1305/asm/poly1305-armv8.pl linux64` |
| `arm_arch.h`             | Local minimal stand-in (not vendored) |
| `poly1305_glue.c`        | Local glue (not vendored) |

- Repository: <https://github.com/openssl/openssl>
- Release: **OpenSSL 3.5.0** (tag `openssl-3.5.0`)
- Perlasm source: `crypto/poly1305/asm/poly1305-armv8.pl`
- Author/licence: CRYPTOGAMS, Andy Polyakov; dual Apache-2.0 / OpenSSL
  (see generated file headers)

The exact commit of `poly1305-armv8.pl` at that tag was not recorded
when the files were generated; the release tag plus the SHA-256 of the
generated output below is the authoritative pin. Regenerating from the
`openssl-3.5.0` tag must reproduce these hashes byte-for-byte.

## Local modifications

None to the generated `.S` files. `arm_arch.h` is a from-scratch
minimal reimplementation (only `ARMV7_NEON` and the BTI/PAC hint
macros), not the upstream header.

## SHA-256

```
ac96e8f720d97a020ea6d02dc6b5e5b04cf42967b1295ce362b52a5cabbd8e86  poly1305-armv8-apple.S
8e2671f54298f4698e305fa1fc4c894f434f996c55128cef53aef54698a9ad2a  poly1305-armv8-elf.S
b9c61ed09e70affe17ead6c456217d3fed09ca093c9d609d94e8abc9f321432d  arm_arch.h
9623e96906cd4fe6f93d9ef6c75fc32b80294b45ae691d78b3eaf479181891b4  poly1305_glue.c
```
