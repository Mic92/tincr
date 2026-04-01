# Issues Found in the Rewrite Plan

After reading the actual source, the plan has several assumptions that don't hold. Ordered by severity.

---

## CRITICAL — Would cause silent interop failure

### 1. The AEAD is NOT RFC 8439 ChaCha20-Poly1305

The plan says: *"ChaCha20-Poly1305: `chacha20poly1305` crate (RustCrypto)"*

**Wrong.** `src/chacha-poly1305/` is the **OpenSSH-style** construction (the one from `PROTOCOL.chacha20poly1305`, pre-RFC), not the IETF AEAD:

| | tinc (OpenSSH-style) | RFC 8439 / `chacha20poly1305` crate |
|---|---|---|
| Nonce | 64-bit, **big-endian** seqno (`put_u64`) | 96-bit |
| Counter | 64-bit | 32-bit |
| Poly1305 input | `tag = Poly1305(ciphertext)` only | `tag = Poly1305(AD ‖ pad ‖ CT ‖ pad ‖ len(AD) ‖ len(CT))` |
| Key | **Two** 256-bit keys (`main_ctx`, `header_ctx`) — see `chacha_poly1305_set_key`: `key + 32` | One 256-bit key |
| Poly1305 key derivation | First block of ChaCha keystream (counter=0) | Same — but only this part matches |

```c
// src/chacha-poly1305/chacha-poly1305.c
chacha_keysetup(&ctx->main_ctx, key, 256);
chacha_keysetup(&ctx->header_ctx, key + 32, 256);   // ← 64-byte key, two contexts
...
put_u64(seqbuf, seqnr);                             // ← big-endian 64-bit nonce
chacha_ivsetup(&ctx->main_ctx, seqbuf, NULL);
chacha_encrypt_bytes(&ctx->main_ctx, poly_key, poly_key, sizeof(poly_key));
chacha_ivsetup(&ctx->main_ctx, seqbuf, one);        // counter = 1
chacha_encrypt_bytes(&ctx->main_ctx, indata, outdata, inlen);
poly1305_auth(outdata + inlen, outdata, inlen, poly_key);  // ← no AD, no length suffix
```

**The `header_ctx` appears unused** in this file, but the key offset means SPTPS feeds 64 bytes where standard ChaCha20-Poly1305 expects 32. Even if you only use half, you must pull the right half.

**Fix:** No off-the-shelf crate implements this. You must hand-roll it from `chacha20` (the raw stream cipher crate, **with `legacy` feature** for the 64-bit-nonce variant) + `poly1305` primitives. ~100 LOC, but it's the single most interop-critical 100 LOC in the project. Extract KAT vectors from the C code on day one.

---

### 2. The ECDH is NOT X25519

The plan says: *"Ed25519/X25519: `ed25519-dalek` + `x25519-dalek`"*

**Wrong.** `src/ed25519/ecdh.c` + `key_exchange.c`:

```c
// ecdh.c
ed25519_create_keypair(pubkey, ecdh->private, seed);  // ← Ed25519 keypair, NOT X25519
// pubkey is an ED25519 PUBLIC KEY (Edwards point, 32 bytes)
// private is the SHA-512(seed) clamped scalar (first 32 of 64 bytes)

// key_exchange.c
/* unpack the public key and convert edwards to montgomery */
/* due to CodesInChaos: montgomeryX = (edwardsY + 1)*inverse(1 - edwardsY) mod p */
fe_frombytes(x1, public_key);           // ← reads Edwards Y coordinate
fe_add(tmp0, x1, tmp1);
fe_sub(tmp1, tmp1, x1);
fe_invert(tmp1, tmp1);
fe_mul(x1, tmp0, tmp1);                 // ← birational map to Montgomery u
// ...then standard X25519 ladder
```

This is **XEdDSA-style key reuse**: the wire carries an **Ed25519 public key**, the peer converts Edwards→Montgomery and does an X25519-ladder scalar mult. The private scalar is `SHA512(seed)[0..32]` clamped — the *expanded* Ed25519 scalar, not a raw X25519 scalar.

`x25519-dalek` cannot do this — it expects Montgomery u-coordinates on input and won't accept Edwards-encoded points.

**Fix:**
- `curve25519-dalek` directly: `EdwardsPoint::decompress()` → `.to_montgomery()` → `MontgomeryPoint::mul_clamped(scalar)`.
- The scalar must come from `Sha512::digest(seed)[0..32]` with the same clamping (`&= 248`, `&= 63`, `|= 64`).
- `ed25519-dalek` for signing is **probably** fine since `sign.c` looks like standard Ed25519, but verify with KATs — the on-disk private key is the **64-byte expanded form** (`SHA512(seed)`), not the 32-byte seed. `ed25519-dalek::SigningKey` wants the seed; you'll need `hazmat::ExpandedSecretKey`.

---

### 3. The PRF is NOT HKDF

The plan says: *"HKDF-SHA256 (`prf.c`): `hkdf` crate"*

**Wrong on both counts.** `src/nolegacy/prf.c`:

```c
/* Generate key material from a master secret and a seed, based on RFC 4346 section 5.
   We use SHA512 instead of MD5 and SHA1. */
```

This is the **TLS 1.0/1.1 PRF** (RFC 4346 §5) construction over **HMAC-SHA512**, not HKDF and not SHA256:
- `A(0) = seed` (initialized to zeros + seed in tinc's variant — see `memset(data, 0, mdlen)`)
- `A(i) = HMAC(secret, A(i-1))`
- `output = HMAC(secret, A(1) ‖ seed) ‖ HMAC(secret, A(2) ‖ seed) ‖ ...`

Note tinc's quirk: `data` is `[64 zero bytes] ‖ seed` initially, and `A(i)` overwrites the first 64 bytes. So `A(0)` is effectively zeros, not `seed` — a **deviation from RFC 4346**.

**Fix:** Hand-roll (~40 LOC over `hmac` + `sha2` crates). Absolutely needs a KAT extracted from the C build — this is the kind of thing where being off-by-one in the iteration produces a key that decrypts nothing.

---

### 4. Ed25519 private key on-disk format is non-standard

```c
typedef struct { uint8_t private[64]; uint8_t public[32]; } ecdsa_t;
// stored as 96 bytes inside "-----BEGIN ED25519 PRIVATE KEY-----" PEM
```

The 64-byte `private` is `SHA512(seed)` (clamped lower half + nonce-prefix upper half), **not** the 32-byte seed and **not** PKCS#8. `ed25519-dalek` cannot load this directly. The `read_pem` is also tinc's own PEM-ish framing, not real PEM/DER.

**Fix:** Custom loader → `ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes()`. Don't use the `pem` crate's parser; it'll choke on tinc's format.

---

### 5. Base64 has a custom decode table

```c
// src/utils.c — decode table accepts BOTH '+'/'/' AND '-'/'_'
-1, -1, -1, 62, -1, 62, -1, 63,   // '+' → 62, '-' → 62, '/' → 63
```

`b64decode_tinc` accepts a *union* of standard and URL-safe alphabets. The `base64` crate's strict modes will reject mixed input that the C code accepts. Minor, but will cause "invalid public key" errors on edge-case configs.

---

## SERIOUS — Would cause architecture rework mid-project

### 6. The C protocol handlers are not pure parsers — Phase 1 differential testing is harder than stated

The plan says: *"feed the same input to C `*_h()` handlers and Rust parsers, assert identical extracted fields"*

But `add_edge_h()`, `req_key_h()` etc. don't *return* parsed structs — they `sscanf` and then immediately **mutate global trees** (`node_tree`, `edge_tree`), call `graph()`, send replies. There's no seam to extract "what was parsed" without either:
- Heavy refactoring of the C code first (defeats the purpose), or
- Dumping the global tree state before/after (fragile, slow).

**Fix:** Don't try to FFI-test the handlers. Instead capture **wire traffic** between two C tincd instances (the integration tests already spin these up) and use that corpus as golden input/output for the Rust parsers. The `sscanf` format strings *are* the spec — there are only 20 of them, transcribe by hand and verify against the corpus.

---

### 7. SIGHUP reload mutates the arena live

```c
// net.c reload_configuration()
for splay_each(subnet_t, subnet, &subnet_tree)
    if(subnet->owner) subnet->expires = 1;
// ...later: walk again, free expired, insert new
```

The plan's `slotmap` arena is fine, but reload doesn't rebuild from scratch — it **selectively expires** subnets/nodes while keeping connections alive. With `&mut Daemon` you can do this, but it's not the clean "drop the arena, build a new one" the plan implies. Budget time for a `daemon.reload()` that walks and patches.

---

### 8. `tinc-ffi` linking is non-trivial

`src/meson.build` builds *executables*, not a `libtinc.a`. Everything is riddled with globals (`node_tree`, `myself`, `connection_list`). To get a linkable static lib for `tinc-ffi` you'd need to:
- Patch meson to emit `static_library('tinc_core', ...)` excluding `tincd.c`'s `main`
- Stub out the `device.c` per-OS modules (they have constructors)
- Initialize `myself`, `confbase`, etc. before any handler runs

**Fix:** Reduce scope. Only FFI-wrap **SPTPS** (`sptps.c` + crypto deps) — it's the one module that's actually self-contained with a clean callback API. For everything else, use the wire-corpus approach from #6.

---

### 9. `route.c` synthesizes packets — `etherparse` is read-only

```c
// route.c — builds ICMP Unreachable, ICMPv6 Too Big, ARP replies, NDP NA
ip.ip_len = htons(ip_size + icmp_size + oldlen);
ip.ip_sum = inet_checksum(&ip, ip_size, ~0);
memcpy(DATA(packet) + ether_size, &ip, ip_size);
```

The plan suggests `etherparse` for parsing. That works for the read path. But tinc *generates* ICMP/ARP/NDP responses in-place with hand-computed checksums. `etherparse` doesn't write. You'll be hand-rolling `#[repr(C)]` header structs + checksum anyway. ~300 LOC, just don't expect a crate to save you.

---

### 10. Legacy LZO has no pure-Rust implementation

The plan acknowledges this (`lzo` FFI), but understates it: LZO is the *default* compression in many existing tinc 1.0 deployments (`Compression = 9` etc.). If you ship Phase 5 nolegacy-only, you also can't talk to compressing legacy peers. The `--features legacy` gate must include LZO, and the `lzo-sys` crate is unmaintained. Consider vendoring minilzo C directly via `cc`.

---

## MINOR — Estimation / scoping nits

### 11. `mio` doesn't help with the per-platform event code

The plan says `mio` replaces `event.c` + `linux/event.c` + `bsd/event.c`. True for the poll mechanism, but tinc's event layer also does **signal-safe self-pipe wakeup** and **timer wheels** (`timeout_add`/`timeout_del`). `mio` gives you neither. You'll build a small timer heap on top — ~200 LOC, just don't count it as "free".

### 12. Windows control socket is a named pipe, not a Unix socket

`tincctl.c` ↔ `control.c` use `AF_UNIX` on POSIX but `\\.\pipe\tinc.NETNAME` on Windows. The plan's "ship `tinc` CLI talking to C daemon" milestone needs Windows named-pipe client code (no good crate; `windows-sys` raw calls).

### 13. The 6-month estimate assumes no time on items 1–5

Each of the crypto-compat items (1, 2, 3, 4) is a "two days to implement, two weeks to be *certain* it's right" problem. KAT extraction + cross-validation for the bespoke crypto stack is realistically a phase of its own. Add 3–4 weeks.

---

## Summary of Required Plan Changes

| # | Plan said | Reality |
|---|---|---|
| 1 | `chacha20poly1305` crate | Hand-roll OpenSSH-style construction from `chacha20` (legacy variant) + `poly1305` |
| 2 | `x25519-dalek` | `curve25519-dalek` low-level: Edwards decompress → Montgomery → clamped scalar mult |
| 3 | `hkdf` crate | Hand-roll TLS-1.0 PRF over HMAC-SHA512, with tinc's zero-A(0) quirk |
| 4 | (implied: standard key files) | Custom 96-byte PEM-ish loader → `ed25519_dalek::hazmat::ExpandedSecretKey` |
| 5 | (implied: standard b64) | Permissive decoder accepting both alphabets |
| 6 | FFI-test C handlers | Wire-corpus golden tests instead |
| 8 | Full `tinc-ffi` | SPTPS-only FFI; rest via corpus |

**The most dangerous sentence in the original plan was "Delete: vendored `src/ed25519/` and `src/chacha-poly1305/`."** Those directories *are* the protocol spec. Delete them only after KATs are extracted and the Rust replacements pass.
