# tinc → Rust Rewrite Plan

## Scope Assessment

| Metric | Value |
|--------|-------|
| C source | ~33k LOC across 66 `.c` files |
| Binaries | `tincd` (daemon), `tinc` (control CLI), `sptps_test`, `sptps_keypair`, `sptps_speed` |
| Platforms | Linux, FreeBSD, NetBSD, OpenBSD, macOS, Solaris, Windows |
| Crypto backends | OpenSSL, libgcrypt, "nolegacy" (ChaCha20-Poly1305 + Ed25519 only) |
| Wire protocols | Legacy meta-protocol v17, SPTPS, control socket protocol |
| Compression | zlib, LZO, LZ4 |

**Hard constraint:** Wire-format compatibility with tinc 1.0.x and 1.1.x peers is non-negotiable. The text-based meta-protocol (`ID`, `METAKEY`, `ADD_EDGE`, …) and the SPTPS binary framing must be reproduced byte-for-byte.

---

## ⚠️ Read This First: Crypto Is Bespoke

After source inspection, **none of the SPTPS crypto primitives match off-the-shelf Rust crates**:

| Primitive | What tinc actually does | Crate that *won't* work |
|---|---|---|
| AEAD | OpenSSH-style ChaCha20-Poly1305: 64-bit BE nonce, 64-byte split key, no AD/length-suffix in MAC | `chacha20poly1305` (RFC 8439) |
| ECDH | Ed25519 pubkey on wire → Edwards-to-Montgomery birational map → X25519 ladder with `SHA512(seed)[0..32]` clamped scalar | `x25519-dalek` |
| KDF | TLS 1.0 PRF (RFC 4346 §5) over HMAC-SHA512, with `A(0) = zeros` quirk | `hkdf` |
| Key files | 96-byte (`SHA512(seed) ‖ pubkey`) in tinc-custom PEM framing | `pem`, `ed25519-dalek::SigningKey` |
| Base64 | Decoder accepts *union* of standard + URL-safe alphabets | `base64` (strict modes) |

The vendored `src/ed25519/` and `src/chacha-poly1305/` directories **are the wire protocol spec.** They must not be deleted until KAT vectors are extracted and Rust replacements pass byte-for-byte.

---

## Strategy: Strangler Fig, Not Big Bang

A 33k LOC ground-up rewrite of a daemon with two custom security protocols is a multi-year effort with high risk of subtle interop regressions. Instead:

1. **Phase 0** — Extract KAT vectors from the C crypto, build an SPTPS-only FFI harness, capture wire-traffic corpus.
2. **Phases 1–4** — Replace subsystems leaf-first, keeping `tincd` shippable at every step.
3. **Phase 5** — Drop the C event loop, switch to a Rust `main()`.

Each phase ends with the existing `test/integration/*.py` suite passing.

---

## Workspace Layout

```
Cargo.toml                  # workspace
crates/
  tinc-proto/               # pure: wire formats, no I/O
  tinc-sptps/               # pure: SPTPS state machine, no I/O
  tinc-crypto/              # bespoke primitives: SSH-ChaPoly, Ed25519-ECDH, TLS-PRF
  tinc-graph/               # pure: node/edge/subnet graph + MST/BFS
  tinc-conf/                # config file parser (host files, tinc.conf)
  tinc-device/              # TUN/TAP abstraction (per-OS modules)
  tinc-net/                 # event loop, sockets, packet routing
  tincd/                    # daemon binary
  tinc-cli/                 # `tinc` control client (replaces tincctl.c)
  tinc-ffi/                 # SPTPS-only bindgen wrapper, test-only
xtask/                      # interop test harness
```

**Key principle:** `tinc-proto`, `tinc-sptps`, `tinc-graph` must be `#![no_std]`-compatible (or at least zero-syscall pure libraries) so they can be exhaustively fuzzed and property-tested without spinning up sockets.

---

## Phase 0 — KATs, Corpus, and SPTPS Harness (~3 weeks)

**Goal:** Lock down ground truth before writing any production Rust.

### 0a. Extract crypto KAT vectors
Instrument the C build to dump test vectors. Add `fprintf(stderr, ...)` hooks (or a `--dump-kat` mode to `sptps_test`) for:

- **ChaPoly:** `(key[64], seqno, plaintext, ciphertext‖tag)` — ≥20 tuples spanning seqno=0, seqno=1, seqno near 2³², varied lengths
- **ECDH:** `(seed[32], ed_pubkey[32], peer_ed_pubkey[32], shared[32])` — ≥10 tuples
- **PRF:** `(secret, seed, outlen, output)` — ≥10 tuples including the exact call SPTPS makes (`outlen = sizeof(sptps_key_t)`)
- **Ed25519 sign/verify:** `(private[64], public[32], msg, sig[64])` — confirm it matches RFC 8032 (it should; `sign.c` looks standard)
- **Key file:** dump a generated `ed25519_key.priv` alongside its `(seed, private[64], public[32])` decomposition
- **b64:** mixed-alphabet edge cases that the permissive decoder accepts

Commit vectors as `crates/tinc-crypto/tests/kat/*.json`. **These outlive the C code.**

### 0b. SPTPS-only FFI
`tinc-ffi` wraps **only** `sptps.c` + its crypto deps. Do not attempt to FFI the protocol handlers — they `sscanf` and immediately mutate global splay trees, there's no parse seam.

- [ ] `build.rs`: `cc::Build` compiles `sptps.c`, `chacha-poly1305/*.c`, `ed25519/*.c`, `nolegacy/prf.c`, plus stubs for `logger`/`xalloc`/`random`. Avoid meson; this subset has no per-OS code.
- [ ] Safe wrapper: `CSptps::start(role, key, peer_key, label)`, `.receive(&[u8]) -> Vec<Event>`, `.send_record(type, &[u8]) -> Vec<u8>`. Adapt the C callbacks to write into a `Vec` via `void* handle`.

### 0c. Wire-traffic corpus
The integration tests already spin up multi-node meshes. Add a capture shim:

- [ ] `LD_PRELOAD` hook on `send_request`/`receive_request` (or just patch `protocol.c` to `tee` to a file when `TINC_CAPTURE` env is set)
- [ ] Run `test/integration/*.py`, collect `corpus/meta/*.txt` — every meta-protocol line ever sent
- [ ] Same for control socket: `corpus/control/*.txt`

The 20 `sscanf` format strings in `protocol_*.c` are the spec; the corpus is the conformance suite.

### 0d. CI baseline
- [ ] `meson test` unchanged — the bar to clear
- [ ] Parameterize `test/integration/testlib/` to launch `${TINCD_BIN:-tincd}` so a future Rust binary slots in

**Deliverable:** `cargo test -p tinc-ffi` runs a C↔C SPTPS handshake. KAT JSON files committed.

---

## Phase 1 — Pure Logic Crates (~4 weeks)

These have no I/O and are the safest place to start. They map almost 1:1 to existing C files.

### `tinc-proto`
| C source | Rust module | Notes |
|---|---|---|
| `protocol.h` request enum | `enum Request` | `#[repr(u8)]` matching wire values |
| `protocol.c` `send_request`/`receive_request` | `Request::format()` / `Request::parse()` | Replaces `sscanf("%d %2048s")` patterns with `nom` or hand-rolled splits |
| `protocol_auth.c` message bodies | `auth.rs` | `ID`, `METAKEY`, `CHALLENGE`, `CHAL_REPLY`, `ACK` framing only — *not* the crypto yet |
| `protocol_edge.c`, `protocol_subnet.c`, `protocol_misc.c`, `protocol_key.c` | one module each | Pure parse/serialize |
| `subnet_parse.c` | `subnet.rs` | IPv4/IPv6/MAC subnet string ↔ struct |
| `netutl.c` (`str2sockaddr` etc.) | `addr.rs` | |

**Testing:** For every parser, a `proptest` round-trip (`parse(format(x)) == x`) **plus** the Phase 0c wire corpus as golden input. Do *not* try to differentially test against C `*_h()` handlers — they have no parse seam (they `sscanf` then mutate globals). The 20 `sscanf` format strings are short enough to transcribe by hand and verify against the corpus.

**`utils.rs`:** Port `b64decode_tinc` exactly — it accepts both `+/` and `-_` simultaneously (decode table maps both to 62/63). The `base64` crate's `GeneralPurpose` engine can't do this; hand-roll the decoder (~40 LOC).

### `tinc-graph`
| C source | Rust |
|---|---|
| `splay_tree.c`, `list.c`, `hash.h` | `BTreeMap` / `Vec` / `HashMap` — **delete, don't port** |
| `node.c`, `edge.c`, `subnet.c` | `struct Node`, `struct Edge`, `struct Subnet` in an arena (`slotmap` or `generational-arena`) |
| `graph.c` (MST + BFS reachability) | `graph.rs` | Port the Prim's-MST and BFS verbatim first, optimize later |

**Why arena, not `Rc<RefCell<>>`:** the C code is full of cyclic node↔edge↔connection pointers. Index-based arenas (`NodeId(u32)`) sidestep the borrow checker fight entirely and match the C memory model.

**Testing:** Generate random graphs, run C `graph()` and Rust `graph()` on identical input, diff the resulting reachability/nexthop tables.

### `tinc-conf`
| C source | Rust |
|---|---|
| `conf.c`, `conf_net.c` | `conf.rs` — parse `tinc.conf` and `hosts/*` key=value format |
| `names.c` | `paths.rs` — `confbase`, `pidfilename`, etc. via `directories` crate respecting tinc's existing lookup order |

Straightforward; the format is trivial. Reuse upstream `test/integration/` config fixtures.

---

## Phase 2 — Crypto & SPTPS (~6 weeks, highest risk)

`sptps.c` (774 LOC) is the most security-sensitive module. It is self-contained, but **every primitive it depends on is non-standard.** Budget two days per primitive to implement, two weeks per primitive to be *certain* it's right.

### `tinc-crypto` — four bespoke primitives

Traits stay simple; implementations are the work.

```rust
pub struct ChaPoly { key: [u8; 64] }   // note: 64, not 32
impl ChaPoly {
    pub fn seal(&self, seqno: u64, pt: &[u8], out: &mut [u8]);  // out = ct ‖ tag[16]
    pub fn open(&self, seqno: u64, ct: &[u8], out: &mut [u8]) -> Result<(), ()>;
}

pub struct EcdhPrivate { expanded: [u8; 64] }  // SHA512(seed), not seed
impl EcdhPrivate {
    pub fn generate(rng) -> (Self, [u8; 32]);   // pubkey is Ed25519 point
    pub fn compute_shared(self, peer_ed_pub: &[u8; 32]) -> [u8; 32];
}

pub fn prf(secret: &[u8], seed: &[u8], out: &mut [u8]);  // TLS 1.0 PRF, HMAC-SHA512

pub struct SigningKey { expanded: [u8; 64], public: [u8; 32] }  // on-disk format
```

#### `chapoly.rs` — OpenSSH-style ChaCha20-Poly1305

Reference: `src/chacha-poly1305/chacha-poly1305.c`. **Not RFC 8439.**

| Aspect | Value |
|---|---|
| Key | 64 bytes. `key[0..32]` → main cipher. `key[32..64]` → "header" cipher (unused by SPTPS but the offset matters for key derivation) |
| Nonce | `seqno: u64` serialized **big-endian** into 8 bytes |
| ChaCha variant | 64-bit nonce / 64-bit counter ("legacy" / DJB original, **not** IETF 96/32) |
| Poly1305 key | First 32 bytes of keystream at `(nonce=seqno_be, counter=0)` |
| Ciphertext | Keystream at `(nonce=seqno_be, counter=1)` XOR plaintext |
| MAC input | `Poly1305(ciphertext)` only — **no AD, no padding, no length suffix** |

Build from primitives:
- `chacha20` crate **with `legacy` feature** → `ChaCha20Legacy` (64-bit nonce variant). The default `ChaCha20` type is IETF and will produce the wrong keystream.
- `poly1305` crate → raw `Poly1305::new(key).compute_unpadded(ct)`

~100 LOC. **Gate on Phase 0a KATs before writing anything else.**

#### `ecdh.rs` — Ed25519-point ECDH

Reference: `src/ed25519/ecdh.c` + `key_exchange.c`. **Not X25519.**

Wire format carries an **Ed25519 public key** (compressed Edwards y-coordinate). Receiver does:
1. Decompress Edwards point from `peer_pubkey[32]`
2. Birational map to Montgomery: `u = (1+y) / (1-y) mod p`
3. X25519 ladder with clamped scalar `SHA512(seed)[0..32]`

Key generation uses `ed25519_create_keypair`: `private = SHA512(seed)` clamped, `public` = standard Ed25519 pubkey.

Build from `curve25519-dalek` low-level:
```rust
use curve25519_dalek::{edwards::CompressedEdwardsY, montgomery::MontgomeryPoint, scalar::clamp_integer};
let ed = CompressedEdwardsY(peer_pub).decompress()?;  // validates point
let mont: MontgomeryPoint = ed.to_montgomery();        // birational map, built-in
let scalar = clamp_integer(sha512(seed)[..32]);        // matches C clamping
let shared = mont.mul_clamped(scalar).to_bytes();
```

**Subtle:** `key_exchange.c` reads only `private_key[0..32]` (the clamped scalar half) and re-clamps. Verify with KATs that `clamp_integer(already_clamped) == already_clamped`.

#### `prf.rs` — TLS 1.0 PRF over HMAC-SHA512

Reference: `src/nolegacy/prf.c`. **Not HKDF.**

RFC 4346 §5 P_hash construction, but with a quirk:
```
data = [0u8; 64] ‖ seed                    // tinc: A(0) is ZEROS, not seed
loop:
    data[0..64] = HMAC-SHA512(secret, data)      // A(i) = HMAC(secret, A(i-1) ‖ seed)
    out.extend(HMAC-SHA512(secret, data))        // P_hash chunk
```

~40 LOC over `hmac` + `sha2`. The `A(0) = zeros` deviation from RFC 4346 means no existing TLS-PRF crate will match. **KAT or bust.**

#### `keys.rs` — tinc PEM-ish key files

On-disk private key: 96 bytes (`SHA512(seed)[64] ‖ pubkey[32]`) inside `-----BEGIN ED25519 PRIVATE KEY-----` framing using tinc's permissive base64. Not PKCS#8, not the 32-byte seed format.

- Load: custom PEM-line stripper → `b64decode_tinc` → split 64+32 → `ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&private[..64])`
- Sign: `hazmat::raw_sign(&expanded, msg, &verifying_key)` — confirm against KATs that this matches `sign.c` (it should; `sign.c` is standard Ed25519, just fed the expanded key)
- Verify: standard `ed25519_dalek::VerifyingKey::verify_strict` — but check `verify.c` for cofactor handling edge cases

**Do not delete `src/ed25519/` or `src/chacha-poly1305/` until all four primitives pass KATs.**

### Legacy RSA + AES-CBC
*Do not* port in this phase. Gate behind `--features legacy`, keep calling OpenSSL via FFI permanently for RSA — reimplementing 20-year-old PKCS#1 padding to be byte-compatible is a footgun. Note: legacy mode also needs LZO (see Dependencies).

### `tinc-sptps`
Sans-I/O state machine:
```rust
pub struct Sptps<C: Crypto> { state: State, ... }
impl Sptps {
    pub fn start(role: Role, my_key: Ecdsa, peer_key: EcdsaPub, label: &[u8]) -> (Self, Vec<u8> /* to send */);
    pub fn receive(&mut self, data: &[u8]) -> Result<Vec<Event>, Error>;
    pub fn send_record(&mut self, type_: u8, data: &[u8]) -> Vec<u8>;
}
pub enum Event { Handshake, Record { type_: u8, data: Vec<u8> } }
```

Maps directly to C `sptps_start`, `sptps_receive_data`, `sptps_send_record`, but **returns** bytes instead of invoking a callback — the caller does I/O.

**Testing — this is where the budget goes:**
1. **KAT:** Every `tinc-crypto` primitive passes Phase 0a vectors before SPTPS work starts.
2. **Self-interop:** Rust initiator ↔ Rust responder.
3. **Cross-interop:** Rust initiator ↔ C responder (via `tinc-ffi`), and the reverse. Run in a `#[test]` with both state machines stepped in lockstep, no sockets. **This is the single highest-value test in the project** — if it passes, the crypto is right.
4. **Socket interop:** Rust `sptps_test` ↔ C `sptps_test` over Unix socket.
5. **Fuzz:** `cargo-fuzz` target on `Sptps::receive` post-handshake. The C code has had CVEs here (replay window, length checks).

**Milestone binary:** `sptps_test` rewritten in Rust, interoperating with the C `sptps_test` over a socket. This is your first shippable artifact.

---

## Phase 3 — Device & Transport (~3 weeks)

### `tinc-device`
| Platform | C source | Rust approach |
|---|---|---|
| Linux | `linux/device.c` | `tun-tap` crate or hand-rolled `ioctl(TUNSETIFF)` — ~150 LOC |
| BSD/macOS | `bsd/device.c`, `bsd/darwin/` | `/dev/tun*`, utun via `libc::ioctl`. The vmnet path can wait. |
| Windows | `windows/device.c` | `wintun` crate (WireGuard's driver) — **drop** TAP-Windows support |
| Multicast/raw/UML/VDE | `*_device.c` | Feature-gated, low priority, port last |

```rust
pub trait Device: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, buf: &[u8]) -> io::Result<usize>;
    fn iftype(&self) -> IfType;  // TUN vs TAP
}
```

### `tinc-net` (sockets only, not the event loop yet)
| C source | Rust |
|---|---|
| `net_socket.c` | TCP/UDP listener setup, `SO_REUSEADDR`, dual-stack, bind-to-interface (`socket2`) |
| `proxy.c` | SOCKS4/5, HTTP CONNECT — hand-roll, it's ~200 LOC and synchronous |
| `address_cache.c` | LRU of recently-seen peer addresses |
| `upnp.c` | `igd` crate, feature-gated |

### Packet synthesis (`route.c` write-path)
`route.c` doesn't just parse — it **builds** ICMP Unreachable, ICMPv6 Packet Too Big, ARP replies, and NDP Neighbor Advertisements in-place, with hand-computed checksums. `etherparse` is read-only. Hand-roll:

- `#[repr(C, packed)]` structs for `iphdr`, `ip6_hdr`, `icmphdr`, `icmp6_hdr`, `ether_arp`, `nd_neighbor_advert` (lift from `src/ipv4.h`, `src/ipv6.h`, `src/ethernet.h`)
- `inet_checksum()` — standard one's-complement, ~15 LOC
- One builder fn per response type, ~50 LOC each

~300 LOC total. Use `etherparse` for the *parse* path only.

---

## Phase 4 — `tinc` CLI (~2 weeks)

`tincctl.c` is 3.4k LOC but it's the *least* risky: it's a client speaking the control-socket protocol (`doc/CONTROL`) plus an interactive shell.

| C source | Rust |
|---|---|
| `tincctl.c` command dispatch | `clap` subcommands |
| `info.c`, `top.c` | control-socket queries + `ratatui` for `tinc top` |
| `invitation.c` | invitation URL generation/consumption — **needs SPTPS from Phase 2** |
| `fsck.c` | config sanity checker |
| `ifconfig.c` | platform `ip`/`ifconfig` shelling-out for `tinc-up` script generation |

This can ship **independently** of the daemon — it talks to the existing C `tincd` over the control socket. **Ship this first** to get Rust into users' hands early.

**Windows caveat:** control socket is `\\.\pipe\tinc.NETNAME` (named pipe), not `AF_UNIX`. No good crate; raw `windows-sys` `CreateFileW` + `ReadFile`/`WriteFile`. ~100 LOC behind `#[cfg(windows)]`.

---

## Phase 5 — The Daemon Core (~6 weeks)

Only attempt this once Phases 1–3 are battle-tested.

### Event loop decision
The C code uses a hand-rolled `epoll`/`kqueue`/`select` loop (`event.c`, `linux/event.c`, `bsd/event.c`, `event_select.c`). Options:

| Option | Pro | Con |
|---|---|---|
| **`mio` + manual poll** | 1:1 with C structure, minimal churn, easy to reason about state machines | More boilerplate |
| **`tokio`** | Batteries included, timers/signals free | The C code's pervasive shared mutable state (`node_tree`, `connection_list` globals) fights async borrow rules hard |
| **`smol`** | Lighter than tokio | Same borrow issues |

**Recommendation:** `mio`. The C daemon is single-threaded with one poll loop. Replicate that. The graph/node/connection state lives in one big `struct Daemon` passed `&mut` into every handler — exactly mirroring the C globals but without `static mut`. Don't fight the architecture; the C design is actually fine, it's just unsafe.

`mio` gives you the poll mechanism but **not** timers or signals. Build on top:
- Timer wheel: `BinaryHeap<(Instant, TimerId)>` checked each loop iteration, ~100 LOC. Maps to C `timeout_add`/`timeout_del`.
- Signals: self-pipe trick (`signal_hook::low_level::pipe`) registered with `mio` as a readable fd. Maps to C `signal.c`.

**SIGHUP reload:** `reload_configuration()` does *not* rebuild from scratch — it walks the live subnet/node trees, marks entries `expires = 1`, re-reads configs, then sweeps expired entries while keeping connections alive. With `slotmap` this means `Daemon::reload(&mut self)` walks and patches in place. Do not assume "drop arena, build new one"; budget ~200 LOC for the selective expiry walk.

### Module mapping
| C source | LOC | Rust module |
|---|---|---|
| `tincd.c` | 735 | `main.rs` — argv, signals, drop privs, reload |
| `event.c` + per-OS | ~500 | thin `mio` wrapper |
| `net.c` | 527 | top-level loop: accept, timeout sweeps, retry outgoing |
| `net_setup.c` | 1336 | one-time daemon init: read configs, create sockets, load keys |
| `net_packet.c` | 1938 | **the hot path**: UDP rx/tx, MTU probing, relay, compression. Port carefully, benchmark against C. |
| `meta.c` | 322 | TCP meta-connection framing |
| `route.c` | 1176 | L2/L3 packet inspection → destination node lookup. Uses `tinc-graph`. |
| `protocol_auth.c` (handler side) | 1066 | The actual auth state machine driving SPTPS + legacy. Uses `tinc-sptps` + `tinc-proto`. |
| `autoconnect.c` | small | maintain N outgoing connections |
| `control.c` | small | control-socket server side |
| `process.c`, `signal.c`, `script.c`, `pidfile.c`, `logger.c` | small | mostly replaced by `nix`, `tracing`, `daemonize` crates |

### Hot-path concerns (`net_packet.c`)
- Preallocated packet buffers — no per-packet `Vec` alloc. Use `bytes::BytesMut` pool or fixed `[u8; MAXSIZE]` on stack.
- Zero-copy where the C code does `memcpy` only because of API shape, not necessity.
- Benchmark: `iperf3` over a 2-node localhost mesh, C vs Rust. Regression budget: ≤5%.

---

## What to Drop

Aggressively shed scope:

| Feature | Disposition |
|---|---|
| `gcrypt` backend | **Drop.** OpenSSL-via-FFI for legacy, RustCrypto for SPTPS. |
| Solaris device | **Drop** unless someone asks. |
| UML, VDE, raw_socket, multicast devices | Feature-gated, port only on demand. |
| `getopt.c`, `getopt1.c` (1k LOC) | **Delete.** Vendored GNU getopt. `clap` replaces it. |
| `splay_tree.c`, `list.c` | **Delete.** std collections. |
| `xalloc.h`, `dropin.c` | **Delete.** libc shims. |
| Jumbograms | Keep — it's just a buffer-size constant. |
| Legacy protocol (RSA+AES) | Port **last**, behind a feature flag. Consider FFI-to-OpenSSL permanently for the RSA parts; rewriting RSA-OAEP padding in Rust to match a 20-year-old C implementation is a footgun. |

---

## Testing Strategy Summary

| Layer | Technique |
|---|---|
| Parsers (`tinc-proto`, `tinc-conf`) | proptest round-trip + differential vs C via FFI |
| SPTPS | Cross-impl handshake (Rust↔C in-process) + cargo-fuzz + KAT vectors |
| Graph | Differential vs C on random graphs |
| Device | Per-OS smoke test in CI (Linux: GitHub Actions; BSD: builds.sr.ht as upstream already does; macOS: GH Actions) |
| End-to-end | Existing `test/integration/*.py` suite, parameterized over `TINC_BIN={c,rust}` |
| Interop | 3-node mesh in CI: 1× C tincd 1.0, 1× C tincd 1.1, 1× Rust tincd. Ping across all pairs. |
| Performance | `criterion` microbenchmarks on SPTPS seal/open + `iperf3` macro-benchmark in CI with regression gate |

---

## Crate Dependencies (Proposed)

| Purpose | Crate | Notes |
|---|---|---|
| ChaCha20 (DJB 64-bit nonce) | `chacha20` | **Must enable `legacy` feature** for `ChaCha20Legacy` |
| Poly1305 raw | `poly1305` | `compute_unpadded`, not the AEAD wrapper |
| Curve ops | `curve25519-dalek` | Edwards→Montgomery + `mul_clamped` |
| Ed25519 sign | `ed25519-dalek` | Via `hazmat::ExpandedSecretKey` (on-disk is expanded, not seed) |
| HMAC/SHA | `hmac`, `sha2` | For hand-rolled TLS-PRF |
| Constant-time | `subtle` | MAC comparison |
| Legacy RSA/AES (feature-gated) | `openssl` (FFI) | Don't reimplement RSA |
| Compression | `flate2` (zlib), `lz4_flex` | |
| LZO (feature-gated, legacy) | vendor `minilzo.c` via `cc` | `lzo-sys` is unmaintained; LZO is the *default* compression in tinc 1.0 deployments |
| Net | `mio`, `socket2`, `nix` (Unix), `windows-sys` (Win) |
| TUN | `tun` (Linux/macOS), `wintun` (Windows) — evaluate vs hand-rolling |
| CLI | `clap`, `ratatui` (for `tinc top`), `rustyline` |
| Logging | `tracing`, `tracing-subscriber` |
| Config | hand-rolled (format is trivial, `serde` is overkill) |
| Testing | `proptest`, `cargo-fuzz`, `criterion` |
| Arena | `slotmap` |

---

## Risk Register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Bespoke crypto primitive mismatch (ChaPoly, ECDH, PRF) | **Certain** without KATs | Phase 0a KAT extraction is mandatory, not optional. No `tinc-crypto` code merges without passing them. |
| SPTPS state-machine subtle incompatibility | High | Phase 2's in-process Rust↔C cross-test catches this before any socket is opened |
| Legacy protocol RSA padding mismatch | High | Keep using OpenSSL via FFI for legacy auth indefinitely |
| `chacha20` crate drops `legacy` feature | Low | It's been stable, but pin the version. Fallback: vendor DJB ChaCha (~200 LOC). |
| `net_packet.c` perf regression | Medium | Benchmark gate in CI; the C code isn't heavily optimized so matching it is realistic |
| Windows TUN driver churn | Medium | Switch to wintun (WireGuard's); it's better-maintained than TAP-Windows anyway |
| `route.c` packet-parsing edge cases (IPv6 ext headers, ARP, NDP) | Medium | Corpus capture from real traffic + fuzz. Consider `etherparse` crate for the parsing. |
| Scope creep into "let's redesign the protocol" | High | **Hard rule:** Phase 1–5 is byte-compatible port only. Protocol v18 ideas go in a separate doc. |

---

## Suggested Order of Shipping

1. **`sptps_test` + `sptps_keypair` in Rust** — proves crypto interop, ~6 weeks in
2. **`tinc` CLI in Rust** — talks to C daemon, real users, ~10 weeks in
3. **`tincd` Rust, SPTPS-only (`nolegacy` mode)** — ~18 weeks in
4. **`tincd` Rust with legacy protocol** — ~24 weeks in

Total: roughly **7 months** for one experienced engineer. The extra month over a naïve estimate is the bespoke-crypto tax: each of ChaPoly/ECDH/PRF/key-format is two days to implement and two weeks to be *certain*. The Phase 0 KAT vectors are the highest-leverage investment in the whole plan — they turn "is the crypto right?" from a debugging nightmare into a `cargo test` boolean.
