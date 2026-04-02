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

## Status

| Phase | State | Commit | Notes |
|---|---|---|---|
| 0a — KAT vectors + `tinc-crypto` | ✅ Done | `tinc-crypto: KAT-verified...` | All 5 primitives pass 7 KATs. See [Findings](#findings-from-phase-0a). |
| 0b — SPTPS FFI harness | ✅ Done | `tinc-ffi: SPTPS C↔C harness...` | 6 tests; deterministic via seeded ChaCha20 RNG |
| 0c — Wire-traffic corpus | | | |
| 0d — CI baseline | | | |
| 1 — Pure logic crates | ✅ | `tinc-conf: line parser...` | All four crates exist. 115 tests. The deferrals (`auth.rs`, `edge_del`, route trie, `names.c`) are intentional — they need their consumers to land first. |
| 2 — SPTPS state machine | ✅ Done | `tinc-sptps: pure-Rust SPTPS, byte-identical...` | 5 diff tests vs C; `byte_identical_wire_output` is the strong claim |
| **Ship #1 — `tinc-tools`** | ✅ | `tinc-tools: sptps_test + sptps_keypair...` | First binaries. Rust↔Rust + Rust↔C on real sockets, both modes, 64KB stream reassembly. |
| **Ship #2 (4a) — `tinc` CLI** | 🟡 9/11 | `tinc-conf: variables[] table...` | `init` + 5 host-shipping + rotation + `sign`/`verify`. `variables[]` (74 entries, fsck's last `tinc-conf` blocker) landed alongside. 235 tests + 9 cross-impl. fsck has one prereq left (`read_server_config` wrapper, ~50 LOC); `edit` defers to 5b. |
| 3 — Device & transport | | | |
| 4 — `tinc` CLI | (split: 4a above, 5b below) | | |
| 5 — Daemon core | | | |

---

## ⚠️ Read This First: Crypto Is Bespoke

After source inspection, **none of the SPTPS crypto primitives match off-the-shelf Rust crates**:

| Primitive | What tinc actually does | Crate that *won't* work |
|---|---|---|
| AEAD | OpenSSH-style ChaCha20-Poly1305: 64-bit BE nonce, 64-byte split key, no AD/length-suffix in MAC | `chacha20poly1305` (RFC 8439) |
| ECDH | Ed25519 pubkey on wire → Edwards-to-Montgomery birational map → X25519 ladder with `SHA512(seed)[0..32]` clamped scalar | `x25519-dalek` |
| KDF | TLS 1.0 PRF (RFC 4346 §5) over HMAC-SHA512, with `A(0) = zeros` quirk | `hkdf` |
| Key files | 96-byte (`SHA512(seed) ‖ pubkey`) in tinc-custom PEM framing | `pem`, `ed25519-dalek::SigningKey` |
| Base64 | **LSB-first bit packing** + decoder accepts union of `+/` and `-_` | `base64` (any mode) |

The vendored `src/ed25519/` and `src/chacha-poly1305/` directories **are the wire protocol spec.** As of Phase 0a, KAT vectors are extracted (`crates/tinc-crypto/tests/kat/vectors.json`, reproducible via `nix build .#kat-vectors`) and the Rust replacements pass byte-for-byte. The C sources still must not be deleted — they remain the regenerate-vectors-after-upstream-merge mechanism, and Phase 0b's FFI harness links them.

### Findings from Phase 0a

Three assumptions in the original plan turned out wrong on inspection:

1. **`chacha20` crate has no `legacy` feature.** `ChaCha20Legacy` is unconditionally exported in 0.9.x. The plan's dependency line was a phantom from older docs. (Fixed in `Cargo.toml`.)

2. **tinc's base64 is more broken than "permissive alphabet".** It packs bits LSB-first within each 3-byte group: `triplet = b[0] | b[1]<<8 | b[2]<<16`, then emits the *low* 6 bits first. RFC 4648 packs MSB-first. These are different *output strings*, not just different decode tables — `tinc_b64([0x48]) == "IB"`, RFC 4648 gives `"SA"`. The dual-alphabet decoder is layered on top of that. No `base64` crate engine config can produce this; it's a hand-roll regardless.

### Findings from Phase 0b

One behaviour the plan didn't anticipate, surfaced by the re-KEX test:

**During rekey, the responder's SIG and ACK both go out under the *old* `outcipher`.** Reading `receive_sig`: when `outstate` is already true (i.e. this is a rekey, not the initial handshake), it does `send_sig()` → `send_ack()` → *then* `chacha_poly1305_set_key(outcipher, new_key)`. Both sends use `send_record_priv` which checks the `outstate` flag (true) and encrypts with whatever `outcipher` currently holds (old key). The new key takes effect on the *next* record after.

Phase 2's Rust state machine must replicate this ordering. The natural "set key, then send" structure is wrong here. **Replicated in `state.rs::receive_sig`; `rust_vs_c_rekey` is the test.**

### Findings from Phase 2

Two state-representation issues, one RNG-bridge subtlety. None of these are wire-format bugs — the interop tests passed before they were fixed — but the byte-identity test caught all three.

1. **`outstate` (bool) vs `outcipher` (ctx*) are separate in C, collapsed into `Option<ChaPoly>` in Rust.** `receive_sig` replaces `outcipher` but doesn't touch `outstate`; `receive_handshake` then checks `if(s->outstate)` — which is the *old* value (set later, on line 423). Collapsing into one Option loses that bit. `receive_sig` returns `was_rekey: bool` to thread it through; the alternative is keeping a redundant field that exists only because the C did.

2. **`chacha.c`'s `chacha_encrypt_bytes` is block-granular.** Counter increments on every call exit, even partial-block. Two consecutive `randomize(32)` calls produce block-0 bytes 0..32, then block-**1** bytes 0..32; block-0's unused half is discarded. `chacha20::ChaCha20Legacy::apply_keystream` is byte-granular and would give block-0 bytes 32..64 for the second call. `BridgeRng` in `tests/vs_c.rs` seeks to the next 64-byte boundary after each fill. **This is a test-harness quirk, not a state-machine bug** — the interop tests pass without it because each side agrees with itself.

3. **Stream-mode `sptps_receive_data` processes one record per call.** No outer loop; it returns `total_read < len` and `protocol.c` calls it again with the tail. The Rust `receive` mimics this so the differential test can be strict about per-call consumed-byte counts. Phase 4's protocol layer needs to know to loop.

3. **`key_exchange.c` does not validate the Edwards point.** It does `fe_frombytes` (which just masks bit 255 and loads whatever's left as a field element) then applies the birational map blindly. The clean Rust path — `CompressedEdwardsY::decompress()?.to_montgomery()` — *validates*, and would reject inputs the C code accepts. `curve25519-dalek` keeps `FieldElement` private with no escape hatch, so `tinc-crypto::ecdh` vendors ~50 lines of 51-bit-limb field arithmetic (`fe` module) to do `(1+y)/(1-y)` without a curve check. The KATs prove it matches; the math is the same ref10 schoolbook every Curve25519 impl uses.

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
  tinc-ffi/                 # SPTPS-only bindgen wrapper, test-only
  tinc-tools/               # sptps_test, sptps_keypair, tinc binaries
                            #   src/names.rs    — Paths struct (was: separate tinc-cli crate;
                            #                     folded in because the binaries share keypair.rs)
                            #   src/cmd/*.rs    — one module per `tinc` subcommand
                            #   src/bin/tinc.rs — dispatch table + argv
xtask/                      # interop test harness
```

**Key principle:** `tinc-proto`, `tinc-sptps`, `tinc-graph` must be `#![no_std]`-compatible (or at least zero-syscall pure libraries) so they can be exhaustively fuzzed and property-tested without spinning up sockets.

---

## Phase 0 — KATs, Corpus, and SPTPS Harness (~3 weeks)

**Goal:** Lock down ground truth before writing any production Rust.

### ✅ 0a. Crypto KAT vectors + `tinc-crypto`

**Done.** Approach taken differs from the original plan in one significant way: rather than instrumenting `sptps_test`, we built a standalone generator (`kat/gen_kat.c`) that links the crypto sources directly. This avoids meson entirely — the crypto subset has no per-OS code, so a single `cc` invocation suffices.

The trick that makes it work without patching upstream: predefine the include guards (`-DTINC_SYSTEM_H -DTINC_UTILS_H ...`) so the real headers become no-ops, then force-include a 50-line shim (`kat/system.h`) that provides the three symbols the crypto actually needs (`xzalloc`, `xzfree`, `mem_eq`). Breaks loudly at compile time if upstream renames a guard, which is exactly when we want to notice.

What landed:

| Artifact | Coverage |
|---|---|
| `kat/gen_kat.c` (344 LOC) | 10 ChaPoly cases (seqno {0, 1, 256, 2³²-1, distinct-bytes}, ptlen {0, 1, 63, 64, 65, 100, 1500}), 5 ECDH pairs, 9 PRF cases (incl. outlen=128 = `sizeof(sptps_key_t)`, secret>128 = HMAC key-hash path, empty secret), 5 sign cases, 9 b64 cases |
| `crates/tinc-crypto/tests/kat/vectors.json` | Committed; `nix build .#kat-vectors` reproduces byte-identically |
| `crates/tinc-crypto` (1000 LOC, `#![forbid(unsafe_code)]`, clippy pedantic) | All 5 primitives; 7 KAT tests pass |

**`sign.c` is confirmed standard RFC 8032** — dalek's `raw_sign::<Sha512>` matches byte-for-byte, fed via `hazmat::ExpandedSecretKey`. Verify uses dalek's `verify` (not `verify_strict`) to accept the same malleable-sig edge cases the C code does.

**PEM-ish key files landed in `tinc-conf`** — see Phase 1.

### ✅ 0b. SPTPS-only FFI

**Done.** `tinc-ffi` wraps **only** `sptps.c` + its crypto deps. The protocol handlers (`protocol_*.c`) are deliberately not wrapped — they `sscanf` and immediately mutate global splay trees, there's no parse seam.

What landed:

- `build.rs` (`cc::Build`, no bindgen): compiles `sptps.c` + the same crypto file set as Phase 0a + `ecdh.c` (sptps wraps the raw `ed25519_key_exchange` in an alloc-then-compute API). Same header-guard suppression; `csrc/shim.h` force-included for `xzalloc`/`memzero`/`mem_eq`/`randomize`/`prf` prototypes plus the `ecdsa_t` forward typedef.
- `csrc/shim.c`: deterministic `randomize()` (ChaCha20 keystream, seed set per-test), our own `ecdsa_t` (96-byte blob, matches `tinc-crypto::SigningKey::to_blob`), event sink (flat byte arena, drained after each FFI return). `sizeof.c` is the one TU that includes real `sptps.h` to export `SPTPS_T_SIZE`.
- `lib.rs`: safe wrapper. `CSptps::start(role, framing, &mykey, &hiskey, label) → (Self, Vec<Event>)`; `.receive(&[u8]) → (consumed, Vec<Event>)`; `.send_record(type, &[u8]) → Vec<Event>`; `.force_kex()`. Lifetime `'k` ties session to keys (sptps_t borrows the `ecdsa_t*`, doesn't copy). Process-global `seed_rng()` + `serial_guard()` mutex.
- `tests/handshake.rs`: 6 tests — stream handshake, datagram handshake, byte-by-byte dribble feed, determinism (run twice, diff wire bytes), wrong-key SIG-verify failure, re-KEX (the SPTPS_ACK state). Top-of-file comment is a precise trace of the handshake state machine derived from reading `sptps.c`.

The six tests are also the *spec* for Phase 2: the same test bodies will run with one peer swapped for `tinc-sptps`, asserting identical event sequences.

### 0c. Wire-traffic corpus
The integration tests already spin up multi-node meshes. Add a capture shim:

- [ ] `LD_PRELOAD` hook on `send_request`/`receive_request` (or just patch `protocol.c` to `tee` to a file when `TINC_CAPTURE` env is set)
- [ ] Run `test/integration/*.py`, collect `corpus/meta/*.txt` — every meta-protocol line ever sent
- [ ] Same for control socket: `corpus/control/*.txt`

The 20 `sscanf` format strings in `protocol_*.c` are the spec; the corpus is the conformance suite.

### 0d. CI baseline
- [ ] `meson test` unchanged — the bar to clear
- [ ] Parameterize `test/integration/testlib/` to launch `${TINCD_BIN:-tincd}` so a future Rust binary slots in

**Deliverable:** `cargo test -p tinc-ffi` runs a C↔C SPTPS handshake. ~~KAT JSON files committed.~~ ✅

---

## Phase 1 — Pure Logic Crates (~4 weeks)

These have no I/O and are the safest place to start. They map almost 1:1 to existing C files.

### ✅ `tinc-proto` — done modulo intentional deferrals
| C source | Rust module | Notes |
|---|---|---|
| ✅ `protocol.h` request enum | `request.rs` | `#[repr(u8)]`, `Request::peek()` is the `atoi` dispatch |
| ✅ `protocol_edge.c` | `msg/edge.rs` | `AddEdge` (6-or-8 fields), `DelEdge` |
| ✅ `protocol_subnet.c` | `msg/subnet.rs` | Shares one struct — same wire shape |
| ✅ `protocol_misc.c` | `msg/misc.rs` | `TcpPacket`, `SptpsPacket`, `UdpInfo`, `MtuInfo`. Body-less `PING`/`PONG`/`TERMREQ` need no struct. |
| ✅ `protocol_key.c` | `msg/key.rs` | `KeyChanged`, `ReqKey` (with the extension hole), `AnsKey` |
| ✅ `subnet_parse.c` | `subnet.rs` | `str2net`/`net2str`/`maskcheck` |
| ✅ `netutl.c` (`sockaddr2str` shape) | `addr.rs` | `AddrStr` newtype — see below |
| ⏸️ `protocol_auth.c` | `msg/auth.rs` | Deferred to Phase 4 — see below |
| ⏸️ `utils.c` `b64decode_tinc` | | First consumer is the `REQ_KEY` SPTPS payload decode, which is daemon-side. The encoder is already in `tinc-crypto`. |

**What landed:** ~2400 LOC across two commits. 41 unit tests (KAT strings lifted directly from the `printf`/`sscanf` format strings) + 11 proptests at 1–2k cases each. `nom` was wrong: 23 sscanf call sites, all `%d`/`%x`/`%s` over space-separated tokens — a 60-LOC tokenizer (`tok.rs`) covers them all.

**Findings from `tinc-proto`:**

- **`AddrStr` is opaque.** `str2sockaddr` has an `AF_UNKNOWN` escape: `getaddrinfo(AI_NUMERICHOST)` failure stuffs the input string verbatim into `sa->unknown.{address,port}`, and `sockaddr2str` round-trips it. So at the parse layer, address fields are arbitrary whitespace-free tokens. `IpAddr::parse` would reject inputs the C accepts and forwards to the next hop. Resolution happens at `connect()` time, not parse time.

- **Optional trailing fields are atomic pairs.** `add_edge_h` accepts `parameter_count == 6 || == 8`, never 7. `ans_key_h` accepts `>= 7` but the 8-case (one trailing token) is UB-adjacent in C. Both modeled as `Option<(_, _)>` with both-or-neither parse.

- **`REQ_KEY` is two messages stapled.** Base `sscanf` accepts an optional fourth `%d` (sub-request type, re-uses `request_t` enum values), then `req_key_ext_h` re-scans for a fifth. We fuse: `Option<ReqKeyExt { reqno: i32, payload: Option<String> }>`. `reqno` stays raw `i32` because the C has a `default:` case that logs and continues — unknown sub-types are not parse errors.

- **`%hd`-then-check-negative is a bounds check.** `tcppacket_h` parses length as `short` then checks `< 0`. Send side emits `%d` from a `uint16_t`; values ≥ 32768 wrap negative under `%hd` and get rejected. Same bound from parsing as `i16`.

- **MAC must be tried before v6 in `str2net`.** `1:2:3:4:5:6` is valid syntax for both. Order matters; `mac_shadows_v6` test pins it.

- **`KEY_CHANGED` skips `check_id`**, just `lookup_node`, fails soft. Replicated.

**Why `protocol_auth.c` is deferred:** `id_h` parses `"%d.%d"` (major.minor) and writes `c->protocol_minor`; `ack_h` reads it back to gate 1.1 features. The parse and the connection-state mutation are *one* `sscanf`-then-if-chain in C with no clean cut point. The struct boundary is artificial there. Better done alongside the `connection_t` port in Phase 4, where the parse output feeds directly into the state it's coupled to.

**Phase 0c (wire corpus) didn't block.** The KAT strings were transcribed by hand from the format strings + integration test configs. Corpus would still strengthen the tests — promote to nice-to-have.

### ✅ `tinc-graph` — algorithms done, mutation deferred to first consumer
| C source | Rust | Status |
|---|---|---|
| `splay_tree.c`, `list.c`, `hash.h` | `BTreeMap` / `Vec` / `VecDeque` | ✅ Not ported, replaced |
| `graph.c` `sssp_bfs` | `Graph::sssp` | ✅ 18 KATs |
| `graph.c` `mst_kruskal` | `Graph::mst` | ✅ 18 KATs |
| `graph.c` `check_reachability` | — | ⏸️ Phase 5 — it's `execute_script`/`sptps_stop`/`timeout_del`, ~10 lines of actual diff logic |
| `edge.c` `edge_add`/`lookup_edge` | `Graph::add_edge` (auto-links `reverse`) | ✅ |
| `edge.c` `edge_del` | `Graph::del_edge` | ⏸️ Append-only slab can't delete in O(1); needs free-list or `slotmap`. First consumer is `del_edge_h` in Phase 5. |
| `node.c` `lookup_node`, `node_add`/`node_del` | name→`NodeId` index | ⏸️ Same: first consumer is the daemon's `*_h` handlers |
| `subnet.c` `lookup_subnet_*` (longest-prefix match) | route trie | ⏸️ First consumer is `route.c` in Phase 5 |

**What landed:** ~540 LOC Rust + 600 LOC KAT generator. The generator includes the real `splay_tree.c`/`list.c` and copies `mst_kruskal`/`sssp_bfs` bodies verbatim from `graph.c`, so divergence shows up as either a build break or a KAT diff. `nix build .#kat-graph` reproduces the committed `tests/kat/graph.json`.

The arena idea held up: `Vec<Node>`, `Vec<Edge>`, `NodeId(u32)`/`EdgeId(u32)` typed handles. No `slotmap` yet — the KAT graphs are append-only, so a plain slab is enough for now. Delete needs the free-list and lands with its first consumer.

`BTreeMap<(weight, from_name, to_name), EdgeId>` is the `edge_weight_tree` analogue. The names are *cloned into the key* to dodge a borrow tangle (iterating the map while indexing `nodes` for compares). Tens of bytes per edge; cheap.

**Findings from `tinc-graph`:**

- **The indirect→direct upgrade overwrites `distance` but not `nexthop`.** `sssp_bfs` line 180's revisit clause (`!e->to->status.indirect || indirect`) makes a direct path always win over an indirect one, *regardless of hop count*. Then lines 188-191 gate `nexthop`/`weighted_distance` separately on a stricter condition (same-hops-and-lighter). So a node first reached indirectly at distance 1, then upgraded to direct at distance 3, ends up with `distance=3, weighted_distance=<from the dist-1 path>`. Internally inconsistent — but `via` (the UDP hole-punch target) is set unconditionally on revisit, and that's what matters. The KAT `diamond_indirect` pins it; `indirect_upgrade_can_increase_distance` is the dedicated trip-wire.

- **Iteration order is part of the contract.** Per-node edges are `splay_each`-ordered by `to->name`; the global edge set by `(weight, from->name, to->name)`. When two paths tie on `(distance, weighted_distance, indirect)`, the alphabetically-earlier neighbor wins. We sort the per-node `Vec` on insert (cached `to_name` field on `Edge` to avoid the comparator borrowing `nodes`).

- **Kruskal-without-union-find rewinds.** Progress-after-skip resets the iterator to head. Without it, a light edge between two unvisited nodes is skipped on the first pass and never revisited. KAT `mst_rewind`.

- **One-way edges are skipped.** `!e->reverse → continue` in both algorithms. They exist transiently between the two halves of an `ADD_EDGE` pair. KAT `oneway`.

- **`sssp` returns a side table, not in-place mutation.** The C writes routing fields directly into `node_t`; we return `Vec<Option<Route>>` indexed by `NodeId`. Two reasons: borrowck (mutating the slab while iterating it), and the daemon wants to diff old-vs-new before applying — `check_reachability`'s up/down detection becomes a clean `old.is_some() != new.is_some()`.

**Testing approach was right.** "Generate random graphs, diff the tables" — except FFI was the wrong harness. `graph.c` reads `node_t` fields scattered across a 200-byte struct embedded in global splay trees; building those from Rust would mean replicating half of `node.c`. The standalone C generator (8 hand-built + 10 random cases → JSON) is the same shape as `kat/gen_kat.c` and dodges all of it. Hand-built cases each pin one branch (the two diamonds, the rewind, the one-way skip, the asymmetric weight); random cases catch interactions.

### ✅ `tinc-conf`
| C source | Rust | Status |
|---|---|---|
| `conf.c` `parse_config_line` | `parse::parse_line` | ✅ All 4 separator forms (`K=V`, `K V`, `K = V`, `K\t=\tV`) parse identically |
| `conf.c` `read_config_file` | `parse::parse_file` | ✅ PEM-block skip (`-----BEGIN`..`END`), `#` comments, CRLF |
| `conf.c` `config_compare` + `lookup_config{,_next}` | `Config` (sorted `Vec`) | ✅ Full 4-tuple ordering preserved |
| `conf.c` `get_config_{bool,int,string}` | `Entry::get_{bool,int,str}` | ✅ `get_int` tightened: rejects trailing garbage |
| `ecdsa.c` `read_pem` / `ecdsagen.c` `write_pem` | `pem::{read,write}_pem` | ✅ `Zeroizing` everywhere keys flow |
| `conf_net.c` `get_config_subnet` | — | ⏸️ Daemon glue: `tinc-proto::Subnet::from_str` already does the parse |
| `conf.c` `get_config_address` | — | ⏸️ Phase 5 — calls `getaddrinfo` |
| `conf.c` `read_server_config` (`conf.d/` scan, `cmdline_conf` merge) | — | ⏸️ **Next** — fsck's last blocker. Pieces (`parse_file` + `Config::merge`) here. |
| `tincctl.c` `variables[]` (74 entries) | `vars::{VARS, VarFlags, lookup}` | ✅ Order preserved incl. alpha-break; sed-diff verified. +3 invariants the C never asserts |
| `names.c` | — | ✅ `tinc-tools::names` — first consumer was `tinc init`, not the daemon. Subset: `confbase`/`confdir` only; `pidfilename`/`unixsocketname` come with 5b. |
| `conf.c` `append_config_file` | — | ⏸️ `tincctl` territory, not the daemon |

**What landed:** ~740 LOC parse + ~430 LOC PEM, 33 unit + 3 proptest. The PEM body is `b64encode_tinc` (LSB-first — see Phase 0a finding 2); the codec was already KAT-locked, so the only thing tested here is framing: 48-byte chunks → 64-char lines on write, arbitrary line length on read, `strncmp` prefix match for the BEGIN type, END type unchecked.

"Straightforward; the format is trivial" was almost right — the line tokenizer is 30 lines of careful index arithmetic, but the *tree* is where the sharp edges hide. Three findings:

- **`config_compare` sorts by `line` before `file`.** The 4-tuple is `strcasecmp(var)` → `cmdline-before-file` → **`line`** → `strcmp(file)`. So `conf.d/a.conf:5` sorts *after* `conf.d/b.conf:3` — line number wins, filename only tiebreaks within the same line. This is the iteration order for `Subnet`/`ConnectTo`/`Address`, which are multi-valued, which means it's protocol-adjacent (a peer's `hosts/foo` is parsed into a config tree, and `Subnet` order can affect which route wins). Tested explicitly in `lookup_line_before_file`.

- **Values starting with `=` don't round-trip** when the separator is whitespace-only. `"A\t=0"` → variable `A`, value `0` — the separator scan eats `\t` then the optional `=`. The C does the same; proptest found it on the 27th case. Not a bug because tinc never emits `=`-prefixed values (its b64 has no padding, addresses don't start with `=`, port numbers don't). The round-trip property holds over the constrained generator. Noted because a Phase 4 caller adding a new config key needs to know the value space.

- **The PEM stripper in `read_config_file` is what makes `hosts/foo` files work.** Same file holds `Address = 1.2.3.4` lines *and* the public key armor; the parser steps over `-----BEGIN`..`END` without treating the base64 body as `key=value`. Then `read_pem` reads the *same file* a second time and ignores everything before `BEGIN`. Two passes, two different lenses. Tested in `file_skips_pem` + `read_skips_preamble` + the `pem_skips_preamble` proptest.

The splay tree became a `Vec` + stable sort. `O(n)` lookup is fine — config files are tens of entries; the syscall to open them costs more than the scan.

---

## Phase 2 — Crypto & SPTPS (~6 weeks, highest risk)

`sptps.c` (774 LOC) is the most security-sensitive module. It is self-contained, but **every primitive it depends on is non-standard.** Budget two days per primitive to implement, two weeks per primitive to be *certain* it's right.

### ✅ `tinc-crypto` — five bespoke primitives (done in Phase 0a)

Landed API — close to the sketch but informed by what the KATs demanded:

```rust
// chapoly.rs — ~160 LOC
pub struct ChaPoly { key: [u8; 64] }
impl ChaPoly {
    pub fn new(key: &[u8; 64]) -> Self;
    pub fn seal(&self, seqno: u64, pt: &[u8]) -> Vec<u8>;        // ct ‖ tag[16]
    pub fn open(&self, seqno: u64, sealed: &[u8]) -> Result<Vec<u8>, OpenError>;
}

// ecdh.rs — ~430 LOC (incl. ~180 LOC vendored field arithmetic)
pub struct EcdhPrivate { expanded: [u8; 64] }
impl EcdhPrivate {
    pub fn from_seed(seed: &[u8; 32]) -> (Self, [u8; 32]);       // pub is Ed25519 point
    pub fn from_expanded(expanded: &[u8; 64]) -> Self;           // for on-disk keys
    pub fn compute_shared(self, peer_ed_pub: &[u8; 32]) -> [u8; 32];  // consumes self
}

// prf.rs — ~90 LOC
pub fn prf(secret: &[u8], seed: &[u8], out: &mut [u8]);

// sign.rs — ~150 LOC
pub struct SigningKey { expanded: [u8; 64], public: [u8; 32] }
impl SigningKey {
    pub fn from_blob(blob: &[u8; 96]) -> Self;                   // on-disk format
    pub fn from_seed(seed: &[u8; 32]) -> Self;                   // KAT/gen only
    pub fn sign(&self, msg: &[u8]) -> [u8; 64];
}
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<(), SignError>;

// b64.rs — ~130 LOC
pub fn encode(src: &[u8]) -> String;          // +/ alphabet
pub fn encode_urlsafe(src: &[u8]) -> String;  // -_ alphabet
pub fn decode(src: &str) -> Option<Vec<u8>>;  // accepts both, even mixed
```

Implementation notes that survived contact with the KATs (the doc-comments in each module are the authoritative reference; this is the digest):

- **chapoly:** `ChaCha20Legacy` (64/64 layout) + `Poly1305::compute_unpadded`. Nonce is `seqno.to_be_bytes()`. Block 0 keystream → Poly1305 key, then `seek(64)` to block 1 for the actual cipher. The `Vec`-returning API is fine for now; an in-place variant is a Phase 5 perf concern.

- **ecdh:** the original plan's `CompressedEdwardsY::decompress()` path **does not work** because it validates the point. `key_exchange.c` doesn't — it does raw `fe_frombytes` (mask bit 255) → `(1+y)/(1-y)` → ladder. We vendor the field math in a private `fe` module: 5×51-bit limbs, schoolbook mul with ×19 wrap, ref10's Fermat inversion chain. Runs once per handshake so performance is irrelevant; the KATs are the correctness proof. dalek's `MontgomeryPoint::mul_clamped` handles the ladder itself.

- **prf:** Mirrors the C buffer layout exactly (`[A(i) | seed]` with in-place overwrite) because that's the simplest way to be sure the `A(0)=zeros` quirk is right. `Hmac::<Sha512>::new_from_slice` handles the long-key-gets-hashed path internally, so we don't replicate `prf.c`'s manual HMAC.

- **sign:** `hazmat::ExpandedSecretKey::from_bytes` + `raw_sign::<Sha512>`. The expanded key's low half is already clamped on disk; dalek re-clamps internally (idempotent). **Verify uses `verify`, not `verify_strict`** — strict rejects non-canonical S and small-order R that `verify.c` accepts; that's a divergence we must not introduce.

- **b64:** LSB-first packing (`triplet = b[0]|b[1]<<8|b[2]<<16`, emit low 6 bits first) is the deeper issue; the dual-alphabet decoder is the easy part. Hand-rolled both directions.

**PEM framing landed in `tinc-conf`** (Phase 1). The `signing_key_roundtrip` test there does the full `SigningKey::from_seed` → `to_blob` → `write_pem` → `read_pem` → `from_blob` → same signature on same message.

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

**Testing — this is where the budget went:**
1. ✅ **KAT:** Every `tinc-crypto` primitive passes Phase 0a vectors. Gate before any SPTPS code.
2. ✅ **Self-interop:** Rust initiator ↔ Rust responder. (`tinc-sptps/tests/vs_c.rs::rust_self_handshake`)
3. ✅ **Cross-interop:** Rust↔C in lockstep, no sockets. `byte_identical_wire_output` is stronger than the plan asked for — not just "handshake completes", but "same RNG seed → same wire bytes". Ed25519 accepts any valid sig over the right message; byte-identity proves we *built* the right message.
4. ✅ **Rust↔Rust socket interop:** `tinc-tools/tests/self_roundtrip.rs`. Stream + datagram + 64KB reassembly. See `tinc-tools` below.
5. ✅ **Rust↔C socket interop:** `tests/self_roundtrip.rs` 2×2 matrix — each role can be C or Rust. Gated on `TINC_C_SPTPS_TEST` env var. `nix build .#sptps-test-c` builds the C side (meson, nolegacy mode, no openssl).
6. ⏸️ **Fuzz:** `cargo-fuzz` on `Sptps::receive`. The replay window and length checks are where the C has had CVEs.

### ✅ `tinc-tools` — first shippable binaries

| Binary | C source | Status |
|---|---|---|
| `sptps_keypair` | `sptps_keypair.c` (140 LOC) | ✅ `OsRng` seed → `SigningKey::from_seed` → `tinc_conf::write_pem` × 2 |
| `sptps_test` | `sptps_test.c` (747 LOC) | ✅ Spine: `poll()` loop bridging stdin↔socket through `Sptps`. Dropped: `--tun`, `--packet-loss`, `--special`, Windows stdin-thread. |

The integration test (`tests/self_roundtrip.rs`) spawns both binaries as subprocesses — same shape as `test/integration/sptps_basic.py`, but a `cargo test`. Four cases: `stream_mode`, `datagram_mode`, `stream_swapped_roles`, and `stream_large_payload` (64 KiB — bigger than any TCP segment, forces kernel-level fragmentation, exercises the SPTPS stream-framing reassembly. `sptps_basic.py` only sends 256 bytes and never sees a partial record).

**The binaries are `#![forbid(unsafe_code)]`.** nix 0.29 has an asymmetry: `poll()` takes `BorrowedFd` (safe via `AsFd`), `read()` still takes `RawFd` (the i32, also safe but untyped). The obvious-but-wrong reach was `unsafe { BorrowedFd::borrow_raw(0) }` for stdin; the right answer is `AsFd` for the typed handle and `AsRawFd` only at the `read()` call site.

Three findings:

- **UDP has no FIN.** The C "accepts" a UDP client by `recvfrom(MSG_PEEK)` to learn the peer address, then `connect()` to filter — the peeked datagram stays in the buffer for the main loop's first `recv()`. On shutdown the server `poll()` blocks forever; `sptps_basic.py` reads N bytes then `server.kill()`. We do the same, and that's correct: a UDP listener with no application-layer goodbye has no other option. (`reap(server, expect_clean: !datagram)`.)

- **Dropping the read end of a child stderr pipe = `SIGPIPE`.** `wait_for_port` initially took `stderr` by value and dropped it on return → server's next `eprintln!("Connected")` got `EPIPE` → `SIGPIPE` → dead server. The 0.01s test duration was the tell — too fast for any real I/O. **This will bite the daemon's `script.c` port** (`popen()` of `tinc-up`, same shape: spawn, read until satisfied, drop pipe, child writes more). Fix here: hold the handle for the child's lifetime, drain to EOF on a thread. Noted forward.

- **`Stdin::lock().read()` goes through a `BufReader`.** Would buffer past the requested size, breaking the `readsize=1460` datagram chunking (one stdin read → one wire datagram). C uses raw `read(2)`; we use `nix::unistd::read()` on `stdin.as_raw_fd()`.

**"Listening on {port}...\n" is API.** `sptps_basic.py` regexes it to find the bound port (it passes `0` for ephemeral). Don't reword.

#### Cross-impl 2×2 matrix

`tests/self_roundtrip.rs` parameterizes the binary path per role. Set `TINC_C_SPTPS_TEST` / `TINC_C_SPTPS_KEYPAIR` to enable; unset → the `cross_*` tests skip silently:

```sh
C=$(nix build .#sptps-test-c --no-link --print-out-paths)
TINC_C_SPTPS_TEST=$C/bin/sptps_test \
TINC_C_SPTPS_KEYPAIR=$C/bin/sptps_keypair \
  cargo test -p tinc-tools cross
```

Why not `sptps_basic.py`: it only knows one `SPTPS_TEST_PATH`. Same impl both sides. The whole point of cross-impl is *different* impls per role.

The matrix is asymmetric in what each cell tests:

| server | client | tests |
|---|---|---|
| Rust | Rust | the binary works at all (always run, 4 tests) |
| Rust | C | Rust *responder* SPTPS path |
| C | Rust | Rust *initiator* SPTPS path |
| C | C | control — if this fails, the harness or C binary is broken |

Plus `cross_pem_read` (private-key cross-reads, the `ecdsa.c` struct-overlap layout) and `cross_stream_large_payload` (64KB through both off-diagonal cells).

**This is a stronger claim than `tinc-sptps/tests/vs_c.rs`.** vs_c proves byte-identity given the same RNG seed. Cross-impl proves wire compatibility with *independent entropy* on each side — the C and Rust binaries don't share an RNG, don't share an address space, communicate only through TCP/UDP bytes. If a Rust SPTPS implementation passed vs_c (same wire bytes, same RNG) but failed cross-impl (independent RNG), the bug would be: the wire format is right but the *verification* is wrong (e.g. signature check succeeds against own pubkey but not peer's). vs_c can't catch that; both sides see the same key material because they're seeded identically. Cross-impl catches it.

**TODO: hermetic `checks.cross-impl`.** Needs `rustPlatform.buildRustPackage` to vendor deps; a naive `runCommand` + `cargo test --offline` dies in the sandbox (no registry index). For now CI uses the devshell invocation above. Tracked.

**TODO: align `cargo fmt` ↔ `flake-fmt`.** They're the same rustfmt binary (`--version` reports the rustfmt crate version 1.8.0, not the toolchain 1.94.0 — false alarm). The reflows in `83c4dbf6` and `540efcdd` were stale-file noise: `cargo fmt` skips files cargo doesn't see as part of the build graph; treefmt globs `*.rs`. The diffs ride along; need a `rustfmt.toml` to pin edition or just stop running both.

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

## Phase 4 — `tinc` CLI (split: 4a filesystem, 5b RPC)

`tincctl.c` is 3.4k LOC but on closer inspection it splits cleanly
into two halves with opposite dependency profiles:

| Half | Commands | Needs daemon? | LOC |
|---|---|---|---|
| **Filesystem** | `init`, `generate-keys`, `export`/`import`, `exchange`, `edit`, `fsck`, `sign`/`verify`, `network` | ❌ pure config-file munging | ~2000 |
| **Daemon RPC** | `dump`, `top`, `pcap`, `log`, `reload`, `connect`/`disconnect`, `purge`, `debug`, `retry`, `pid`, `info` | ✅ control socket | ~1000 |

The `connect_tincd()`-calling commands in `tincctl.c`: 18 of 30. The
rest never touch a socket. (`stop` is a borderline case — it sends
`SIGTERM` after reading the pidfile, no protocol.)

### Phase 4a: Filesystem half — **Ship #2**

Lands now, before the daemon. The filesystem commands have no
testability problem: their inputs are argv + on-disk files, their
outputs are on-disk files. Integration tests via `tempdir` + actual
file diff, same shape as `tinc-tools/tests/self_roundtrip.rs`.

| C source | Rust |
|---|---|
| `tincctl.c` command dispatch | hand-rolled `match argv[1]` (same reasoning as `sptps_test`: clap is 10× deps for ~15 subcommands) |
| `tincctl.c` `cmd_init` | `cmd/init.rs` — `mkdir`, write `tinc.conf`, gen Ed25519, write host file, stub `tinc-up` |
| `tincctl.c` `cmd_generate_ed25519_keys` | ✅ `cmd/genkey.rs` — `disable_old_keys` then append. Plan said "thin wrapper"; the wrapper is thin, the disable function is the substance |
| `tincctl.c` `cmd_export`/`cmd_import` | ✅ `cmd/exchange.rs` — `Name = X` line is the framing, `#---63 dashes---#` separates hosts. Plan said `BEGIN HOST` markers; wrong, the C uses `Name =` itself as the marker |
| `tincctl.c` `cmd_sign`/`cmd_verify` | ✅ `cmd/sign.rs` — `golden_c_vector` is the proof: same key + same body + same `t` → same bytes |
| `fsck.c` | `cmd/fsck.rs` — see validated structure below; was underestimated |
| `names.c` | `names.rs` — `Paths` struct. **First consumer.** Was Phase 5 deferral; pulled forward because `tinc init` literally can't function without `confbase` |
| `fs.c` `makedirs`/`fopenmask` | `names.rs` methods — `fs::create_dir_all` + `OpenOptions::mode()` |

#### ✅ What landed (commit `tinc-tools: tinc init — first 4a...`)

| File | LOC | What |
|---|---|---|
| `src/names.rs` | ~280 | `Paths` struct + `check_id`. The `make_names()` globals materialized as a function return value. |
| `src/cmd/mod.rs` | ~90 | `CmdError` enum, `io_err()` helper. One error type for all 4a commands. |
| `src/cmd/init.rs` | ~500 | `tinc init NAME`. makedirs (with chmod-on-exists), tinc.conf write, keygen, PEM private (0600 `O_EXCL`), `Ed25519PublicKey =` config line, tinc-up stub (0755). |
| `src/bin/tinc.rs` | ~300 | Hand-rolled argv (`+` getopt mode — stop at first non-option), dispatch table, `NETNAME` env fallback, `.` netname normalization, traversal guard. |
| `tests/tinc_cli.rs` | ~510 | 17 integration tests through the binary. The load-bearing one is `cross_init_key_loads_in_c`. |

**`CONFDIR` resolved as `option_env!("TINC_CONFDIR")` at compile time, default `/etc`.** The C bakes meson's `dir_sysconf`; Rust has no configure step. Packagers set the env var in their build (Nix derivation does this via `env`); a bare `cargo build` gets `/etc`. XDG fallback was considered and rejected — the C doesn't do it, and adding it is a separate behavioral decision (tracked below).

**Three findings:**

- **`init` writes the public key as a config line, not a PEM file.** `hosts/NAME` gets `Ed25519PublicKey = <tinc-b64>` — read by *peers* via the config parser, not via `read_pem`. The private key *is* PEM (read by the daemon's `net_setup.c` via `read_pem`). Different readers, different formats. `keypair::write_pair` (used by `sptps_keypair`) does PEM-both-sides; `cmd::init` does PEM-then-config. The b64 in the config line is **tinc's LSB-first variant** — standard base64 there would fail `ecdsa_set_base64_public_key` and the peer rejects your key. `cross_init_key_loads_in_c` proves the round-trip: `tinc init` → extract pubkey from `hosts/NAME` → decode tinc-b64 → re-wrap as PEM → hand to C `sptps_test` → handshake completes.

- **`makedir` chmod-on-exists is load-bearing.** `fs.c:10-14`: `mkdir; if EEXIST chmod`. An existing `/etc/tinc/myvpn` with mode `0777` (because the user ran shell `mkdir` first) gets clamped to `0755`. We replicate it. Test: `makedir_clamps_mode`.

- **Testing env-var → paths is awkward.** `NETNAME=foo tinc init alice` resolves to `/etc/tinc/foo`, which a test can't write. First attempt: assert `foo` appears in the EPERM error path. Wrong — `makedir(confdir)` runs before `makedir(confbase)` (parent before child), so the error is on `/etc/tinc` and the netname never makes it into a message. Second attempt (the one that works): use the *both-given warning* as the observable. `NETNAME=foo tinc -c /tmp/x init alice` emits "Both netname and configuration directory given" iff `Paths::for_cli` saw `netname.is_some()`. Side-channel observability when you can't observe the direct effect.

**Intentional deviations from C** (see `cmd/init.rs` module doc for full rationale):

| Dropped | Why |
|---|---|
| Interactive name prompt | Exists for `tinc> ` shell mode reusing `cmd_init`; we don't have shell mode. When 5b adds it, the prompt becomes a shell-layer concern — shell prompts → calls `init::run("alice")`. |
| `check_port` (try-bind-655, random fallback) | Best-effort QoL that often picks a port your firewall doesn't allow. Better to fail loudly at first daemon start. |
| RSA keygen | `DISABLE_LEGACY` is permanently on. |

#### ✅ What landed (commit `tinc-tools: export/import/exchange...`)

| File | LOC | What |
|---|---|---|
| `src/cmd/exchange.rs` | ~920 | All five host-shipping commands. `get_my_name` via `tinc-conf` (the C copy-pastes the strcspn/strspn tokenizer; we don't), `export_one`/`export_all`/`import` with `impl Write`/`BufRead` parameterization. |
| `src/names.rs` | +152 | `replace_name` — `$HOST`/`$FOO` env-var expansion + non-alnum→`_` squash. `nix::unistd::gethostname` for the `$HOST` fallback. |
| `src/bin/tinc.rs` | +156 | 5 dispatch entries; `Globals { force }` threaded through dispatch sig; `--force` parsing. |
| `tests/tinc_cli.rs` | +239 | 8 integration tests. `export_import_workflow` is the contract test — alice's export → bob's import → byte-identical `hosts/alice`. |

**The blob format wasn't what the plan guessed.** Plan said `#-- BEGIN HOST NAME --#` markers. Actually: `Name = X` *is* the framing — export injects it, import parses it. The `#---63 dashes---#` line is the *separator* between hosts in `export-all`, not a per-host wrapper. Shape:

```
Name = alice
<hosts/alice contents, with any Name= lines stripped>

#---------------------------------------------------------------#
Name = bob
<hosts/bob contents>
```

**Three findings:**

- **`replace_name`'s squash is asymmetric on purpose.** Non-alnum→`_` only fires for the `$`-prefix branch — the C's for-loop is *inside* `if(name[0]=='$')`. So `Name = my-laptop` fails `check_id` (dash rejected), but `Name = $HOST` on a machine called `my-laptop` succeeds (becomes `my_laptop`). It's a convenience for hostnames, not a general sanitizer. `replace_name_literal` vs `replace_name_envvar_squashes` tests pin the asymmetry.

- **The `Name =` filter on export is a `strcspn` length check, not a prefix match.** `strcspn(buf, "\t =") != 4 || strncasecmp(buf, "Name", 4)`. So `Namespace = foo` survives (strcspn=9), `Named = foo` survives (strcspn=5), and ` Name = foo` with a leading space *also* survives (strcspn=0) — even though `tinc-conf` would parse it as a `Name` line. The leading-space case is a C bug; replicated, because the cost of fixing is a behavioral diff and the cost of replicating is one comment. Test: `name_line_filter`.

- **import's `Name = ` match is `sscanf`-exact.** `sscanf("Name = %s")` matches `Name = foo` only — `Name=foo`, `name = foo`, ` Name = foo` all return 0. Export always writes the canonical form so this is invisible in practice; replicated because looser matching could turn a host-file comment containing `Name=something` into a section boundary. Test: `import_name_format_is_exact`.

**One intentional deviation: `export-all` sorts.** The C uses `readdir` order (filesystem-dependent — ext4 ≠ tmpfs ≠ btrfs). We sort. `tinc export-all > all.txt` is now diffable across machines, and tests don't depend on tmpfs hash order.

**`Globals` struct, not `Paths` extension.** `--force` (and eventually `tty`) are behavior toggles, not paths. Different concern; different lifetime — a future shell mode resets `force` per-command but keeps `Paths`. Threading as a struct (vs the C's bare global) means a command's signature *says* whether it cares: `cmd_init(_, _: &Globals, _)` vs `cmd_import(_, g: &Globals, _)`.

**`exchange` doesn't `fclose(stdout)`.** The C does `if(!tty) fclose(stdout)` after export so the pipe's other end sees EOF before import starts. We don't — the OS pipe buffer means import can start reading while export is writing (full-duplex `exchange | ssh peer exchange` doesn't deadlock unless export-side output exceeds the pipe buffer, which is 64KB on Linux, enough for ~1000 host files). If it ever hangs, revisit; the C's explicit close may be a workaround for exactly that. Noted in `cmd_exchange`'s adapter doc.

#### Remaining 4a commands — guesses validated against C source

*After the export/import format guess turned out wrong, went back and read every remaining 4a function before estimating.*

##### ✅ `generate-ed25519-keys` — landed (commit `tinc-tools: generate-ed25519-keys...`)

The validated plan was right: `disable_old_keys` is the substance, the wrapper is 5 lines. **~700 LOC** including 14 unit tests. The `disable_old_keys` function itself is ~180 LOC of which ~100 is comments mapping each block to `keys.c` line numbers — the function is too easy to almost-get-right (the END check runs *after* the write, the no-match path unlinks rather than renames, etc.).

**One finding worth keeping outside the commit message:** `open_append` does NOT `fchmod` after open. C `fopenmask` does (`fs.c:85` — `if(perms & 0444) fchmod`, which is always-true for any sane mode). So C clamps the private key back to `0600` on every genkey. If you `chmod 0400` (read-only-even-owner — paranoid but legal), C silently undoes it. We respect it. This is the rare "C behavior is the bug" call — recorded in `genkey.rs` because if a future fsck check warns on `0400` private keys, the asymmetry surfaces ("why did rotation stop fixing this?") and the answer is here.

`TmpGuard` is hand-rolled, not `tempfile::NamedTempFile`. The latter picks `tmp.XXXXXX` in a system tempdir; C uses `<path>.tmp` in the *same dir as the target* — necessary for `rename(2)` to be atomic (same filesystem) and so a crash leaves an obviously-stale `ed25519_key.priv.tmp` not a mystery file in `/tmp`. The crate's `NamedTempFile::new_in()` would solve the same-dir part but not the predictable-name part. Hand-rolling is one struct + one Drop impl.

`disable_old_keys` is now `pub` — `fsck` (still pending) uses it for the keypair-coherence-fix path.

##### ✅ `sign` / `verify` — landed (commit `tinc-tools: sign/verify — byte-identical...`)

The validated guesses held: trailer with leading space, `time()` parameterized, `get_pubkey` replaced by `tinc-conf` (the fourth tokenizer collapses to `Config::lookup("Ed25519PublicKey")`). Three tests pin the format, in increasing strength:

| Test | Proves |
|---|---|
| `trailer_leading_space` | the space is load-bearing (constructs a sig over the spaceless trailer, watches it fail) |
| `verify_tampered_time` / `_signer_name` | the trailer scheme works (header fields bound by sig — reconstruction differs, verify fails) |
| `golden_c_vector` | **it's the same format as C, not just a format** |

The golden test was a find. The plan said "we don't have a C `tinc` binary, test the envelope by self-roundtrip + tamper." That was the planned floor. Then `test/integration/cmd_sign_verify.py` turned out to have a fixed-key, fixed-time blob (`SIGNED_BYTES`, `t=1653397516`). Ed25519 is deterministic: same key + same message = same sig. Transcribe the constants, set up a confbase with the same key, call our `sign(paths, body, 1653397516, ...)`, `assert_eq!(ours, SIGNED)`. Passes. **The artifact IS the cross-impl test.** Same kind of free win as `kat-vectors` — the C side already did the work, we just consume it.

The binding-via-reconstruction click: `verify` doesn't *check* a trailer against anything. There's no trailer in the blob to check. It builds a fresh one from the header's name/time and feeds it to the crypto. The signature *is* the check — any header lie produces a different reconstruction, different message, sig fails. The header is bound *as a side effect of verify being lazy*.

One deviation noted at point of decision: header parse is split-on-single-space (5 fields exact), not sscanf's zero-or-more-whitespace. C accepts `Signature=alice 1 sig` (sscanf format-string space matches zero chars). We don't. `sign` always emits canonical form; only hand-editing hits this.

**One thing to revisit if `fsck` keypair-coherence reuses pubkey loading:** `load_host_pubkey` is currently `cmd/sign.rs`-private. fsck does the same dance (config-line then PEM-fallback, `keys.c:315-340`). When fsck lands, lift it to `cmd/mod.rs` rather than duplicating.

##### `fsck` — was 400 LOC; **is 679, and structurally heavier than guessed**

**The plan undercounted by a wide margin.** Real shape:

- **679 LOC**, ~7 of which are `DISABLE_LEGACY` so call it ~500 effective
- Not just `if(!x) eprintln!`. Four distinct check categories with their own logic:
  1. **Keypair coherence** (`test_ec_keypair`, `keys.c:380`): derive pubkey from private, compare to the `Ed25519PublicKey =` in `hosts/NAME`. If mismatch, *with `--force`*, **rewrite the host file** — `disable_old_keys` then append correct pubkey. fsck *fixes*, not just diagnoses. (`ask_fix_ec_public_key`, `keys.c:269`.)
  2. **Per-variable validity** (`check_conffile`, `keys.c:122`): walks the config, for each entry calls `tinc_conf::lookup_var` (✅ landed), warns if a server-only var appears in a host file or vice-versa, warns on obsolete, **counts duplicates** and warns when a non-`MULTIPLE` var appears twice (the only place that surfaces silent-first-wins). Straight loop now: `for entry in cfg { match lookup_var(&entry.variable) { ... } }`.
  3. **Script executability** (`check_script_confdir` + `check_script_hostdir`, `keys.c:448-528`): scan confbase and `hosts/` for `tinc-up`, `tinc-down`, `host-up`, `host-down`, `subnet-up`, `subnet-down`, `<hostname>-up`, `<hostname>-down`; check `access(R_OK|X_OK)`; with `--force`, `chmod 0755`.
  4. **File modes** (`check_key_file_mode`, `keys.c:205`): warn if private key isn't `0600`.

- **Uses `read_server_config` + `read_host_config`** (`conf_net.c`), the daemon's config-tree builder — not the bare `parse_file`. The merge-multiple-files-and-conf.d wrapper is **~50 LOC** and the pieces are already here. Pull it forward.

Remaining fsck cost: **~400 LOC fsck logic + ~50 LOC config-tree wrapper**. The `variables[]` table came in over estimate (~500 LOC vs ~100 guessed), but ~half of that is module-doc + structural-invariant tests we didn't plan for and the C never had. Data portion was ~150 LOC.

| Command | Blocked on | Validated estimate |
|---|---|---|
| `fsck` | ~~`disable_old_keys`~~ ✅ ~~pubkey loader~~ ✅ ~~`variables[]`~~ ✅ — only `read_server_config` wrapper left (→ `tinc-conf`, ~50 LOC) | **medium (~450 LOC)** |
| `edit` | `$EDITOR` spawn + post-edit `reload` (5b for the reload half) | small-but-5b-coupled |

**Ship order:** `read_server_config` wrapper → `fsck`. `edit` defers to 5b.

The table also unblocked **`set`/`get`'s parse half** (`lookup_var` does name validation + canonicalization; `VAR_SAFE` does the `--force` gate). Not building them yet — the daemon-reload half is 5b — but the table sits in `tinc-conf` where both reach it.

### Phase 5b: RPC half + new control protocol

Blocked on the daemon existing. The current C control protocol is the
meta-protocol re-purposed — `^` prefix in the ID name field tells
`id_h` "this is a control connection, not a peer". Problems:

- **Auth is a bearer token in the pidfile.** Pidfile is
  `0644`-ish; anyone who can read it can `tinc stop`. Should be
  `SO_PEERCRED` — kernel tells you the connecting uid, no token.
- **Overloads `connection_t`.** Control connections sit in
  `connection_list` next to real peers, with `if(status.control)
  continue` sprinkled everywhere.
- **Streaming printf format.** `dump_nodes` does one `send_request`
  per node, sentinel-terminated. CLI parses line-by-line until it
  sees `18 3` (`CONTROL REQ_DUMP_NODES` empty payload). No length
  prefix, no error channel.

**The control protocol has no compatibility constraint** — CLI and
daemon ship together, and a 1.0.x peer never speaks it. We can
replace it. Proposal:

```rust
// AF_UNIX, line-delimited JSON. Auth via SO_PEERCRED.
// Windows: named pipe with ACL (same security model, no token).
#[derive(Serialize, Deserialize)]
enum CtlRequest {
    Stop, Reload, Retry, Purge,
    DumpNodes, DumpEdges, DumpSubnets, DumpConnections,
    SetDebug(u8),
    Connect(String), Disconnect(String),
    Subscribe(Stream),  // Pcap/Log — connection stays open
}
enum CtlResponse {
    Ok, Err(String),
    Nodes(Vec<NodeDump>),  // one message, not N+1 lines
    Edges(Vec<EdgeDump>),
    // ...
}
```

Daemon side: ~100 lines, one `match` on `CtlRequest` calling the
same internals (`dump_nodes`, `reload_configuration`, etc.). CLI
side: `serde_json::to_writer` + `from_reader`. Compare to 240 lines
of `control.c` + the `sscanf` jungle in `tincctl.c` cmd_dump.

| C source | Rust |
|---|---|
| `info.c`, `top.c` | control-socket queries + `ratatui` for `tinc top` |
| `invitation.c` | invitation URL generation/consumption — **uses SPTPS from Phase 2**, also writes config (straddles 4a/5b) |
| `tincctl.c` `cmd_dump` family | one fn per `CtlRequest` variant |
| `control.c` | daemon-side `match` |
| `ifconfig.c` | platform `ip`/`ifconfig` shelling-out for `tinc-up` script generation (used by invitation, not by core RPC) |

**Windows caveat unchanged:** named pipe, `windows-sys` raw
`CreateFileW`. ~100 LOC behind `#[cfg(windows)]`.

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
| ChaCha20 (DJB 64-bit nonce) | `chacha20` 0.9 | `ChaCha20Legacy` is unconditionally exported — ~~`legacy` feature~~ doesn't exist |
| Poly1305 raw | `poly1305` | `compute_unpadded`, not the AEAD wrapper |
| Curve ops | `curve25519-dalek` 4 | `MontgomeryPoint::mul_clamped` for the ladder. **`FieldElement` is private** — the unvalidated Edwards→Montgomery map is hand-rolled in `tinc-crypto::ecdh::fe`. |
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
| `chacha20` crate drops `ChaCha20Legacy` | Low | No feature flag involved (unconditional export in 0.9). Pin `=0.9` and check on bumps. Fallback: vendor DJB ChaCha (~200 LOC). |
| `curve25519-dalek` exposes `FieldElement` | Would let us delete the vendored `fe` module | Monitor; the dalek maintainers have discussed it. Until then, the ~180 LOC stays. |
| `net_packet.c` perf regression | Medium | Benchmark gate in CI; the C code isn't heavily optimized so matching it is realistic |
| Windows TUN driver churn | Medium | Switch to wintun (WireGuard's); it's better-maintained than TAP-Windows anyway |
| `route.c` packet-parsing edge cases (IPv6 ext headers, ARP, NDP) | Medium | Corpus capture from real traffic + fuzz. Consider `etherparse` crate for the parsing. |
| Scope creep into "let's redesign the protocol" | High | **Hard rule:** Phase 1–5 is byte-compatible port only. Protocol v18 ideas go in a separate doc. |

---

## Suggested Order of Shipping

1. ✅ **`sptps_test` + `sptps_keypair` in Rust** — proves crypto interop. **Shipped as `tinc-tools`.** Rust↔Rust + Rust↔C on real sockets (2×2 matrix, gated on `TINC_C_SPTPS_TEST`). Cross-impl is a stronger claim than vs_c: independent entropy on each side, only TCP/UDP bytes between binaries.

   Three things the in-process differential test couldn't catch:

   - **`OsRng` for real.** First time non-seeded entropy flows through key derivation.
   - **TCP record splitting.** `stream_large_payload` pushes 64KB; the kernel fragments it, the SPTPS stream framing reassembles. The Phase 2 byte-identity test pumps whole records and never sees a partial.
   - **The `SIGPIPE` footgun.** Found while writing the test, not by the test: dropping the read end of a child's stderr pipe means the child's next `eprintln!` is `EPIPE` → `SIGPIPE` → dead. Would have bitten the daemon's `script.c` port (it `popen()`s and reads; same shape). The test harness now holds stderr open for the child's lifetime and drains it on a thread.
2. 🟡 **`tinc` CLI in Rust** — sliced. The original "talks to C daemon" framing was wrong; 30 commands split into a filesystem half (no daemon, ships now as 4a) and an RPC half (needs a daemon, waits for 5b). 4a's first command (`init`) **shipped**: `tinc -n NETNAME init NODENAME` produces a confbase the C `sptps_test` accepts.

   `cross_init_key_loads_in_c` is the closure on the wire-compat question for Ship #2. It pulls together every layer: `OsRng` → `SigningKey::from_seed` → `write_pem` → `tinc-b64` → file → C `ecdsa_read_pem_private_key` → C `sptps_start` → C `chacha20-poly1305` decrypt → 256 bytes match. Any link wrong — key derivation, blob layout, PEM armor, LSB-first b64 — the C handshake fails. It doesn't.

   **The control protocol gets replaced.** It's the meta-protocol re-purposed (`^` prefix on the ID name = "this is a control connection"); auth is a bearer token in a `0644`-ish pidfile; control connections sit in the same `connection_list` as real peers. No compatibility constraint — CLI and daemon ship together. New protocol: `AF_UNIX` + `SO_PEERCRED` auth + line-JSON. Daemon side ~100 lines (one `match`); CLI side `serde_json::{to,from}_reader`. Phase 5b.
3. **`tincd` Rust, SPTPS-only (`nolegacy` mode)** — ~18 weeks in
4. **`tincd` Rust with legacy protocol** — ~24 weeks in

Total: roughly **7 months** for one experienced engineer. The extra month over a naïve estimate is the bespoke-crypto tax: each of ChaPoly/ECDH/PRF/key-format is two days to implement and two weeks to be *certain*. The Phase 0 KAT vectors are the highest-leverage investment in the whole plan — they turn "is the crypto right?" from a debugging nightmare into a `cargo test` boolean.
