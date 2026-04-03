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
| **Ship #2 (4a) — `tinc` CLI** | ✅ 13 cmds | `tinc-tools: join — invite's pair, in-process roundtrip...` | invite/join pair complete. `invite_join_roundtrip_in_process`: two `Sptps` structs ping-pong (no subprocess, no socket) — invite writes file → server stub recovers via cookie→hash → SPTPS pump → `finalize_join` writes confbase → `fsck` approves. The server stub *is* `protocol_auth.c::receive_invitation_sptps` minus `connection_t*`; lifts to daemon unchanged. `invitation.c` (1484 LOC) consumed at ~-470 LOC after dropping HTTP probe / `ifconfig.c` / tty prompts. |
| **5b chunk 1 — control transport + simple RPCs** | ✅ +7 cmds | `tinc-tools: control socket transport + 7 simple RPC commands` | `CtlSocket` (the `connect_tincd` channel) + `pid`/`stop`/`reload`/`retry`/`purge`/`debug`/`disconnect`. **Kept the C wire shape** — pidfile is `0600` (`umask|077` before `fopen`, `pidfile.c:28`), cookie is fs-perms auth, same model as ssh-agent. |
| **5b chunk 2 — `cmd_config`** | ✅ +5 cmds | `tinc-tools: get/set/add/del — config-file editing, opportunistic reload` | Three-stage seam (`parse_var_expr` / `build_intent` / `run_edit`). Seventh `strcspn` tokenizer. `tinc-proto` dep added (Subnet validation only). The single-adapter argv→Action bug: `tinc add ConnectTo bob` would have routed GET→SET-via-coercion, *deleting* other ConnectTo lines — caught by reading the fall-through, not by a test. Four 1-line adapters. `config_set_fires_reload`: `tinc set` sends `"18 1\n"` to a real fake-daemon. |
| **5b chunk 3 — `cmd_dump`** | ✅ +2 cmds | `tinc-tools: dump nodes/edges/subnets/connections/graph/invitations` | The `" port "` literal: `sockaddr2hostname` returns `"10.0.0.1 port 655"` as ONE string, daemon writes via one `%s`, CLI parses `%s port %s`. Daemon printf has fewer conversions than CLI sscanf, per hostname. `Tok::lit()` + `Tok` made `pub`. Format pinned by `node.c:210`/`edge.c:128`/`subnet.c:403`/`connection.c:168` (the C daemon's `dump_*` fns). `dump_nodes_against_fake` is the cross-impl seam: byte-exact `node.c:210` wire → byte-exact `tincctl.c:1310` stdout. |
| **5b chunk 4 — `cmd_info`** | ✅ +1 cmd | `tinc-tools: info NODE\|SUBNET\|ADDRESS — three sequential dumps + maskcmp` | `info.c:53` sends third arg `"18 3 alice"`; `control.c:63` ignores it (`case REQ_DUMP_NODES: return dump_nodes(c)`, no sscanf past the type). Filtering is client-side; the third arg is dead on the wire. `forbid → deny` for one `localtime_r` shim. `Subnet::matches` + `maskcmp` to `tinc-proto`. The `/` and `#` checks are SUBSTRING checks (`strchr`), not parsed-value: `10.0.0.5/32` ≡ `10.0.0.5` semantically but `/` makes it exact-mode. Actual ~520 LOC vs estimate ~150. 573 tests + 9 cross-impl, 27 commands. |
| **5b chunk 5 — `cmd_top`** | ✅ +1 cmd | `tinc-tools: top — real-time per-node traffic, hand-rolled curses shim` | ratatui dropped — 7 ANSI escapes + nix `termios`/`poll` is enough; `top.c` is `printf` with cursor moves. `top.c:248-257`'s `i` field is a stable-sort EMULATION: `qsort` isn't stable, the `i` tiebreak makes it stable across frames. `slice::sort_by` IS stable; don't port `i`, sort the same Vec in-place. Two C bugs ported: daemon-restart `wrapping_sub` (the spike IS the signal); first-tick epoch-seconds interval (`static struct timeval prev` zero-init → tick-1 rate ≈ counter/1.7e9 ≈ 0). `~400 LOC` estimate → 1984 LOC actual, **5× off**. 608 tests + 9 cross-impl, 28 commands. |
| **5b chunk 6 — `cmd_log`/`cmd_pcap`** | ✅ +2 cmds | `tinc-tools: log/pcap — streaming commands, the seventh reversal` | `BufReader<T>: Read`; `read_exact` drains the internal buffer before touching `T`. The shared-buffer worry (C `tincctl.c:496` file-scope statics) was already solved by std. `recv_data` is one line. SIGINT handler NOT ported (first deliberate C-behavior-drop: exit 130 vs 0, daemon doesn't care). pcap headers `to_ne_bytes()` per-field — magic `0xa1b2c3d4` IS the endianness marker, native-endian is the format. y2038 truncation ported faithfully (`i64→u32`). 641 tests + 9 cross-impl, 30 commands. |
| **5b chunk 7 — `cmd_edit`/`version`/`help`** | ✅ +3 cmds | `tinc-tools: edit/version/help — sh -c "$@", not system()` | The C's `xasprintf("\"%s\" \"%s\"", editor, filename); system(cmd)` is wrong TWICE: filename-with-`$` expands AND double-quoted `"$EDITOR"` doesn't word-split (so `EDITOR="vim -f"` → ENOENT). The C never supported spacey EDITOR — the wrapping quotes defeat `system()`'s tokenization. We do `sh -c '$TINC_EDITOR "$@"' tinc-edit <file>` (the git way): editor unquoted (split), filename `"$@"` (literal). `edit_dollar_in_filename_not_expanded` sets `HOME=/tmp/WRONG`, edits `"$HOME"`, asserts stdout has `$HOME` literal. `edit_spacey_editor_tokenized` pins `EDITOR="echo arg"` → stdout `arg <path>`. The path-resolution lattice: conffiles[] check BEFORE dash-split (`tinc-up` would otherwise split to `("tinc","up")` → wrong file). C bare-hostname case validates NOTHING; we reject `/`, `..`, empty. STRICTER. CONFFILES sed-diff'd vs `tincctl.c:2400-2406` (✓). 671 tests + 9 cross-impl, 33 commands. |
| **5b chunk 8 — `cmd_network`** | ✅ +1 cmd | `tinc-tools: network — list mode only, switch is C-behavior-drop #2` | C has TWO modes: argless lists `confdir/*/tinc.conf`-bearing dirs; with arg, `switch_network` mutates `netname`/`confbase`/`prompt` globals for the readline loop. We have no readline. Switch would mutate-then-exit — silent no-op, worse than erroring. List ported, switch errors with "use `-n NAME`" advice (`.` sentinel gets distinct "no -n" advice). Second deliberate drop after SIGINT, different shape: SIGINT is "exit code differs, daemon doesn't care"; this is "feature requires scaffolding we don't have." Sorted output (NOT in C — readdir order undefined; sorted is in the set of valid C outputs; deterministic). `Paths::confdir_always()` papers over the C's-always-set vs our-`Option` mismatch. `list_skip_unreadable` gates on euid (root reads `chmod 000` via DAC override). 685 tests + 9 cross-impl, 34 commands. **Phase 5b CLOSED — all Phase-5-reachable commands landed.** |
| 3 — Device & transport | | | |
| **3 chunk 1 — `tinc-device` Linux + Dummy** | ✅ 8th crate | `tinc-device: TUN/TAP — the +10 layout pun, NOT the nix macro` | The +10: `read(fd, buf+10, MTU-10)` lands `tun_pi.proto` at byte 12 = the ethertype slot of a synthetic ethernet frame. `memset(buf, 0, 12)` zeroes fake MACs AND `tun_pi.flags` (overlapping bytes 10-11). No reformat; `route.c` never knows the bytes used to be `tun_pi`. `tun_offset_arithmetic` pins `14 - 4 = 10`. **NOT `nix::ioctl_write_ptr_bad!`** — `TUNSETIFF` is encoded `_IOW` (kernel reads from us) but kernel WRITES BACK `ifr_name`; the macro generates `*const`, wrong contract. Direct `libc::ioctl` with `*mut`. Third unsafe-shim instance, same SAFETY shape, but the macro divergence is new. `pack_ifr_name` is the testable seam: validate-first means `open_too_long_iface_err_before_open` passes without CAP_NET_ADMIN. STRICTER than C (rejects 16+ byte ifname; C truncates). 706 tests + 9 cross-impl. |
| **3 chunk 2 — `tinc-device` fd (Android)** | ✅ third backend | `tinc-device: fd backend — the +14 cousin, nix EARNS the dep here` | The +14: Android `VpnService` writes RAW IP, no prefix; read at `+14` (`ETH_HLEN`), synthesize ethertype from `ip[0]>>4`. The +10's TESTABLE cousin — `linux.rs` couldn't fake `tun_pi` (kernel-side layout); `fd.rs` reads bytes a `pipe()` can feed. `read_ipv4_via_pipe`/`read_ipv6_via_pipe` cover the offset arithmetic with no CAP_NET_ADMIN. **Shim #4 USES nix; #3 BYPASSED it.** `recvmsg`+`SCM_RIGHTS` is well-specified POSIX; nix's `ControlMessageOwned::ScmRights` collapses ~40 LOC of `cmsghdr` boilerplate AND fixes the C's NULL-deref at `fd_device.c:73`. `FdSource::{Inherited(RawFd), UnixSocket(PathBuf)}` makes the C's `sscanf("%d")==1` string-dispatch explicit. STRICTER than C: closes leaked fds before erroring on multi-fd cmsg (C leaks). C-is-WRONG +2 (the NULL deref; the leak — both masked by Java sender always sending 1 cmsg, 1 fd). 723 tests + 9 cross-impl. |
| **3 chunk 3 — `tinc-device` raw (`PF_PACKET`)** | ✅ fourth backend | `tinc-device: raw_socket — the +0, the SUBSTITUTE shim, SEQPACKET fake` | The +0: `socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))` writes raw ethernet, `route.c` wants ethernet at offset 0, done. Three points define the line: `offset = ETH_HLEN − len(prefix)`; linux 14−4=10, fd 14−0=14, raw 14−14=0. **Shim #5 SUBSTITUTES the syscall**: C does `SIOCGIFINDEX` ioctl (2002 code); `if_nametoindex(3)` is the POSIX function (2001) doing the SAME RESOLUTION. nix wraps it. New row class. Shim #6 hand-rolled: nix `LinkAddr` is getters-only (designed for `recvfrom` outputs, not `bind` inputs). The HYBRID file: nix for `socket()`+CLOEXEC (full match), nix for `if_nametoindex` (substitute), raw libc for `bind` (half-baked). **The fakeable boundary HOLDS but the WHICH-FAKE question is new**: `socketpair(SOCK_DGRAM)` BLOCKS on close (UDP-ish, no EOF concept; gcc-verified, eof test hung). `SOCK_SEQPACKET` preserves datagram boundaries AND EOFs on close — both PF_PACKET properties. STRICTER same as `linux::pack_ifr_name`: `if_nametoindex` errors on full name, no truncation. 734 tests + 9 cross-impl. |
| **3 chunk 4 — `tinc-device` bsd (3 offsets, 1 file)** | ✅ fifth backend, prep commit `1b1a2a85` | `tinc-device: bsd — three offsets, AF_INET6 varies, tested-on-Linux` | `ether.rs` hoist (`1b1a2a85`) made the synthesis reusable; `bsd.rs` 1218 LOC for 592 LOC C is **2.1×** (vs `fd.rs`'s 5.4×). `cfg(unix)` MODULE, `cfg(bsd)` `open()`: `read(2)`/`write(2)` are the same syscalls everywhere; only the fd's SOURCE (open path: `/dev/tun*`, `PF_SYSTEM`, `TUNSIFHEAD`) is BSD-only. **`cfg` goes on the smallest thing that's platform-varying** — the `open()` impl, not the module. 20 tests run on Linux via pipe()/seqpacket fakes. The IGNORED-prefix observation TESTED: `utun_read_ignores_prefix` feeds `[0xFF; 4]` garbage prefix + valid IPv4; if read decoded the prefix it'd error on the nonsense AF; doesn't, synthesizes from `buf[14]>>4`. **`AF_INET6` per-platform**: Linux 10, FreeBSD 28, macOS 30. CAN'T pin golden bytes. Test pins STRUCTURE: `(libc::AF_INET6 as u32).to_be_bytes()`. The RFC-vs-ABI distinction (`ether.rs` doc) operationalized: `0x86DD` is wire-format truth (hoisted); `AF_INET6` is local convention (`libc::` at use site). 754 tests + 9 cross-impl. |
| 4 — `tinc` CLI | (split: 4a above, 5b below) | | |
| **5 chunk 1 — `tinc-event` (loop scaffolding)** | ✅ +mio, 9th crate | `tinc-event: dispatch enum, BTreeMap timers, self-pipe — the daemon substrate` | `event.c`+`linux/event.c`+`signal.c`+`event.h` (476 C LOC) consumed; `bsd/event.c`/`event_select.c` are mio's job. 1619 LOC, **3.4×**. **Dispatch enum, not callbacks**: cb set is closed (6 io cbs + 7 timer cbs across all of `src/`) so encode as `enum IoWhat`/`TimerWhat`; loop body is a `match`; `EventLoop<W: Copy>` stays daemon-agnostic. **`BTreeMap<(Instant, u64)>` not `BinaryHeap`**: all 7 timers re-arm; heap entries immutable means push+tombstone churn; BTreeMap remove-reinsert is O(log n) same as C splay. The `u64` seq does what `event.c:62-72`'s ptr-compare does (same-tv tiebreak), stably. **Per-event liveness check, not generation bail**: C `linux/event.c:141` bails batch on ANY change because it can't tell which slot; we check `slab.get(token).is_some() && interest.wants(ready)` per event — process more per wake, correct because mio is level-triggered. C-is-WRONG #5 (`linux/event.c:121` NULL deref masked by `net.c:489` always arming pingtimer) and #6 (`signal()` portability + no CLOEXEC) fixed for free. Shim matrix new class: signal-handler `write` hand-rolled because "probably async-signal-safe" isn't a thing. `while(running)` NOT ported — daemon's `main()`. 780 tests + 9 cross-impl. |
| **5 chunk 2 — `tincd` walking-skeleton** | ✅ +slotmap, 10th crate, 4th binary | `tincd: walking-skeleton — boots, serves REQ_STOP, exits` | The dispatch enum compiles inside an actual loop. `IoWhat`/`TimerWhat`/`SignalWhat` get concrete variants; the `match`-on-one-big-`&mut Daemon` design works without `Rc<RefCell>` or async. **One `tinc-event` bug found by integration**: `io.rs:270`'s doc claimed mio swallows EINTR; it doesn't (mio 1.2 `epoll.rs:60` is `syscall!(epoll_wait)` raw). `SA_RESTART` doesn't help — `epoll_wait` is in the man-7-signal never-restart list. Every signal during `epoll_wait` produces EINTR. C `linux/event.c:128` does `if(sockwouldblock) continue` (`sockwouldblock` is `EWOULDBLOCK \|\| EINTR` per `utils.h:62`). The fix: `turn()` returns `Ok(())` empty on `Interrupted`; caller's loop re-ticks then re-turns; self-pipe byte fires next turn. The 26 unit tests in `tinc-event` couldn't catch this — you need a subprocess to send a real signal during a real `epoll_wait`. `sigterm_stops` IS the test. **REQ_STOP ack never sends, faithfully**: `control.c:59-61` queues `"18 0 0"`, `event_loop()` exits before WRITE fires, conn closes with reply stuck in outbuf. `tincctl.c:679-681` knows: `while(recvline()) {}` drain-to-EOF, ignore contents. The integration test was wrong (expected the ack); fixed to match the CLI's actual contract. **`LineBuf` range invalidation** (caught by 4 unit tests): `buffer.c:71-74` resets `offset=len=0` when consume drains; the C pointer survives because reset doesn't free `data`. Our `data.clear()` drops bytes — returned `Range<usize>` indexes empty Vec. Fix: `read_line` advances offset, never compacts; compact lives in `add()` only. The trace: `tinc_conf::read_server_config` → `tinc_device::Dummy` → `tinc_event::EventLoop::new`+`SelfPipe` → cookie+pidfile+`ControlSocket` → `match IoWhat::UnixListener` accept → `match Conn(id)` feed → `tinc_proto::Request::Id` gate → cookie cmp → `"0 testnode 17.7\n4 0 <pid>\n"` → `"18 0"` → `running=false`. Four prod unsafe (`libc::read`/`send` in feed/flush, `libc::umask` ×2 — `UnixListener::bind` doesn't take mode), all existing shapes (no new shim-matrix row). 613 C LOC traced → 3382 Rust (**5.5×**, 4.7× excl integration test). 47 tests (827 + 9 cross-impl). Chunk-3 worklist: `listen_sockets` (TCP+UDP, currently zero), `setup_myself_reloadable` (~40 settings), `id_h` `?`/peer branches, `control_h` rest of switch, the 6.01s test sleep (PingTimeout currently hardcoded 5s). |
| **5 chunk 3 — `tincd` TCP/UDP listeners** | ✅ +socket2 | `tincd: TCP/UDP listeners — socket2 for the four-step seam, tarpit faithful` | **socket2, NOT a new shim-matrix row**: std's `TcpListener::bind` is `socket()→bind()` atomic, no seam for `setsockopt(IPV6_V6ONLY)`. socket2 is std-with-seams; only dep is libc (already linked). Same quadrant as slotmap-instead-of-hand-rolling-a-slab. REUSEADDR/V6ONLY/NODELAY/BROADCAST all NOT gated on `feature="all"` (verified in 0.5.10 source). `accept4(SOCK_CLOEXEC)` closes a leak the C has (accepted peer fd inherited into `script.c` children). **getaddrinfo skipped**: `add_listen_address(NULL, NULL)` does `getaddrinfo(NULL, port, AI_PASSIVE)` → `0.0.0.0` then `::` (gcc-verified). The two AI_PASSIVE wildcards are KNOWN; the "is this family supported" probe is `Socket::new(Domain::IPV6)` failing on a v6-disabled kernel — same outcome as getaddrinfo not returning a v6 entry. C `:705` already does `if(tcp_fd<0) continue`. **Tarpit off-by-one ported**: `:699` `>` (same-host triggers at 11) vs `:721` `>=` (all-host at 10). Been this way since 2013 (`efa42d92`). The same-host EARLY RETURN (`:699-702` returns before `:705 prev_sa = *sa`) freezes `prev_addr` AND the all-host bucket once same-host triggers. Probably both accidental. `tarpit_samehost_early_return` pins it. **Manual probe (dual-stack, `ss -tln`)**: 2 TCP rows (`0.0.0.0` AND `[::]`) proves V6ONLY worked — without it the v6 socket grabs both via mapped addresses, v4 bind gets `EADDRINUSE`, `open_listeners` returns one listener, **the Rust test would PASS** (one is still ≥1). Integration tests pin `AddressFamily=ipv4` to dodge v6-disabled CI; the probe was the dual-stack proof. Four different ports (TCP v4, UDP v4, TCP v6, UDP v6) — deferred `bind_reusing_port`. **Suite 6.01s → 2.01s** (PingTimeout=1). 0 prod unsafe, 2 test (fcntl getters). 310 C LOC → 1265 Rust (**4.1×**, on estimate). 858 tests + 9 cross-impl. Chunk-4 worklist: `bind_reusing_port`, `service_to_port`, `BindToAddress`/`ListenAddress`/LISTEN_FDS, deferred sockopts (RCVBUF/SNDBUF/MTU_DISCOVER/MARK/BINDTODEVICE/TOS/TCLASS), `id_h` `?`/peer branches. |
| **5 chunk 4a — `tincd` `id_h` peer branch → SPTPS HandshakeDone** | ✅ | `tincd: id_h peer branch — SPTPS handshake to HandshakeDone` | **THE NUL** (`65d6f023`, 2012-02-25): `char label[25 + strlen(a) + strlen(b)]` is a VLA, `sizeof` is the bracket expr, `snprintf` NUL-terminates at `[labellen-1]`. gcc-verified `("alice","bob")`: `labellen=33`, `label[32]=0x00`. The NUL is in the SIG transcript (`sptps.c:206`) and PRF seed (`:258`). All tinc 1.1 releases have it. The invitation label `("tinc invitation", 15)` does NOT — string literal + explicit count. Not a deliberate "NUL is part of every label" policy; a sizeof-of-VLA accident at one call site that became wire format. `tcp_label()` does explicit `label.push(0)`; `tcp_label_has_trailing_nul` pins the gcc bytes. **Integration test can't catch "both wrong"** (test uses same construction); the unit test pins the gcc-verified bytes; a real cross-impl handshake against C tincd is Phase 6. **The borrow shape**: `Sptps::receive` returns `Vec<Output>`; daemon dispatches AFTER. Loses one C semantic (Wire from record N queued before N+1 processed). For the handshake (KEX→SIG→DONE) doesn't matter — no interleaving. `feed_sptps` is associated fn taking `&mut Sptps` directly (not `&mut self`) so the take_rest re-feed can call it. **The piggyback**: same TCP segment can deliver `"0 alice 17.7\n"` AND initiator's KEX (Nagle). C handles by processing the stack buffer iteratively inside `receive_meta`'s do-while; mode switch happens mid-read. We split feed/dispatch differently → explicit `LineBuf::take_rest` handoff. Rare (initiator usually waits for our send_id). **The chunk-4a shortcut sync-flush**: SIG and HandshakeDone arrive in same `Vec<Output>`. Queue SIG → see HandshakeDone → terminate → SIG never hits wire. C never has this (no terminate-at-HandshakeDone). Sync `flush()` before terminate is wrong in production (slow peer stalls us) but the terminate itself is temporary; chunk 4b removes both. **TEST IS THE INITIATOR**: no `do_outgoing_connection` yet (chunk 5). Same shape as `cmd_join`'s pump loop. `(&TcpStream).read()` for the duplex borrow trick. **The 17× ratio is misleading**: 57% comments, ~50% tests. keys.rs prod code-only is **1.5×** (117 LOC vs C 78). The comment ratio is the C-source-mapping doc; the test ratio is the standing 3-5× for static-table/infrastructure ports. **C-is-WRONG #7**: `keys.c:141` `& ~0100700u` flags setgid/sticky bits, not just group/other-read. False positives. Ported (cosmetic warning). 0 new unsafe. 894 tests. Chunk-4b worklist: `send_ack` (`meta.c:129`→`protocol_auth.c:826-868`, replaces terminate-at-HandshakeDone + sync-flush), `ack_h` (`:948-1066`: node_tree, edge, graph(), send_everything), `Output::Record` arm (`meta.c:153-161`), per-conn config tree (YAGNI'd, ack_h re-reads). |
| **─ cleanup: comments + tests + tooling** | ✅ | `rustfmt.toml` + `Cargo.lock` committed | **27 commits, −3,543 LOC, 894→752 tests.** Three workmux passes, partitioned by file (zero overlap, ff-merge clean). **Comments** (−2,344 LOC): 413 box-drawing decoration lines; think-aloud noise (`wait, no` ×7, `ANYWAY:`); module-doc essays → module docs (`tincd/lib.rs` 84→24, `tinc-event/lib.rs` 81→24, `edit.rs` 110→52); 4 lazy crate-level `#![allow]` → item-level (`tinc-conf` `cast_possible_truncation`, `tinc-event` `missing_errors_doc`, `tincd` `struct_excessive_bools`, `fsck.rs` `too_many_lines`); 19 dead allows (`similar_names` on single-letter vars, `missing_errors_doc` on private fns). **Tests** (−142 tests): 113 table-consolidated (model: `subnet.rs::kat_roundtrip` — per-row comments preserve C-line-ref provenance), 27 integration drops (each → named `unit + integration` covering pair in commit msg), 2 outright drops (`sort_stability_*` — stdlib stability guarantee). `id_early_rejects` table is *stronger*: no-state-mutation now asserted on all 5 cases including the path-traversal security row. **Tooling**: `rustfmt.toml: style_edition = "2024"` resolved a bistability — treefmt-nix's rustfmt module passes `--edition 2024`, `cargo fmt` reads `edition = "2021"` from Cargo.toml; the sort orders differ (2024 case-insensitive). 66 files stopped diffing on `cargo fmt --check`. `Cargo.lock` committed (4 binaries; `.gitignore` was Phase-0a-library-only). 752 tests + 9 cross-impl. |
| **5 chunk 4b — `send_ack`/`ack_h`, world-model stub** | ✅ | `tincd: send_ack/ack_h — terminate goes away, conn STAYS UP, dump shows it` | **`conn.send()` grew the SPTPS branch** (`meta.c:65-67`): the ACK is the FIRST line that goes through `sptps_send_record` not `buffer_add`. The id-reply still goes plaintext because `id_h` calls `send()` BEFORE `Sptps::start` — same as C `protocol.c:126-130` `if(id)` routing ID through `send_meta_raw`. **The PMTU intersection** (`ack_h:996-999`): `if(!(c->options & options & PMTU)) clear both`. PMTU only sticks if BOTH sides want it; the other 3 OPTION bits are simple OR. Per-host config overrides (`:844-865` IndirectData/TCPOnly/Weight from `c->config_tree`) STUBBED — config not retained. **`i32::midpoint` not `(a+b)/2`**: clippy `manual_midpoint`. Rounding semantics differ (truncate vs floor) but both weights are RTT-ms ≥ 0 → unreachable. The C `:1048` is UB at 24-day RTT; we are not. **`NodeState` is the (b)-path stub**: conn + the edge fields `ack_h` would build (addr-with-port-rewritten `:1024-1025`, weight average `:1048`, options-intersected `:1001`). `tinc-graph::Graph` is topology, this is runtime annotation. Dup-conn handling (`:975-990`) ported: same name reconnects → close old, accept new. **`status_value()`**: GCC bitfield LSB-first (`connection.h:38-58`); `control` is bit 9 = `0x200`. Only modeling bits we set. **`myport.udp` from `listeners[0].udp_port()`** (`net_setup.c:1194 get_bound_port`); with `Port=0` TCP/UDP get DIFFERENT kernel ports until `bind_reusing_port`. **`peer_ack_exchange`**: pump until HandshakeDone AND daemon-ACK Record both arrive (might be same outbuf flush). Parse `"4 <port> <weight> 700000c"`. Send our ACK via `sptps.send_record(0)`. 100ms read post-ACK: **WouldBlock is the success signal** (conn up, daemon idle, `send_everything` walked empty trees). `dump connections` over control socket: 2 rows, peer's has `700000c` (PMTU survived intersection). 239 C LOC → 1009 file-LOC = **4.2×**. 0 new unsafe. 758 tests + 9 cross-impl. |
| **5 chunk 5 — world model proper: subnet trees, edge propagation** | ✅ 7 commits | `tincd: wire ADD/DEL_EDGE + ADD/DEL_SUBNET into daemon.rs` | **Seven commits, 6 parallel + 1 serial.** The leaf modules genuinely don't share state — each is one new file + one `pub mod` line; mergiraf auto-resolved the `lib.rs` adjacency. **Three-way world model**: `Graph` (topology, what sssp/mst walk), `node_ids: HashMap<String, NodeId>` (the reverse lookup `tinc-graph` doesn't have), `nodes: HashMap<String, NodeState>` (runtime: which `ConnId`, edge addr/weight). `lookup_or_add_node` zeroes `reachable` — `Graph::add_node` defaults `true` (KAT steady-state); daemon needs `false` so the diff emits `BecameReachable`. **`on_ack` adds BOTH edge halves** — sssp skips reverseless (`graph.c:159`); with stubbed forward we'd never get the peer's half. **Edge update = del+add** (no in-place mutation in the slab; commented for future `Graph::update_edge`). **`SubnetTree` Ord uses `.reverse()` not `b-a`**: weight is `%d` never bounds-checked, `i32::MIN - 1` is UB in C. **`seen.check` no-alloc on hit** via `String: Borrow<str>` — mirrors C stack-borrowed `past_request_t`. **`inet_checksum` is native-endian load** (`memcpy(&word, data, 2)`, RFC 1071 §2(B) byte-order independence) — KAT-locked via `nix build .#kat-checksum` linked against `route.c:63-86` verbatim. **Addrcache went text-format**: C `fwrite(&sockaddr_storage)` is platform-specific (BSD `sin_len`); ours is `SocketAddr::Display` per line. STRICTER (C cache won't parse) but it's a CACHE — regenerated from config + first connection. **`graph_glue::run_graph` order is sssp→diff→mst** (C `graph.c:341-344`): mst reads the written-back `reachable` bit for its starting node. `peer_ack_exchange` extended: ADD_SUBNET → dump shows row → dup ADD dropped (`seen.check`) → DEL → empty. `peer_edge_triggers_reachable`: ADD_EDGE testpeer↔faraway → stderr "faraway became reachable", `dump connections` STILL 1 row (faraway is graph-only). **15 `STUB(chunk-6)` markers**: all `forward_request` + send-correction paths; one-peer mesh has nobody to broadcast to. ~1440 C LOC → ~3.7k Rust (vs ~7k estimate — the "5×" was wrong; pure data structures table-consolidate to 2×). 758→825 tests + 9 cross-impl. |
| 5 chunk 6 — outgoing connections + `forward_request` | | | Today we only ACCEPT. `do_outgoing_connection` (`net_socket.c:564-662`, ~100), `setup_outgoing_connection` (`:664-732`), `try_outgoing_connections` (`:815-884`), `retry_outgoing` (`:405-417`, exponential backoff timer). **`addrcache` already landed** (`4a641b0f`, text-format not C struct dump). **The async-connect dance**: nonblocking `connect()` returns `EINPROGRESS`; you `epoll` for WRITE; when writable, `getsockopt(SO_ERROR)` tells you if it actually connected. socket2 has `Socket::connect` that does this; the WRITE-readiness path is a new `IoWhat::OutgoingPending(ConnId)` variant. **`forward_request`** (`protocol.c:135-146`) unstubs HERE, not chunk 5: with one peer, broadcast-to-everyone-else is broadcast-to-nobody. The chunk-5 stubs (15 grep-able `STUB(chunk-6)` markers) are: 4× `forward_request`, 5× send-correction (`send_add_edge`/`send_del_subnet` for the `from == myself` retaliate paths), 2× `contradicting_*_edge` counters, 1 `send_everything` actual iteration, 3 misc. **The chunk-5 integration test gets simpler**: instead of test-process-is-the-initiator, BOTH sides are real daemons with `ConnectTo = peer` in tinc.conf. ~550 C LOC → ~2.5k Rust. |
| 5 chunk 7 — first packet: minimal data plane | | | **THE GOAL.** TUN read → `route_ipv4` only (no ARP, no v6, no broadcast) → `lookup_subnet_ipv4` (chunk 5's tree) → owner node → `protocol_key.c::send_req_key`/`ans_key_h` (per-tunnel SPTPS handshake — DIFFERENT from the meta-conn SPTPS; datagram framing, label `"tinc UDP key expansion %s %s"`) → `send_sptps_packet` → UDP send. The receive path: `handle_incoming_vpn_data` (`net_packet.c:1845`) → `try_mac` (find which node sent it by trial-decrypt; the 6-byte node_id_t prefix is the fast path) → `sptps_receive_data` → `route()` (loop back into route_ipv4, but `source == subnet->owner` so it goes to TUN write). `protocol_key.c` (648) is mostly the per-tunnel key exchange — REQ_KEY/ANS_KEY messages over the meta connection that bootstrap a UDP-side SPTPS. `tinc-sptps` already does datagram framing; this is wiring. **What's deferred from `route.c`**: ARP/NDP spoofing (~400 LOC), ICMP unreachable synthesis (~200), ClampMSS (~100), broadcast (~100), MAC learning / RMODE_SWITCH (~150). `route_ipv4` happy-path is ~50 LOC of the 1176. **What's deferred from `net_packet.c`**: MTU probing (~400), compression (~300, all three of LZO/LZ4/zlib), TCP-fallback for blocked UDP (~200), the relay path (~100). The send/recv core is maybe ~500 of the 1938. **Integration test**: two daemons on a `socketpair` instead of TUN (the `Dummy` device's read returns canned IPv4 packets); `dump traffic` on both sides shows the byte counts. ~1200 C LOC traced → ~6k Rust. **iperf3 over real TUN is Phase 6** (needs root). |
| 5 chunk 8 — fill out: PING/PONG, control protocol server, scripts | | | `protocol_misc.c` (376): `ping_h`/`pong_h` (the 2.01s integration-test timer fires this), `tcppacket_h` (TCP-relay receive), `udp_info_h`/`mtu_info_h` (PMTU discovery hints). `control.c` rest of switch (~200 of 241): `REQ_DUMP_*` walk the trees and `writeln!`; `REQ_RELOAD` calls `reload_configuration`; `REQ_DEBUG`/`REQ_PCAP`/`REQ_LOG` set flags. `process.c` (243): `daemon()`, `setuid` drop, `tinc-up`/`tinc-down` script spawn — the SIGPIPE-from-dropped-stderr footgun shipped in Ship-#1's `self_roundtrip` harness applies here. `net.c::periodic_handler` (~100 of 527): the 5-second sweep that ages connections, retries outgoings, calls `try_tx`. **CLI `start`/`restart`/`connect` unblock here** — `start` is `fork()+execvp(tincd)`, `restart` is `stop` then `start`, `connect` sends `REQ_CONNECT` (daemon side: `setup_outgoing_connection` for the named peer). ~900 C LOC. |
| 5 chunk 9 — fill out: route.c rest, net_packet.c rest, net_setup.c reloadable | | | The deferred pieces from chunk 7. `route.c`: ARP spoofing (`route_arp`, ~100 — synthesizes ARP replies so the kernel-side routing table works without real L2), NDP for v6 (`route_neighborsol`, ~150), ICMP unreachable (`route_ipv4_unreachable`, ~100 — when no subnet matches, send ICMP back so the sender's TCP backs off instead of hanging), ClampMSS (`clamp_mss`, ~100 — rewrite TCP MSS option to fit tunnel MTU), `route_broadcast` (~50, walks the `mst()` connections). `net_packet.c`: MTU probing (`send_udp_probe_packet` etc, ~400 — the daemon discovers per-peer MTU by sending growing probes), the TCP-fallback path (`send_sptps_tcppacket`, ~100 — when UDP fails, tunnel via the meta connection), `try_mac` trial-decrypt fallback when the node_id prefix doesn't match. `net_setup.c::setup_myself_reloadable` (~500 of the 1336 — the SIGHUP path that re-reads config without dropping connections; the plan's existing note about `expires=1` selective sweep applies). ~1800 C LOC. |
| 5 chunk 10 — listener-side leftovers + invitation server | | | The chunk-3 worklist, finally: `bind_reusing_port` (TCP+UDP same port — today's daemon uses 4 different ports), `BindToAddress`/`ListenAddress`, `LISTEN_FDS` (systemd socket activation), the 7 deferred sockopts. `id_h` `?` branch (~80 LOC): the daemon-side invitation accept. `cmd_join` already has `server_receive_cookie` (the SPTPS-record handler, ported in 5b chunk 5); the daemon needs the `?` greeting branch + the same handler. `ifconfig.c` (321 — `cmd_join`'s TODO at `:427`): generates platform-specific `ip addr add` / `ifconfig` lines for the `tinc-up` script from invitation `Ifconfig`/`Route` stanzas. ~600 C LOC. |
| **6 — cross-impl tincd** | | | The unit test pins the gcc-verified `tcp_label` NUL bytes. `peer_handshake_reaches_done` uses the same construction on both sides — can't catch "both wrong". A real handshake against `c-tincd` is the only end-to-end proof. `nix build .#sptps-test-c` already builds the C side; this is `nix build .#tincd-c` (same meson recipe, different target) + a 3-node integration test: 2× Rust, 1× C, each with one Subnet. All three's `dump subnets` show all three. Then `iperf3` over the actual TUN devices (requires `CAP_NET_ADMIN`, gates on root same as `tinc-device`'s `open_non_root_err`). |
| **defer / drop** | | | `proxy.c` (285, SOCKS/HTTP-CONNECT — niche), `multicast_device.c` (224 — niche), `autoconnect.c` (197 — heuristic ConnectTo, nice-to-have), compression in `net_packet.c` (LZO/LZ4/zlib, ~300 — `Compression = none` works), legacy protocol (~400 LOC behind `DISABLE_LEGACY` — RSA+AES-CBC for tinc 1.0.x peers; the plan already says "FFI to OpenSSL or never"). |

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
  tinc-event/               # poll loop scaffolding (mio + timers + self-pipe)
  tinc-net/                 # listener sockets, packet routing
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
| `conf.c` `read_server_config` (`conf.d/` scan) | `parse::read_server_config` | ✅ cmdline merge skipped (daemon-only, fsck sees empty list). Ports pre-`40719189` behavior — see fsck note |
| `tincctl.c` `variables[]` (74 entries) | `vars::{VARS, VarFlags, lookup}` | ✅ Order preserved incl. alpha-break; sed-diff verified. +3 invariants the C never asserts |
| `names.c` | — | ✅ `tinc-tools::names` — `confbase`/`confdir` (4a) + `pidfilename`/`unixsocketname` resolution (5b chunk 1). The LOCALSTATEDIR fallback dance is a 3-row truth table; the bottom row (neither `/var/run/X.pid` nor `confbase/pid` exists → return `/var/run` path anyway) is the surprise, replicated. `unix_socket()` derives from `pidfile()` by string surgery: `> 4` not `>= 4`, case-sensitive `.pid` match. |
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
| Linux | `linux/device.c` | ✅ `linux.rs` (907 LOC) — hand-rolled. **NOT** `tun-tap` crate, **NOT** `nix::ioctl_write_ptr_bad!`. Direct `libc::ioctl` because the macro generates `*const` and `TUNSETIFF` writes back. The ~150 LOC estimate was the *unsafe shims alone*; the +10 offset trick + testable seam + 15 tests are the rest. |
| Dummy | `dummy_device.c` | ✅ `lib.rs` `Dummy` impl. Trivial. Read → `WouldBlock`, write → `Ok(len)`. |
| `fd` (Android) | `fd_device.c` | ✅ `fd.rs` (1330 LOC) — the +14 cousin. `pipe()`-testable. nix `socket`+`uio` features for `recvmsg`+`SCM_RIGHTS`. |
| `raw` (`PF_PACKET`) | `raw_socket_device.c` | ✅ `raw.rs` (797 LOC) — the +0. Shim #5 SUBSTITUTES (`if_nametoindex` for `SIOCGIFINDEX`). `SOCK_SEQPACKET` test fake. |
| BSD/macOS | `bsd/device.c` (592 LOC) | ✅ `bsd.rs` (1218 LOC, 20 tests) — `BsdVariant::{Tun,Utun,Tap}`. **`cfg(unix)` MODULE, `cfg(bsd)` open()** — read/write logic tested on Linux via fakes; only constructors stubbed. `to_af_prefix` (the dual of `from_ip_nibble`) lives HERE not in `ether.rs` because `AF_INET6` is platform-varying. Shims #7 (`TUNSIFHEAD`) + #8 (`PF_SYSTEM`/`sockaddr_ctl`) noted in open() worklist. vmnet/tunemu dropped. |
| Windows | `windows/device.c` | `wintun` crate (WireGuard's driver) — **drop** TAP-Windows support |
| Multicast | `multicast_device.c` (224 LOC) | +0, TAP-only. Uses `recv`/`sendto` NOT `read`/`write`. nix has `IpAddMembership`/`IpMulticastTtl`/`IpMulticastLoop` sockopt wrappers. The `ignore_src` MAC-loopback-suppression (`:191`, `:214`) is the one piece of state. The `str2addrinfo` dep pulls DNS (`getaddrinfo`); port after `tinc-proto` exposes addr resolution. |
| UML/VDE | `*_device.c` | Drop. UML doesn't exist; VDE needs `libvdeplug`. |

**Transferable decisions** (full reasoning in source-file docs —
`tinc-device/{linux,fd,raw,bsd,ether}.rs`, `tinc-event/sig.rs`):

**Unsafe-shim decision matrix** (seven rows, four classes; `TUNSIFHEAD`
and `PF_SYSTEM`/`sockaddr_ctl` are next, in the BSD `open()` worklist):

| # | What | C does | We do | Class |
|---|---|---|---|---|
| 1 | `localtime_r` (`info.rs`) | `localtime_r` | hand-rolled `MaybeUninit<libc::tm>` | nix doesn't wrap |
| 2 | `TIOCGWINSZ` (`tui.rs`) | ioctl | `nix::ioctl_read_bad!` | wraps-same-syscall, encoding honest |
| 3 | `TUNSETIFF` (`linux.rs`) | ioctl | bypass; raw `libc::ioctl` | wraps-same-syscall, **encoding lies** |
| 4 | `recvmsg`+`SCM_RIGHTS` (`fd.rs`) | ~40 LOC cmsghdr | `nix::sys::socket::recvmsg` | wraps-same-syscall, POSIX-clean, fixes C bug |
| 5 | `SIOCGIFINDEX` (`raw.rs`) | ioctl | `nix::if_nametoindex` | **substitutes-with-higher-level-POSIX** |
| 6 | `bind(sockaddr_ll)` (`raw.rs`) | `bind()` | hand-rolled `libc::bind` | nix half-baked (`LinkAddr` getters-only) |
| 7 | signal-handler `write()` (`sig.rs`) | `write(pipefd[1], &num, 1)` | hand-rolled `libc::write` | **signal-context demands certainty** |

Per-shim decision tree: (1) nix doesn't wrap? hand-roll. (2) higher-
level POSIX primitive does same job? substitute. (3) wrapper matches
kernel's actual contract? use. (4) half-baked or encoding lies?
hand-roll. (5) signal-context AND wrapper goes through any abstraction
you can't audit forever? hand-roll. Row #7's `nix::unistd::write` is
`libc::write` + `Errno::result` — no allocation, no locks, *probably*
safe. "Probably" isn't good enough for a handler. (`pipe2`/`sigaction`
stayed hand-rolled by the same +1-dep-for-−10-LOC call as
`read_fd`/`write_fd` factoring.)

Don't pattern-match on the neighboring shim; `raw.rs` mixes three
classes in one file. Read the man page per shim.

**Four standing decisions** (the ones the daemon will hit):

| Decision | Rule | Where the source-doc lives |
|---|---|---|
| `cfg` placement | Gate the smallest thing that's platform-varying. `bsd.rs` is `cfg(unix)` (read/write logic POSIX); `open()` is `cfg(bsd)` (the only platform-varying thing). Module-at-`cfg(unix)` gets you tested-on-Linux for free. | `bsd.rs` doc + `lib.rs` mod-gate comment |
| Platform-varying constant tests | Pin the EXPRESSION (`(libc::AF_INET6 as u32).to_be_bytes()`), not the bytes (`[0,0,0,0x1e]`). Pin literals only for cross-platform invariants (`AF_INET=2` everywhere). | `bsd.rs::tests::prefix_ipv6_is_libc_af_inet6_be` |
| RFC vs platform-ABI constants | RFC values (`ETH_P_IP=0x0800`) hoist to `ether.rs`. Platform values (`AF_INET6={10,28,30}`) reference `libc::` at use site. The `cfg`-boundary rule applies to the latter; the former never had a `cfg`. | `ether.rs` doc |
| `read_fd`/`write_fd` factoring | Six module-private 8-line fns (four in `tinc-device`, two in `tincd::conn`). Don't factor: 48 LOC duplication buys six small `#[allow(unsafe_code)]` scopes. A shared fn widens unsafe to crate scope. Trigger isn't instance count; it's "the caller's lib.rs itself needs raw I/O." | `bsd.rs::read_fd` block comment; `tincd::conn` feed/flush |

Trait shape (settled; `write` takes `&mut [u8]` because `linux.rs`
zeroes `buf[10..12]` and `bsd.rs` clobbers `buf[10..14]`):

```rust
pub trait Device: Send {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn mode(&self) -> Mode;       // Tun vs Tap
    fn iface(&self) -> &str;      // for tinc-up's INTERFACE=
    fn mac(&self) -> Option<Mac>; // TAP only; route.c ARP path
    fn fd(&self) -> Option<RawFd>; // for poll(); Dummy is None
}
```

C `setup`/`close` are constructor + `Drop`, not trait methods.

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
| `fsck.c` | ✅ `cmd/fsck.rs` — `Finding` enum + `Report`. `clean_init_passes` is the contract test |
| `names.c` | `names.rs` — `Paths` struct. **First consumer.** Was Phase 5 deferral; pulled forward because `tinc init` literally can't function without `confbase` |
| `fs.c` `makedirs`/`fopenmask` | `names.rs` methods — `fs::create_dir_all` + `OpenOptions::mode()` |

(Per-command findings live in source-file docs: `cmd/init.rs`,
`cmd/exchange.rs`, `cmd/genkey.rs`, `cmd/sign.rs`, `cmd/fsck.rs`,
`cmd/invite.rs`, `cmd/join.rs`. Status table at top has the dense
summaries. Forward refs preserved below.)

**`CONFDIR` = `option_env!("TINC_CONFDIR")` at compile time**, default
`/etc`. Packagers set the env in their build (Nix derivation does).

**`server_receive_cookie` is the daemon seed.** It's `protocol_auth.
c:185-310` minus `connection_t*`: cookie→filename via KAT-tested
`cookie_filename`, atomic `rename` to `.used` (single-use), mtime-
vs-expiry, `Name =` first-line validate. Lifts to `tincd::auth`
in Phase 5; the daemon version takes `&mut Connection`.

**Upstream bug `40719189`** (2026-03-30, broke `conf.d/`): `if(!dir
&& ENOENT) return true; else return false;` falls to else when
opendir succeeds. `tinc-conf` ports pre-regression behavior. Filed
upstream.

**`sign` doesn't respect `Ed25519PrivateKeyFile`** (deferred fix).
fsck does. `private_key_file_config` test in `fsck.rs` is the
reference for when sign gets fixed.

### Phase 5b: RPC half — transport landed, kept C wire shape

**Kept the C control protocol.** The pidfile is `0600` (`umask|077`
before `fopen`, `pidfile.c:28`) — cookie is fs-perms auth, same
model as ssh-agent. JSON would have cost `serde_json` and the
`nc -U /var/run/tinc.socket` debuggability. (Full reasoning in
`ctl.rs` doc; per-chunk findings in `cmd/dump.rs`, `cmd/info.rs`,
`cmd/top.rs`, `cmd/stream.rs`, `cmd/edit.rs`, `cmd/network.rs`.)

**C-is-WRONG findings** (the masked-by-well-behaved-sender class —
"works because the other side is nice" is a coupling smell):

| Location | The bug | Why masked | Our fix |
|---|---|---|---|
| `fd_device.c:73` | `CMSG_FIRSTHDR` returns NULL on empty control buffer; C dereferences `cmsgptr->cmsg_level` without checking | Java sender always sends a cmsg; in practice never empty | nix's `msg.cmsgs()` iterator: empty → empty iter → `None` from `find_map` → error, not segfault |
| `fd_device.c:86` | `cmsg_len` check rejects multi-fd AFTER `recvmsg` returned — kernel already dup'd; rejecting now leaks | Java sender always sends 1 fd | `let [fd] = fds[..] else { close all; Err }` |
| `tincctl.c:2458` `system()` | `"\"%s\" \"%s\""` quotes both — `EDITOR="vim -f"` won't tokenize, `$` in filename expands | nobody sets spacey EDITOR | `sh -c '$TINC_EDITOR "$@"' tinc-edit <file>` |
| `conf.c` `40719189` | `conf.d/` early-return bug; opendir success falls through to `return false` | upstream regression 2026-03 | port pre-regression behavior |
| `linux/event.c:121` | `tv->tv_sec * 1000` when `timeout_execute` returned NULL (empty tree); `event_select.c:98` correctly passes NULL to `select` | `net.c:489-492` arms `pingtimer`+`periodictimer` before `event_loop()` runs | `tick() -> Option<Duration>`, mio handles None |
| `signal.c:77` + `:58` | `signal()` not `sigaction()` (SysV-vs-BSD semantics); pipe leaks into `script.c` children (no CLOEXEC) | glibc/BSD `signal()` give BSD semantics; children just have an extra fd | `sigaction(SA_RESTART)` explicit; `pipe2(O_CLOEXEC)` |

| Command | Blocked on |
|---|---|
| `start`/`restart` | Daemon binary needs to exist. Phase 3. |
| `connect` | Daemon-only RPC (asks daemon to `outgoing_connection`); meaningless until daemon exists. Phase 3. |
| `generate-keys`, `generate-rsa-keys` | RSA legacy crypto. We have `generate-ed25519-keys`. Intentionally not ported. |

**True coverage** (`comm -23` against `tincctl.c:2995-3050` dispatch
table, 39 entries): 34/39 ported. The 5 unported are 2 daemon-gated
+ 1 daemon-only-RPC + 2 legacy-crypto. None reachable before Phase 5.

**Deliberate C-behavior-drops:**

| # | Command | What the C does | What we do | Why dropped |
|---|---|---|---|---|
| 1 | `log`/`pcap` | `signal(SIGINT)` → `shutdown(fd)` → exit 0 | default SIGINT → exit 130 | daemon doesn't care; nobody scripts `tinc log`'s exit code | needs-scaffolding |
| 2 | `network NAME` | mutate globals for readline loop | error "use `-n NAME`" | no readline loop → mutation goes to /dev/null | needs-scaffolding |
| 3 | `IFF_ONE_QUEUE` | reads `IffOneQueue` config, sets flag in `TUNSETIFF` | doesn't | kernel commit `5d09710` (2.6.27, 2008) made it a no-op | dead-kernel-side |

**C source consumed:**

| C source | Rust |
|---|---|
| `info.c` | ✅ `cmd::info` — the dead third arg, `Reachability` cascade, `Subnet::matches`. `info.c` fully consumed. |
| `top.c` | ✅ `tui.rs` shim + `cmd::top` — the `i` field is a stable-sort emulation (don't port; `sort_by` is stable), `wrapping_sub` for daemon-restart spike, first-tick epoch-seconds bug-port. `top.c` fully consumed. |
| `tincctl.c` `pcap`/`log_control` (590-669) + `cmd_pcap`/`cmd_log` (1518-1567) | ✅ `cmd::stream` — `recv_data` is `read_exact` on the `BufReader` (the shared-buffer worry was already solved by std). `to_ne_bytes()` for pcap headers. SIGINT handler NOT ported. `log_against_fake`/`pcap_against_fake` pin the C-daemon-compat seam: subscribe wire matches `control.c:128/135` sscanf, header wire matches `logger.c:213`/`route.c:1124` send_request. |
| `console.c` (5-11, Unix branch) | ✅ `cmd::stream::use_ansi_escapes_stdout` — `isatty(stdout) && getenv("TERM") && strcmp(TERM, "dumb")`. |
| `tincctl.c` `cmd_edit` (2399-2472) + `conffiles[]` (2399-2408) | ✅ `cmd::edit` — the resolution lattice (conffiles BEFORE dash-split), `sh -c '$TINC_EDITOR "$@"'` instead of `system()`. The C's shell-quoting is wrong twice; we fix both. STRICTER `/`/`..`/empty rejects. Silent reload best-effort (`let _ = ctl.send(Reload)`). |
| `tincctl.c` `cmd_help`/`cmd_version` (2366-2384) | ✅ binary-level `cmd_help`/`cmd_version` — trivial dispatchers to `print_help`/`print_version`. `help: ""` makes them invisible in `--help` (recursive listing is silly; C doesn't list them either). |
| `tincctl.c` `cmd_dump` (1182-1376) + `dump_invitations` (1108-1180) | ✅ `cmd::dump` — four row parsers, DOT-format graph, the `" port "` literal. `dump_nodes_against_fake` pins the C-daemon-compat seam. |
| `tincctl.c` simple `cmd_*` (reload/purge/retry/stop/debug/pid/disconnect) | ✅ `cmd::ctl_simple` — 5-line wrappers around `CtlSocket` |
| `tincctl.c::cmd_config` (1774-2138) | ✅ `cmd::config` — three-stage seam, `TmpGuard` RAII (tighter than C's leaked tmpfiles), Subnet validation via `tinc-proto::Subnet` |
| `tincctl.c::connect_tincd` + `recvline`/`sendline` + `pidfile.c::read_pidfile` | ✅ `ctl.rs` — `CtlSocket` + `Pidfile` |
| `control.c` | daemon-side `match`. **`CtlRequest` discriminants already aligned** — the daemon's switch is a straight transcription. |
| ~~`invitation.c`~~ | **Reclassified to 4a, both halves landed.** 1484 LOC → ~1010 LOC Rust (invite+join+crypto kernel) after dropping HTTP probe / ifconfig.c / tty prompts. `server_receive_cookie` (the daemon's `receive_invitation_sptps` body) lives in `cmd::join` for now; lifts to `tincd::auth` in Phase 5. |
| `ifconfig.c` | platform `ip`/`ifconfig` shelling-out for `tinc-up` generation. Used by `finalize_join` for `Ifconfig`/`Route` invitation keywords. **Stubbed**: keywords recognized (no "unknown variable" warning), placeholder `tinc-up` written, no per-platform shell generation. -300 LOC. Lands when someone needs it. |

**Windows caveat unchanged:** named pipe, `windows-sys` raw
`CreateFileW`. ~100 LOC behind `#[cfg(windows)]`.

---

## Phase 5 — The Daemon Core (~6 weeks)

Only attempt this once Phases 1–3 are battle-tested.

### Event loop — ✅ `tinc-event` (`aeabcaa6`)
mio + manual poll, single-threaded. tokio rejected: the C's pervasive
shared mutable state (`node_tree`, `connection_list` globals) fights
async borrow rules; one `&mut Daemon` into every handler mirrors the
C globals without `static mut`. The C design is fine, just unsafe.

**Dispatch enum, not callbacks.** C `io_add(&io, cb, data, fd, flags)`
stores fn pointers; cb reaches `node_tree` via globals. Rust can't
store `fn(&mut Daemon)` inside `Daemon`. The cb set is closed: 6 io
callbacks (`rg 'io_add\(' src/*.c`), 7 timer callbacks. Encode as
`enum IoWhat`/`enum TimerWhat`; the loop body is a `match`.
`EventLoop<W: Copy>` stays daemon-agnostic.

**`BTreeMap<(Instant, u64)>` not `BinaryHeap`.** All 7 timers re-arm
(`timeout_set` from inside the cb, `event.c:127-129` checks if cb
re-armed past now). Heap entries immutable → re-arm = push+tombstone
churn. BTreeMap remove-reinsert is O(log n) same as C splay. The `u64`
seq does what `event.c:62-72`'s ptr-compare does, stably. **Deliberate
semantic difference**: C auto-deletes if cb didn't re-arm; we make
re-arm explicit. Every match arm decides.

**Self-pipe hand-rolled** (`signal-hook` was +3 deps for 90 LOC of C).
`sigaction(SA_RESTART)` not `signal()`. `pipe2(O_CLOEXEC)`. Shim #7.

**`while(running)` not ported.** `turn()` is one iteration. The loop,
`event_exit()`, the tick/turn interleave — that's `tincd::main()`.

**SIGHUP reload:** `reload_configuration()` does *not* rebuild from scratch — it walks the live subnet/node trees, marks entries `expires = 1`, re-reads configs, then sweeps expired entries while keeping connections alive. With `slotmap` this means `Daemon::reload(&mut self)` walks and patches in place. Do not assume "drop arena, build new one"; budget ~200 LOC for the selective expiry walk.

### Module mapping (`85236bac`)

~9200 C LOC remaining of the daemon's 12422 (`src_tincd` in `meson.build`). At post-cleanup ratios (1.5× code-only, ~5× file-LOC with table-driven tests), figure ~45k file-LOC remaining.

| C source | LOC | ported | what's done / what's left |
|---|---|---|---|
| `event.c` + `linux/event.c` + `signal.c` | 476 | ✅ | `tinc-event`. `bsd/event.c`/`event_select.c` are mio's job. |
| `dummy_device.c` + `linux/device.c` + `fd_device.c` + `raw_socket_device.c` | ~550 | ✅ | `tinc-device`. `bsd/device.c` open() is a cfg-gated stub (read/write paths tested via pipe fakes). |
| `buffer.c` | 110 | ✅ | `tincd::conn::LineBuf`. The range-invalidation bug from chunk 2 is the load-bearing finding. |
| `connection.c` | 175 | ✅ | `tincd::conn::Connection` + `daemon::dump_connections` inline. `status_value()` builds the GCC-LSB-first bitfield int (only bits we model; rest are 0 anyway at this stage). |
| `meta.c` | 322 | ~85% | `feed`/`feed_sptps` + `dispatch_sptps_outputs`. `Record` arm → `record_body` strip + `check_gate`; `HandshakeDone` arm → `send_ack`. `send()` grew the `sptps_send_record` branch. Left: `tcplen` arm (`:143-152`, `tcppacket_h` body delivery, chunk 8). |
| `protocol.c` | 245 | ~80% | `check_gate` (dispatch) + `seen_request` cache + `age_past_requests` timer. Left: `forward_request` (`:135-146`, chunk 6). |
| `protocol_auth.c` | 1066 | ~45% | `id_h` peer+control + `send_ack` + `ack_h` done. Left: `?` invitation branch (~80) chunk 10; `send_everything` (`:870-900`, 30 LOC — `for splay_each` ×2 → `send_add_subnet`/`send_add_edge`) needs chunk-5 trees; `send_ack` per-host config (`:844-865`, 22) chunk 9; legacy (~400) defer. |
| `keys.c` | 334 | ✅ | `tincd::keys`. The `& ~0100700u` perm-check bug ported as C-is-WRONG #7. |
| `control.c` | 241 | ~25% | REQ_STOP + REQ_DUMP_CONNECTIONS + REQ_DUMP_SUBNETS. 11/14 `REQ_*` left (chunk 8). CLI client side already speaks the protocol; daemon side is `match` arms that walk trees and `writeln!`. `init_control` landed in chunk 2. |
| `pidfile.c` | tiny | ✅ | `Pidfile::read` (CLI side) + write (daemon, chunk 2). |
| `net_socket.c` | 884 | ~35% | `tincd::listen` (listeners + tarpit). Left: outgoing connections (`do_outgoing_connection` etc, ~250) chunk 6; chunk-3 listener worklist (`bind_reusing_port` etc) chunk 10. |
| `net.c` | 527 | ~10% | `terminate_connection` partial. Left: `periodic_handler` (timeout sweep), `try_tx`, `purge`. |
| `net_setup.c` | 1336 | ~10% | Skeleton `setup_myself`. Left: `setup_myself_reloadable` (~500), `load_all_nodes` (~100), device enable/disable script hooks. |
| `tincd.c` | 735 | ~40% | `main.rs` argv + signal install. Left: `--mlock`, `--chroot`, `--user`, the `daemon()` call, SIGHUP→reload. |
| `node.c` | 232 | ~30% | Three-way: `Graph` (topology), `node_ids: HashMap<String, NodeId>` (the C `lookup_node`), `nodes: HashMap<String, NodeState>` (runtime). `lookup_or_add_node` is the C's `n = lookup_node(name); if(!n) node_add(n)` idiom. Left: node_id_t for UDP, per-tunnel SPTPS, `dump_nodes` (chunk 7/8). |
| `edge.c` | 138 | ~50% | `tinc-graph::add_edge`/`del_edge`/`lookup_edge` (free-list slab, `8dc93535`) + `on_ack`'s edge-build. Left: `dump_edges`; the per-edge address store (`e->address`, currently in `NodeState.edge_addr`). |
| `subnet.c` | 409 | ~70% | `SubnetTree` (the lookup tree, descending-prefixlen Ord). `add`/`del`/`lookup_ipv4`/`lookup_ipv6`/`lookup_mac`/`iter`. `dump_subnets` daemon-side. Left: hash cache (`:33`), `subnet_update` script firing (chunk 8). |
| `protocol_edge.c` + `protocol_subnet.c` | 583 | ~60% | All four `*_h` handlers. `seen.check` → `lookup_or_add_node` → tree mutation → `run_graph`. STUBBED: `forward_request`, send-correction retaliation, `contradicting_*` counters. The `tunnelserver`/`strictsubnets` modes deferred. |
| `graph.c` | 327 | ✅ | `tinc-graph::sssp`/`mst` + `graph_glue::diff_reachability`/`run_graph`. The sssp→diff→mst order pinned (`run_graph_mst_sees_writeback`). Transition handling beyond log lines: chunk 7/8. |

| `protocol_key.c` | 648 | 0 | chunk 7. Per-tunnel SPTPS bootstrap. REQ_KEY/ANS_KEY over meta connection establish a *second* SPTPS session (datagram-framed) for the UDP data plane. `tinc-sptps` already does datagram framing. |
| `protocol_misc.c` | 376 | 0 | chunk 8. PING/PONG, TCPPACKET, UDP_INFO, MTU_INFO. `tinc-proto::msg::misc` already has wire format; these are tiny handlers. |
| `net_packet.c` | 1938 | 0 | chunks 7+9. **The hot path.** Chunk 7 takes the send/recv core (~500); chunk 9 adds MTU probing, compression, TCP-fallback. Preallocated `[u8; MAXSIZE]` on stack, no per-packet `Vec`. |
| `route.c` | 1176 | 0 | chunks 7+9. Chunk 7 takes `route_ipv4` happy-path (~50 of 1176); chunk 9 adds ARP/NDP spoofing, ICMP unreachable, ClampMSS, broadcast, RMODE_SWITCH. `etherparse` crate evaluated for the packet header parsing — might cut the v6 ext-header LOC in half. |
| `address_cache.c` | 284 | ~80% | `addrcache.rs`. Text-format (`SocketAddr::Display`) not C struct dump (platform-specific `sockaddr_storage` layout). next_addr/reset/add_recent/save. Left: lazy hostname resolve (`:170` `str2addrinfo`, chunk 6). |
| `route.c` `inet_checksum` + headers | ~100 | ✅ | `packet.rs`. `#[repr(C, packed)]` Ipv4Hdr/Ip6Hdr/IcmpHdr/Icmp6Hdr/EtherArp + KAT-locked checksum (native-endian `memcpy` load, RFC 1071 §2(B)). Ready for chunk-9 builders. |
| `process.c` | 243 | 0 | chunk 8. `daemon()`, setuid, scripts. Ship-#1's SIGPIPE-from-dropped-stderr finding applies to script spawn. |
| `proxy.c` | 285 | defer | SOCKS4/5, HTTP CONNECT. Niche. |
| `multicast_device.c` | 224 | defer | niche backend. |
| `autoconnect.c` | 197 | defer | heuristic ConnectTo. Nice-to-have. |
| `splay_tree.c` + `list.c` | ~800 | drop | std collections. |
| `getopt*.c` | ~1k | drop | clap. |

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
| UML, VDE, multicast devices | Feature-gated, port only on demand. raw_socket landed at `5db2ea3e`. |
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
| CLI | `clap`, ~~`ratatui` (for `tinc top`)~~ hand-rolled ANSI shim, `rustyline` |
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
2. ✅ **`tinc` CLI in Rust** — 34/39 commands. `cross_init_key_loads_in_c` is the wire-compat closure: `OsRng` → `from_seed` → `write_pem` → `tinc-b64` → C `ecdsa_read_pem_private_key` → C `sptps_start` → 256 bytes match. The 5 unported are 2 daemon-gated + 1 daemon-only-RPC + 2 legacy-RSA.
3. **`tincd` Rust, SPTPS-only (`nolegacy` mode)** — ~18 weeks in
4. **`tincd` Rust with legacy protocol** — ~24 weeks in

Total: roughly **7 months** for one experienced engineer. The extra month over a naïve estimate is the bespoke-crypto tax: each of ChaPoly/ECDH/PRF/key-format is two days to implement and two weeks to be *certain*. The Phase 0 KAT vectors are the highest-leverage investment in the whole plan — they turn "is the crypto right?" from a debugging nightmare into a `cargo test` boolean.
