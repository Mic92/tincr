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
| **5 chunk 6 — outgoing connections + `forward_request`** | ✅ 3 commits | `tincd: two-daemon integration test — proves the full chunk-6 chain` | Three commits, one workmux serial (clean seams). **`forward_request` collect-then-send**: slotmap iter borrow conflicts with `get_mut`; same two-phase shape as `dispatch_sptps_outputs`. Broadcast is per-topology-change not per-packet; the alloc doesn't matter. **The active flag**: `meta.c:115` filters on `c->edge != NULL` (the C's pointer-as-bool past-ACK mark, set by `ack_h:1051`). We didn't store EdgeId on `Connection`; bool is enough. `connection.h:40` calls bit 1 `unused_active` — the C never sets it; we do, so two-daemon test polls "past ACK" via `dump connections` not log scraping. **`send_everything` flattens**: C `:892-899` per-node nesting is an artifact of `n->subnet_tree` hanging off `node_t`; `SubnetTree::iter()` + `Graph::edge_iter()` is same wire output, less indirection. **Async-connect via dup()**: probe needs `&socket2::Socket` (for `take_error`); `Connection.fd` is `OwnedFd`. dup the fd; probe socket lives in `connecting_socks` for ~1 RTT then drops. C uses raw `int`, no split; the cost of type-safe ownership. **`TimerWhat::RetryOutgoing(OutgoingId)`** — was unit variant; now carries the slot. C has one `timeout_t ev` per `outgoing_t`; we have one `TimerId` per `OutgoingId` in `SecondaryMap`. **`id_h` outgoing branch**: `:383-393` name MUST match (DNS hijack defense), `:451` don't send ID again, `:461-467` label arg order swapped + `Role::Initiator`. **mio edge-trigger bug** (the prize finding): first two-daemon run HUNG at "Connected to bob", `ss` confirmed ESTABLISHED, both in `epoll_wait`, zero bytes. mio always sets `EPOLLET`. WRITE edge fires ONCE; `on_connecting` consumed it for the probe; `finish_connecting` queued ID; old `continue` waited for another WRITE edge that never comes (socket was already writable when queued). C `handle_meta_io:553` clears `connecting` then FALLS THROUGH to `:556`. Same edge, same wake. Probe-spurious DOES return. Fix: `on_connecting -> bool`, true=fallthrough. **Invisible to everything except two real epoll loops** — unit tests are pure, chunk-5 test-as-peer does blocking reads (no edge-trigger). 15→1 STUB(chunk-6) (last one re-chunked to 7: `getsockname` for inbound `local_address`). 831→839 tests + `two_daemons.rs`. ~550 C LOC → ~2.3k Rust. |
| **5 chunk 7 — first packet: minimal data plane** | ✅ 4 commits | `tincd: first packet across the tunnel — socketpair-TUN end-to-end` | **`first_packet_across_tunnel` passes in 70ms.** TUN read → `route()` → `Forward{to: bob}` → `!validkey` → `send_req_key` (kicked, packet dropped — C `:686` buffers nothing) → REQ_KEY over meta-SPTPS → bob's `on_req_key` → responder `Sptps::start(Datagram)` + feed initiator's KEX → ANS_KEY back → alice's `on_ans_key` → SIG out → … → `HandshakeDone` both sides. NEXT TUN read → `send_record(0, ip[14..])` → `Wire` → `[nullid][src_id6][ct]` → `sendto`. Bob's `on_udp_recv` → strip 12 → `id6_table.lookup(src)` → `sptps.receive` → `Record{0, ip}` → re-prepend ethertype from `ip[0]>>4` → `route()` → `Forward{to: myself}` → `device.write`. **The two-SPTPS architecture made flesh**: handshake of the SECOND SPTPS transported as ANS_KEY records inside the FIRST. C `send_initial_sptps_data` swaps the callback after the first Wire (`REQ_KEY` for KEX, `ANS_KEY` after); we dispatch on `first` bool. **`dispatch_tunnel_outputs`** is BOTH C callbacks fused: `Wire` → `send_sptps_data` (TCP or UDP by `record_type == REC_HANDSHAKE`), `HandshakeDone` → set `validkey`, `Record` → `receive_sptps_record`. **Device rig**: `socketpair(SOCK_SEQPACKET)`, daemon end as `DeviceType=fd` (via `FdTun` — chunk-3's Android backend, repurposed; reads at `+14`, synthesizes ethertype from IP nibble). Daemon end NEEDS `O_NONBLOCK` (`on_device_read` loops to EAGAIN, level-triggered); `fd_device.c` doesn't set it (Java-parent's job), test does. **C interop snag found**: C `protocol_key.c:996` sends `"-1 -1 -1"` for cipher/digest/maclen; `sscanf("%lu", "-1")` is glibc-permissive (wraps to ULONG_MAX); our `u64::parse` rejects. `STUB(chunk-9-interop)`: send `0 0 0` for Rust↔Rust; loosen parser when interop-testing C. **`getsockname` unstubbed** via `socket2::SockRef::from(&OwnedFd)` (no unsafe, `&OwnedFd: AsFd`). **`Subnet` config-load** added (`net_setup.c:860-870`): without it `route()` returns `ICMP_NET_UNKNOWN` for everything. **`dump_nodes` now real**: `id6_table.id_of()`, `TunnelStatus::as_u32()`, traffic counters, mtu fields. ~35 `STUB(chunk-9)` markers (relay, REQ_PUBKEY, compression, PMTU, TCP-fallback, ICMP synth). 856→857 tests + 9 cross-impl. ~1200 C LOC traced → ~1.8k Rust (vs ~6k estimate — the prep modules paid off; this commit is glue). |
| **5 chunk 7+ — bwrap netns harness** | ✅ | `tincd: bwrap netns harness — real TUN, no root` | **`--tmpfs /dev` (NOT `--dev /dev`) is the load-bearing flag.** Kernel `2ab8baf` (2016) checks the device-node mount's owning userns at `TUNSETIFF`; binding host devtmpfs inherits init-ns ownership and EPERMs. A userns-owned tmpfs at `/dev` with `/dev/net/tun` dev-bound on top satisfies the check. Promotes Phase-6 testing from root-only to CI-default. **The two-TUN-addrs-one-netns shortcut**: both addrs in one ns are kernel-local → ping shortcuts via `lo`. Fix: `TUNSETIFF` in outer ns, then `ip link set tinc1 netns CHILD`. **fd→device binding survives the move** (`tun_chr_write_iter` follows `file->private_data`, not netns). Bob's daemon stays in outer ns; bob's TUN packets land in child kernel. **Self-exec trick**: outer test spawns `bwrap ... -- /proc/self/exe --exact <test-name>`; inner sees `BWRAP_INNER=1`. Runtime-skips (passes as no-op) when bwrap unavailable — discoverable, non-blocking. **`real_tun_ping`**: kernel ICMP → tinc0 → daemon → SPTPS → UDP loopback → daemon → tinc1 → kernel reply. 1.3ms RTT. 857→858 tests. The `+14`-offset reads, `IFF_NO_PI` framing — formerly CI-dark — now lit up. |
| **5 chunk 8 — keepalive sweep, scripts, periodic** | ✅ 2 commits | `tincd: wire ping sweep, PING/PONG, scripts, periodic_handler` | Leaf+serial pair: `984bdfdc` `script.rs` (331 LOC, 6 tests) + `f8bc46ae` daemon wire-up (730 net LOC). **The system() vs Command shebang diff** is the load-bearing decision: C `system()` is `sh -c`, so shebang-less scripts work as sh; `Command::new()` is `execve()` → ENOEXEC. Doc'd prominently; `ScriptInterpreter` config var is the escape hatch. The C's `putenv()` mutates process env (every script call leaks vars to the next); `Command::envs` makes the 35-LOC `unputenv()` workaround evaporate. **`on_ping_tick` body** (`net.c:180-266`): four cases per conn — skip control, force-close-all on laptop wake, terminate pre-ACK timeouts, terminate pinged-no-PONG, send PING when idle. The laptop-suspend detector (`now - last_periodic_run_time > 2×udp_discovery_timeout`): daemon was asleep, peers gave up, SPTPS contexts are stale; force-close everything so outgoings retry fresh. **Born-stale-conn race found**: `Connection::new_meta` stamps `last_ping_time` from cached `timers.now()`, up to 1s stale when accept arrives mid-turn; with `PingTimeout=1` the conn is reaped before `id_h` runs. **C has the same race** (`net_socket.c:764`); `PingTimeout=1` was always unrealistic. Bumped to 3. **periodic_handler**: contradicting-edge storm detection (two daemons fighting over the same Name). The `sleep_millis` is **synchronous** — daemon BLOCKS during backoff; blocking IS the throttle. Sleeptime doubles each trigger (cap 3600s), halves each clean tick (floor 10s). **PONG resets backoff** but only if `outgoing.timeout != 0` — healthy conns pong every `pinginterval`, shouldn't churn the cache. SIGHUP mark-sweep re-chunked 8→10 (depends on `reload_configuration`). 868→873 tests. 6× `STUB(chunk-8)` → 0 (5 cleared, 1 re-chunked). |
| **5 chunk 8+ — security.py + splice.py port** | ✅ | `tincd/tests: S1 port of security.py + splice.py` | Five S1 negative tests for the protocol's security boundary — all chunk-4a-viable, all gates already in `proto.rs`. The big finding: **`splice_mitm_rejected` proves TWO defense layers**, not one. Layer 1 (the one I expected): `tcp_label` argument order — alice's label is `"...alice bob\0"`, bob's is `"...bob alice\0"`; relay swaps claimed identities; transcripts diverge; SIG fails. Layer 2 (agent found): **SPTPS role asymmetry** — both daemons are Responders (the relay connected TO both); neither sends SIG on KEX-receipt; deadlock before label even matters. The test exercises layer 1; layer 2 is pinned by the proto unit test. `legacy_minor_rejected` isolates the version gate (the python sends own-name AND `17.0`, conflating two gates). `id_timeout_half_open_survives` was PARTIAL pre-chunk-8 (asserted no-crash); chunk-8's sweep made it assert EOF. Tarpit integration test omitted: loopback-exempt; unit tests cover the bucket arithmetic. 859→864 tests. |
| **5 chunk 9 — route.c rest, net_packet.c rest** | ✅ 8 commits, 6 leaves + 2 serial | `tincd: relay path, PMTU/neighbor wiring, try_tx (chunk 9b)` | Six pure leaf modules (3376 LOC, 94 tests, all `#![forbid(unsafe_code)]`) + two serial daemon.rs wire-ups. The leaf-first decomposition paid off: each is the same `(input bytes) → enum result` shape as `route::RouteResult`; daemon dispatches. **`icmp.rs`** (`route.c:121-327`): RFC 792/4443 quoted-original synthesis. `build_v4_unreachable(frame, type, code, frag_mtu) → Option<Vec>`. The TTL-exceeded `getsockname` dance (`:148-169`, find which local IP faces the sender) is `STUB(chunk-9-relay)` — I/O in pure synth, only matters when we're a relay hop. **`mss.rs`** (`route.c:389-487`): TCP option TLV walk + RFC-1624 incremental checksum. The C **doesn't gate on SYN flag** — clamps any TCP packet with the option (in practice MSS only appears in SYN/SYN-ACK). 21 tests including a sweep that recomputes from scratch and asserts the incrementally-adjusted result matches. **`compress.rs`** (`net_packet.c:240-400`): zlib 1-9 (`flate2` miniz), LZ4 12 (`lz4_flex::block` — RAW block, no frame, no prefix; matches `LZ4_compress_fast_extState`), LZO 10/11 `STUB(chunk-9-lzo)`. **Cross-impl KAT**: real zlib `compress2` output → our decompress; miniz output bytes ≠ zlib but both implement deflate spec. **`neighbor.rs`** (`route.c:793-1035`): ARP/NDP reply synthesis. **The fake-MAC trick**: kernel ARPs for next-hop MAC before sending into TUN; we answer with `kernel_mac XOR 0xFF` (last byte) — a different mac, derived; kernel caches it; daemon ignores eth header anyway. NDP verifies ICMPv6 checksum on parse (link-local trust = hop-limit-255 only; checksum is the integrity check). **`pmtu.rs`** (`net_packet.c:90-240,1170-1460`): the 5-phase `mtuprobes` state machine. **The exponential KAT-locked**: `probe_size(0, 1518, 0)` ≈ 1329, `probe_size(1329, 1518, 1)` = 1407 (the math-simulation magic values from `:1419` comment). Concentrates near minmtu because most probes are too-large-no-reply. **C `for(;;)` synchronous-EMSGSIZE feedback unmodeled**: `tick()` returns ONE probe, `on_emsgsize()` recomputes, next tick uses new bounds — slightly slower converge, same outcome. **`route.rs::route_ipv6+decrement_ttl`**: same `RouteResult` shape; `TtlResult` has 4 reified exits. **C-is-WRONG #8 found here**: `route.c:344` storm-guard reads `[ethlen+11]` (= `ip_sum` low byte) for `IPPROTO_ICMP` and `[ethlen+32]` (= quoted-IP `ip_len`) for `ICMP_TIME_EXCEEDED`. Correct: `+9`/`+20`. **14-year-old bug** (`f1d5eae6`, 2012-02). Benign — TIME_EXCEEDED synthesized with TTL=255, 254+ hops to re-expire. Ported faithfully. **Chunk-9a serial** (`1763e0b9`): wired icmp/mss/compress. **`real_tun_unreachable`** (S3): `ping 10.42.0.99` → kernel says "Destination Net Unknown". **End-to-end wire-format proof** — bad checksum or wrong quoted-header would just time out. Agent **rejected LZO at handshake time**: failing fast beats packet-loss-debug at runtime (our `compress()` returns None; raw fallback would corrupt their decompress). **Chunk-9b serial** (`18fa47b0`, 1535 net LOC): the relay path + everything else. **`three_daemon_relay`** (S2): alice→mid→bob with no direct ConnectTo. **Found a chunk-5 bug**: `on_add_edge` idempotence checked only `weight+options` — C `protocol_edge.c:144` also checks address. mid's `on_ack`-synthesized `bob→mid` reverse half had no `edge_addrs` entry; when bob's real ADD_EDGE arrived (same w/o, with addr), C `sockaddrcmp(zero, real)` ≠ 0 → falls through to update+forward; ours early-returned → **alice never learned `bob→mid`**, sssp had no path. The chunk-5 comment "weight+options is what matters for graph topology" was correct for TOPOLOGY but missed that the early-return suppresses the FORWARD. 10s hang → 0.15s. `stop.rs::peer_edge_triggers_reachable` was pinning the OLD broken behavior; updated. ~1500 C LOC traced → ~5.5k Rust. 938 tests. **49 → 28 `STUB(chunk-9)` + 18 → `chunk-9c`.** |
| **5 chunk 9c — config gates, tunnelserver, try_tx recursion** | ✅ 1 commit | `tincd: tunnelserver, directonly, try_tx recursion (chunk 9c)` | 28+18 stubs → ~5. One agent, 16 minutes, +31 tests. **`three_daemon_tunnelserver`** is the prize: same `three_daemon_relay` harness with `mid.with_conf("TunnelServer = yes")`; asserts the asymmetric world view (alice `dump nodes` = 2, mid = 3) AND the data-plane consequence (`ping 10.0.0.2` from alice gets ICMP `NET_UNKNOWN` at byte `[21]==6` — alice doesn't have bob's subnet because mid never forwarded it). **Better than `net.py::test_tunnel_server`** which only checks the dump. **Gate placement is the load-bearing decision**: BEFORE `lookup_or_add_node` (so we don't pollute graph with indirect names), AFTER `seen_request` (so dups from another conn don't re-process). C does it after-lookup-before-new_node because their lookup is just-lookup; ours is lookup-or-add. String-compare names instead. **`on_add_edge` has TWO names**: drop only if NEITHER is us-or-direct-peer. **`try_tx` via-recursion** (`net_packet.c:1487-1498`): static-relay deref, then recurse on `via` instead. Read `last_routes`, copy out `NodeId`, drop the borrow, THEN recurse — same two-phase as `forward_request`. Finite (sssp tree, max depth = graph diameter). The `(via->options >> 24) < 4` gate matters for old-C-tincd interop. **Re-chunking**: switch/TAP cluster → `chunk-12-switch` (11), LAN-direct cluster → `chunk-10-local` (10), `try_harder`/legacy → `chunk-never`, `subnet_cache_flush` → DELETED (we don't HAVE a cache; don't stub a flush for a cache that doesn't exist). 938→1969 tests. daemon.rs 6587→6958. |
| **5 chunk 10 — SIGHUP reload, invitation server, PROXY_EXEC** | ✅ 5 leaves + 1 serial, 6 commits | `tincd: SIGHUP reload, invitation server, PROXY_EXEC (chunk 10)` | Five pure leaf modules (3687 LOC, 102 tests) + one serial. Same chunk-9 decomposition. **`tinc_join_against_real_daemon`** is the strongest test in the suite: REAL `tinc_tools::cmd::join::join()` (the actual CLI code, as `[dev-dependencies]`) over real TCP against the daemon's `?` branch. End-to-end: `0 ?<throwaway-b64> 17.1` greeting → daemon checks `invitation_key.is_some()` → plaintext `0 alice 17.7\n4 <inv-pubkey-b64>` back → SPTPS handshake (15-byte label, **NO trailing NUL** — string literal + explicit count, vs `tcp_label`'s sizeof-VLA accident; pinned by `invite_label_no_nul`) → type-0 cookie record → `serve_cookie` (atomic-rename to `.used` IS the single-use enforcement) → `chunk_file` 1024-byte type-0s + empty type-1 → joiner writes `bob/tinc.conf`+`hosts/alice`+generates identity → type-1 pubkey back → `finalize` writes `alice/hosts/bob` (`create_new(true)` = the `fopen("x")` exclusive-create, security-relevant: don't overwrite an attacker's pre-populated key) → type-2 ack → unlink `.used` → close. **Second join with same cookie fails** (rename hits ENOENT). The in-process pump test in `join.rs` proved the protocol; THIS proves the daemon's epoll dispatch. **`sighup_reload_subnets`** (S2): rewrite `hosts/alice` mid-run, `kill -HUP`, poll bob's `dump subnets` until the diff propagates. Proves: re-read → `reload::diff_subnets` (the C mark-sweep is `BTreeSet::difference`) → `broadcast_subnet` ADD/DEL → bob's `on_add/del_subnet`. Then the inverse. **`reload::conns_to_terminate`**: the `:447` mtime check (`stat() || mtime > last_check` — the `||` means deleted-file ALSO terminates). The `>` not `>=` one-second-granularity means a file written between two same-second reloads doesn't trigger; **C has this issue**, doc-commented not fixed. **`socks.rs`** (`d988b79f`): SOCKS4/5 byte format. **C-is-WRONG #9**: `proxy.c:201` `*auth++ = userlen` size_t→u8 implicit truncation; 256-byte username sends `[00]`, proxy reads 0 bytes. RFC 1929 says 1..255. We bound-check, error at config load. **NOT wired this chunk** — SOCKS needs a conn state machine (read `tcplen` bytes BEFORE id_h dispatch); `STUB(chunk-11-proxy)`. **`do_outgoing_pipe`** (PROXY_EXEC): the simple proxy mode. `socketpair(AF_UNIX, SOCK_STREAM)`, fork, child dup2's `sock[1]` to fds 0+1, `execvp(/bin/sh -c $cmd)`. **The ONE `unsafe` block** in chunk 10. Post-fork in MT program: child does **libc-only** until exec (no allocator, no std). The parent treats `sock[0]` as the TCP fd; same `Connection::new_meta` path. `proxy_exec_roundtrip("cat")` proves the plumbing. **Hoist**: `invitation_serve.rs::serve_cookie` is `tinc-tools/join.rs::server_receive_cookie` nearly verbatim — dependency direction (daemon can't dep on tinc-tools), so hoist. The `tinc-crypto::invite::cookie_filename` math is the shared piece. **Security checks preserved**: `BadPubkey` on newline (config injection defense, `protocol_auth.c:125`), `HostFileExists` on pre-existing `hosts/{name}` (`:131`). ~1100 C LOC traced → ~5.5k Rust. 969→1033 tests. daemon.rs 6958→7736. **`STUB(chunk-10)` 7→0**, re-chunked: `recvmmsg`/`PERF` → `chunk-11-perf` (4), proxy SOCKS/HTTP/BindToAddress → `chunk-11-proxy` (8). |
| **5 chunk 11 — autoconnect + UDP/MTU_INFO + has_address + cross-impl + LZO** | ✅ 5 commits | `tincd: cross-impl tests run by default in nix develop` | Five commits, two **wire bugs found**. Stub clearing: `chunk-11`→0, `chunk-10-mtu-hint`→0, `chunk-10-local`→6, `chunk-9-lzo`→1 (LzoHi), `chunk-9-interop`→0. **`b0c66155` minilzo vendor**: we call THE SAME C code C tinc calls (~6k LOC GPL-2.0+ C89, builds anywhere). LzoHi compress stays stubbed (minilzo doesn't include `_999`); decompress works for both (same `_safe` fn). Asymmetry is fine: compression is per-direction. **`7ba8bc2d` chunk-11 serial** (962 daemon.rs LOC): `load_all_nodes` adds hosts/-only names to graph (matching `net_setup.c:186-189`), `has_address` is `HashSet<String>` not a NodeState field (different lifecycle), UDP_INFO chain-forward terminates at `to_is_myself`, `update_node_udp` collapses to one assignment (we don't have `node_udp_tree`). Tests asserted COUNTS pre-load_all_nodes; updated to assert REACHABLE (the actual invariant). **`38ba4aa6` cross-impl test**: 647 LOC, env-gated, only ever ran as SKIP. **`463b9987` THE PAYOFF**: first real run against `.#tincd-c` → **two wire bugs** invisible to Rust↔Rust. UDP-label NUL: `protocol_key.c:122` `labellen = 25 + strlen(a) + strlen(b)` is one MORE than the formatted string — the `snprintf` NUL goes into HKDF; we omitted it; `BadSig` on every per-tunnel handshake. TCP label already correct (the `sizeof`-of-VLA made the NUL question obvious there; explicit `25+` here didn't). PACKET dispatch: C floods TCP-tunnelled MTU probes pre-UDP-confirm; we had no arm → terminate → reconnect loop. Rust daemon never sends them so Rust↔Rust missed it. **`ed1e9d95` make it run by default**: `.#tincd-c` fileset is `src/`-only → Rust edits don't invalidate → devshell can depend on it for free. Harness fix: drain C `-d5` stderr in a background thread (64KiB pipe fills in ~2s, `fprintf` blocks, event loop freezes mid-handshake — the test hung in `dump`, not in `poll_until`). 1080→1091 tests. daemon.rs 7736→8709. |
| **5 chunk 11+ — SOCKS wire, route_mac leaf, throughput gate** | ✅ 5 commits | `tincd: fix edge-triggered meta-conn drain deadlock — found by throughput gate` | Three workers + one debug. **`e841d05e` SOCKS wire** (727 LOC, +5 tests): `tcplen` multiplexed for proxy reply (pre-SPTPS raw `read_n`) vs PACKET (post-SPTPS record); mutually exclusive by `FeedResult` arm. `finish_connecting` queues SOCKS bytes THEN ID line in one flush; proxy reads its bytes, replies, forwards ID to peer. In-process RFC 1928 server asserts every byte. `chunk-11-proxy` 8→0, re-chunked to `chunk-12-{bind,http-proxy}`. **`52f6f348` route_mac.rs** (560 LOC, +15 tests): `(RouteResult, LearnAction)` two-channel — daemon owns gossip, leaf stays pure. `RouteResult::Broadcast` new variant. **`efdd4092` throughput gate** (1032 LOC, `#[ignore]`): three configs (C↔C / R↔R / R↔C), `perf record -g -F 999` during 5s window, top-10 self-time always reported. **GATE FAILED on first run: R↔R 0.0 Mbps, C↔C 910.** Ping passed; iperf MSS-sized didn't. **`2b5dda45` THE FIX**: not a port error — a level-vs-edge semantic mismatch. C `meta.c:185` does ONE `recv()` per callback (level-triggered: leftover bytes re-fire). mio is `EPOLLET`. We mirrored C; one iperf3 burst → hundreds of ~2KB SPTPS_PACKET on meta-conn → bob recv()s once → edge fired → never reads again → bob's TCP rcvbuf fills → alice EAGAIN forever. Fix: 64-iteration drain + `EPOLL_CTL_MOD` rearm at cap. Same applied to `on_device_read` (was unbounded). **0.0 → 850 Mbps release.** Residual ~18% gap is per-packet `Vec` allocs (`Sptps::send_record_priv` 7% in profile) — `STUB(chunk-11-perf)`. The third Rust-is-WRONG. Why nothing caught it: every test fit meta-conn traffic in one 2176-byte read. 1091→1111 tests. daemon.rs 8709→9043. |
| **5 chunk 12-prep — daemon.rs split + 4 leaves + scripts.py port** | ✅ 6 commits | `tincd: tests/scripts.rs — fire subnet-up for own subnets at startup` | One mechanical refactor + four parallel leaves + one test-file-that-found-bugs. **`abb2d2bd` daemon.rs split** (9043 → 1778 + 6): multi-impl-block, NOT struct surgery. Each `daemon/{gossip,net,txpath,metaconn,connect,periodic}.rs` is `impl Daemon { ... }`. **Privacy is module-scoped, not type-scoped** — a method in `daemon/net.rs` calling `terminate()` defined in `daemon/connect.rs` needs `pub(super)`; the "type is visible → methods are visible" intuition is WRONG across sibling modules. 78 methods got `pub(super)`. `use super::*` + `#[allow(clippy::wildcard_imports)]` — curated per-file imports are merge-friction busywork. 2.3% of the diff is scaffolding (mod lines, impl wrappers, rustfmt-reflowed multi-line sigs); rest is `git --color-moved` clean. All 34 STUB markers survived. **`bc9f223b` mac_lease.rs + broadcast.rs** (466 LOC, 19 tests): chunk-12-switch state machines as pure leaves. The C smushes lease expiry into `subnet_t.expires` (`subnet.h:53`); we can't — `tinc_proto::Subnet` is wire-format, no expiry field. Side table: `HashMap<Mac, Instant>`. Expiry boundary pinned: `route.c:496` is `<` strict-less, `age_exactly_at_expiry` locks it. `learn()` returns true on FIRST lease so daemon knows to arm the timer (`route.c:549`). `mst_targets`/`direct_targets` are pure target selection over the discarded `_mst` from `gossip.rs:994`. `direct_excludes_self` pins `:1650` `n != myself` — easy to miss when myself trivially satisfies `via==n`. **`e015d527` local_addr.rs** (305 LOC, 11 tests): chunk-10-local pure logic. Agent went `RngCore` not `rand::Rng` (matching `autoconnect.rs`; the prompt was wrong). The `&[SocketAddr]`-not-`&[Listener]` decision keeps unit tests socket-free; daemon builds the slice trivially (≤8 elements). C's `:740` no-match-fall-through-with-`*sock`-untouched mirrored exactly — the subsequent `sendto` fails `EAFNOSUPPORT`, daemon logs and moves on. **`aa2f72c2` tcp_tunnel.rs** (530 LOC, 15 tests): chunk-12-tcp-fallback prep. The binary `SPTPS_PACKET` path — NOT the b64-via-REQ_KEY path (already wired). **Found a latent bug while scoping**: `metaconn.rs:892` `_` arm TERMINATES on `Request::SptpsPacket`. A C peer at proto-minor ≥ 7 in `TCPOnly = yes` would get its connection dropped. The throughput gate dodges it by waiting for `minmtu ≥ 1500` (UDP wins, binary fallback never fires); `crossimpl.rs` doesn't set TCPOnly. Nobody noticed. The leaf is the prep; serial wiring will add `c->sptpslen` (twin of `tcplen`) + the dispatch arm. `RouteCtx` chose `&dyn Fn` over plain-data struct — maps 1:1 to C's `lookup_node_id` call sites; fallback path, dyn cost irrelevant. Frame is byte-identical to the UDP wire frame at `daemon/net.rs:1246` (only the transport differs); KAT pins SHA-512[..6] byte order. `random_early_drop` guards `max < 2` to avoid `%0` panic. **`6110347b` tests/scripts.rs** (650 LOC, 4 tests): the `scripts.py` port. **Found two bugs by inspection before any test ran**: `setup()` fires `tinc-up` (`daemon.rs:1422`) but never the `subnet_update(myself, NULL, true)` the C does at `net_setup.c:1273`. Same gap mirrored in `Drop` (`net_setup.c:1298`). Both fixed: same loop shape as the `BecameReachable` arm at `gossip.rs:1061`. The notification mechanism is shell appenders to one log file — simpler than the python's notification socket. `script.rs:194` `Command::output()` blocks, so append order IS firing order. Tests pin `host-up → hosts/NAME-up → subnet-up` from `graph.c:273-294`; `subnet-down → tinc-down` on shutdown; the `#weight` syntax. ~130 C LOC traced (`net_packet.c:732-808/975-986/1614-1660` + `route.c:491-556`) → ~1.5k Rust pure logic + 680 LOC tests/fix. 1111→1160 tests (+49). |
| ~~5 chunk 11-prep~~ | (rolled into chunk 11) | | Two pure leaves landed in 3 minutes. NOT yet wired (serial is next). **`autoconnect.rs`** (701 LOC, 12 tests): `decide(…) → AutoAction`. The `connect_to_unreachable` all-node prng IS the backoff. Agent caught a subtlety the prompt missed: the C `<3` branch early-returns (`:183-186 if(nc<3){make_new();return}`); step 4 (`connect_to_unreachable`) NEVER fires when under-3. The high-prob test required modeling "a node with 3 conns whose graph view shows many unreachable" — a partitioned mesh from inside the connected fragment. **`connect_unreachable_backoff_low_prob`**: 100 nodes, 1 unreachable; 1000 seeded ticks; expects ~10 hits (1% prob). `(5..20).contains(&hits)` — binomial variance bound. THE design-intent test. **`udp_info.rs`** (1237 LOC, 35 tests): `should_send_udp_info(…) → bool` is 7 gates from `protocol_misc.c:155-215`, one test each. The **`(options>>24) < 5` gate** (`:194`): UDP_INFO introduced in protocol minor 5 (2013, `a1e72f84`); a relay running older tincd would log "got bad request" and drop the conn. We're `7<<24` always; gate matters for cross-version interop. **The receive-side payoff** (`:251-257`): only `UpdateAndForward` if `!directly_connected && !udp_confirmed && addr_differs`. Direct conns: meta-socket addr is more authoritative. udp_confirmed: our own probes already verified; relay observations are older. **MTU_INFO** is the same shape: minor 6 not 5, no TCPONLY check (MTU is path-level, not transport-level), payoff is `from->maxmtu = min(from->maxmtu, msg->mtu)` — a relay knows a tighter bound. ~420 C LOC → ~1.9k Rust. 1033→1080 tests. **Chunk-11-serial** wires both: `decide()` into `periodic_handler`, UDP/MTU_INFO send/receive at the 5+10 stub sites. Needs `has_address` tracking (load_all_nodes equivalent — walk `hosts/` at setup). **UPnP**: deferred (separate feature, `igd-next` crate, dedicated thread). |
| ~~6 — cross-impl tincd~~ | ✅ chunk 11 | | Landed as S4. `38ba4aa6` + `463b9987` + `ed1e9d95`. The `sscanf("%lu","-1")` blocker → `Tok::lu()` strtoul-compatible. Ping works both directions in `nix develop` by default. |
| **6 chunk 12 — SPTPS_PACKET fix, http-proxy, local-wire, addrcache test** | ✅ 5 commits | `tincd: HTTP CONNECT proxy — close chunk-12-http-proxy` | Five workmux dispatches across two batches (2+2+1 serial). **`300a8e96` SPTPS_PACKET binary tcp fallback fix**: the latent bug from `aa2f72c2` scoping. Our `feed_sptps` collected records, returned, daemon dispatched AFTER — `sptpslen` set TOO LATE. Same `recv()` chunk has `[SPTPS-framed "21 LEN" \| raw blob bytes]`; blob bytes parsed as SPTPS framing → `DecryptFailed`. Fix: `feed()` inlines the C do-while, peeks for `"21 "` prefix between `receive()` calls. **Agent CORRECTED the prompt's regression test** — `net_packet.c:725` short-circuits direct neighbors to PACKET 17 BEFORE reaching `:975` binary path; SPTPS_PACKET 21 only fires in relay topology, never with `TCPOnly` 2-node. Unit test `feed_sptpslen_then_record` instead: crafted blob `\x00\x09junkjunk!` LOOKS like a valid SPTPS record header (len=9); without the peek, `receive()` tries to chacha-poly-decrypt → Dead. Mutation-tested (`sed s/"21 "/"99 "/` → confirmed Dead). **`15d1b8fb` tests/addrcache.rs**: `address_cache.py` port. 3 restart rounds. Round 3 deletes `Address =` from `hosts/bob`, restarts, connects from cache only — THE proof that `AddressCache::open()` actually wires into the dial path. **SIGTERM not SIGKILL** — `addrcache::Drop` IS the disk write. **`af26db41` HTTP CONNECT proxy**: 2 stubs. `CONNECT host:port HTTP/1.1\r\n\r\n` via `send_raw`; intercept response BEFORE `check_gate` while `allow_request==Id`. **C-is-WRONG #10 found by inspection**: header lines (`Via:`, `Content-Type:`) fall through to `atoi` → "Bogus data" → terminate. RFC 7231 §4.3.6 permits headers in 2xx CONNECT; `proxy.py:155` sends none, so the C never triggered. We mirror the C; lenient mode is a TODO. STRICTER: bracket IPv6 in CONNECT authority (RFC 7230 §2.7.1; C doesn't). **Agent caught BufReader leftover bug** during testing: tinc queues CONNECT+ID in one flush; `BufReader::read_line` ate CONNECT+blank but ID was in the buffer; `into_inner()` would lose it. `reader.buffer().to_vec()` before `into_inner()`, forward upstream. **`67e0dc22` chunk-10-local wire**: 6 stubs. `choose_udp_address` three-mode (`send_locally` override, `udp_confirmed` reflexive, 1-in-3 cycle counter). The cycle counter is daemon-level not per-tunnel (matching C `static int x`). Reflexive append/consume on ANS_KEY relay path; consume gated on `validkey` checked AFTER `dispatch_tunnel_outputs` (which sets it on `HandshakeDone`). `ans_key_reflexive_roundtrip` proves `format_addr_port` → `"%s %s %s"` concat → `AnsKey::parse` → `parse_addr_port` for v4 AND v6; also asserts `msg.format()` is byte-exact (idempotent relay). 1160→1166 tests. |
| **6 chunk 12-switch — RMODE_SWITCH packet path + MAC learning** | ✅ 1 commit | `tincd: chunk-12-switch — RMODE_SWITCH packet path + MAC learning` | **`2bbd51b0`, 21 stubs → 0, 1061 LOC, 1166→1168 tests.** `rust_dials_c_switch` + `c_dials_rust_switch` ping over TAP. Kernel ARPs → `route_mac` sees `ff:ff:ff:ff:ff:ff` → `Broadcast` → `broadcast_packet` sends to bob → reply → ADD_SUBNET gossip propagates → ICMP unicast routes by MAC. Any `Subnet::Mac` wire-format mismatch → ARP times out → ping fails. 3/3 packets, ~1.6ms RTT. **`route_packet` gains `from: Option<NodeId>`** (= C `node_t *source`). Dispatch on `routing_mode`: Switch → `route_packet_mac`; Hub → always Broadcast; Router → fall through. `RouteResult` arms factored into `dispatch_route_result` (mechanical, `--color-moved` clean). **The borrow shape**: `RouteResult<'a>` ties `Forward.to` to `self.subnets`/`self.mac_table`; `dispatch_route_result` is `&mut self`. `detach_route_result()` exhaustively rebuilds with locally-owned `&str` — any new variant trips a compile error there. The Forward arm cloned `to` anyway; this hoists. **`send_sptps_packet` takes `&[u8]`** (verified) → broadcast iterating same buffer to N targets is zero-copy-safe. **The TAP race** found by the test, not the prompt: TAP devices emit IPv6 router solicits the moment they go up, even with no address. Both kernels emit simultaneously while per-tunnel SPTPS handshake is in flight → simultaneous REQ_KEY → handshake restart loop. TUN doesn't (no L2 → no spontaneous frames). Three-phase fix: meta handshake with devices DOWN → `place_devices` brings up → directional kick-ping ensures one side initiates REQ_KEY first. **`learn_mac`**: `subnets.add(Subnet::Mac{weight:10})` + `mac_table.insert` + `mac_leases.learn` + broadcast ADD_SUBNET + lazy-arm `age_subnets` timer (`Option<TimerId>`, only on first lease when `learn() → true`). **`on_age_subnets`**: `mac_leases.age` → expired → broadcast DEL_SUBNET + `subnets.del` + `mac_table.remove`; re-arm if `any_left`, else `timers.del` + `take()`. **Fast handoff**: peer ADD_SUBNET for a MAC we leased → `mac_leases.refresh(addr, now, 0)`; with `age()`'s strict-less compare it expires next tick (≡ C's `expires=1`). **`broadcast_packet`**: `from.is_some()` → echo to device first; `tunnelserver\|BMODE_NONE` → stop; MST mode walks active conns whose `NodeState.edge` is in `last_mst` (the `run_graph().1` no longer discarded). `from_conn` via `last_routes[from].nexthop` → `nodes[nexthop].conn`. **Offset/type**: `Router → (14, PKT_NORMAL)`, `Switch/Hub → (0, PKT_MAC)`. Receive offset is **type-driven** (`:1108`), not mode-driven — cross-mode mismatch warnings match C exactly. `ForwardingMode::Kernel` wired (6 lines). `DeviceType=tap` arm. **Re-tagged**: strictsubnets (5) and overwrite_mac (2) were always orthogonal, mislabeled. ~660 C LOC traced. |
| **6 chunk 12+ — strictsubnets + PACKET 17 batch** | ✅ 2 commits | `tincd: route PACKET 17 (TCPOnly works against C peers)` | **`bc62b722` PACKET 17**: closes `chunk-12-tcp-fallback` ×1 + the mislabeled `chunk-11-perf` at `:1132` (was actually the `n->connection` send gate). Receive: `metaconn.rs` `tcplen!=0` block now does `receive_tcppacket` (MTU check + counters + `route_packet(from=Some)`). Send: the C `:684` `!validkey && !connection` gate — with a direct conn, validkey doesn't matter; without it, first reply hits `!validkey` → REQ_KEY → hang (TCPOnly C `try_tx_sptps:1477` returns early, never sends ANS_KEY). **C-is-WRONG #11**: C gates AFTER compression (`:708-718`); when compression helps, `:716` reassigns to a stack `vpn_packet_t` with uninit `data[0..14]`; `:726` sends garbage prefix; PACKET 17 has no `PKT_COMPRESSED` bit; receiver drops on bad ethertype. STRICTER: gate BEFORE compression. **`two_daemons` fallout**: kick packet was previously dropped at `!validkey`; now goes via PACKET 17 (minmtu=0); drain it; the `udp_confirmed` assert relied on the old broken send path — dropped. Tests: `rust_dials_c_tcponly` + `c_dials_rust_tcponly` (no validkey poll — per-tunnel SPTPS never starts; just reachable → ping 3/3). **`66bea146` strictsubnets**: closes `chunk-12-strictsubnets` ×5 + `chunk-12-bind` ×2 + stale `http-proxy` doc ×1 + NOT-PORTING re-tags ×3. The trick is the **lookup-first ordering at `protocol_subnet.c:93`**: `if(lookup_subnet(owner,&s)) return true` BEFORE the gate at `:116` — `load_all_nodes` preloads authorized subnets; gossip arrives, lookup hits, silent noop; only UNAUTHORIZED subnets fall through. Our `on_add_subnet` lacked this ("BTreeSet-idempotent" was true for data, but the gate would fire on AUTHORIZED subnets). Added `SubnetTree::contains`. `:880` `strictsubnets|=tunnelserver` makes the `:109` gate dead-on-same-predicate — kept both for parity. `on_del_subnet`: forward then early return (`:247-249`). BindToAddress: `bind()` before `connect()`, threaded `Option<SocketAddr>`. Test: `three_daemon_strictsubnets` (alice rejects bob's gossiped subnet → ICMP NET_UNKNOWN; restart with `Subnet=` in `hosts/bob` → preload → noop). 30→17 stubs. |
| **6 chunk 12+ — residuals sweep + first perf increment** | ✅ 4 commits | `tincd: routing-loop guards + FRAG_NEEDED + maxoutbufsize plumb` | **`8ea18bed` residuals sweep** (17→6 stubs): two routing-loop guards (`route.c:649` owner==source, `:675` via==source) — both ERR/WARN-logged in C, both absent here since chunk-7. The C does them inline in a 90-LOC `route_ipv4` because everything is one function; our split (pure `route()` returns `RouteResult`, impure dispatch arm does the SPTPS plumbing) put the cut between the C's checks and where `via_nid`/`from` are computed. Dark in 2-node tests (via never == from); would fire under stale-routes-during-DEL_EDGE-race or overlapping subnets. FRAG_NEEDED v4 (`:685-696`) + ICMP6_PACKET_TOO_BIG v6 (`:779-784`); floors 590/1294 (RFC 791/8200 minimums + eth) so we never claim MTU < 576; required hoisting `via_mtu` out of the OPTION_CLAMP_MSS scope. `fragment_ipv4_packet` (`:614-681`) → NOT-PORTING (modern OS sets DF). maxoutbufsize plumb (RED was `usize::MAX` → no-drop). 8 NOT-PORTING re-tags (overwrite-mac, relay-ttl-src ×5, relay-ndp-ttl). **`8b6c3b09` `seal_into`** (69.5%→76.6% of C, +264 Mbps): `send_record_priv` was 7.62% self-time — three body-sized memcpys hiding under inlined `Vec::extend_from_slice` (build pt scratch → seal copies pt into fresh out → wire.extend(sealed)). C does `alloca` + ONE memcpy + `chacha_poly1305_encrypt(.., buffer+4, .., buffer+4, ..)` in-place (`sptps.c:125`). `ChaPoly::seal_into` matches that shape: appends type+body to caller's already-headered Vec, encrypts in-place over `[encrypt_from..]`, appends tag. `pt.zeroize()` dropped (was wiping a scratch copy of an IP packet that's already in the kernel TUN buffer). 3 allocs → 1, 3 copies → 1. **`50800c0d` regression fix** for an agent transcription error in `66bea146`: the new `:109` tunnelserver gate body had `forward_request`; C `:109-113` is just log+return (only `:116` strictsubnets forwards — "I don't add it but maybe my peers care"; tunnelserver means "unauthorized, period"). Spurious forward made `three_daemon_tunnelserver` race against alice's connect ordering: spawn order is mid→bob→alice; if bob ACKs while alice is still connecting, forward iterates an empty active-conn set → noop → pass. Three full-suite runs won the race before one lost it under parallel load. Second-order: the gates early-return before `subnets.add`, so a tunnelserver hub now C-correctly requires `Subnet=` preloaded in `hosts/PEER` (`:93` lookup-first noops on those; reaching `:109` means the subnet isn't on disk). The test predated that requirement; mid now appends `Subnet=` to its `hosts/{alice,bob}`. |
| **6 — perf to 95%** | ✅ 3 commits | `tincd: port choose_initial_maxmtu (52% → 110-122% of C)` | **The bottleneck wasn't the syscall path — it was a bogus ICMP Frag Needed.** `perf trace -s` syscall counts: Rust-alice did 310k `sendto` for 261 Mbps; C-alice did 206k for 479 Mbps — **3× smaller payload per packet** (~524 vs ~1453 bytes). Same per-call latency (0.004ms both); we weren't slower at `sendto`, we were doing it 3× more for the same bytes. Root cause: `route.c:685`'s frag-needed check reads `via->mtu`, which is 0 until `try_fix_mtu` fires (`minmtu>=maxmtu`). C ported `choose_initial_maxmtu` (`:1249`, getsockopt IP_MTU → probe at exact value); first probe confirms, converges in ~1 RTT. We didn't (`NOT-PORTING` comment said "just an optimization" — **wrong**); we walk the ~10-probe ladder at 333ms each = ~3.3s during which `MAX(0,590)` claims MTU 576 to any TCP flow that asks. Kernel caches per-dst for 10 minutes; iperf3's TCP shrinks MSS to 536 and never recovers. C `#undef IP_MTU` would have the same bug — the convergence speed isn't optional. **Fix is two lines that compose**: port `choose_initial_maxmtu` (1-RTT convergence like C), AND gate the frag check on `via_mtu != 0` (don't claim a path MTU before we've measured one — correct regardless of convergence speed). **`recvmmsg` was a side quest**: the original ask. Ported (`net_packet.c:1845-1895`); recv syscalls drop 64→~5 per epoll wake; `perf trace` shows parity with C (Rust-bob 4.67% vs C-bob 4.92% in `__recvmmsg`). Real but small — bob was never the bottleneck (Rust↔C ≈ Rust↔Rust consistently, so alice limits). **Profiling infra fix was prerequisite**: release profile had no debuginfo + no frame pointers; `perf -g` couldn't unwind (`Daemon::run` showed 12% cumulative not 99%); sampling overhead hit Rust 2.5× harder than C, making perf data misleading AND perturbing throughput unequally. Added `[profile.profiling]` (inherits release + `debug=true`) and `force-frame-pointers=yes` to `.cargo/config.toml`. `PerfTrace` (RAII `perf trace -s -p`, gated `TINCD_TRACE=1`) gave the syscall counts that broke this open. n=4 runs: 110.0%, 110.6%, 118.8%, 122.1% (median ~115%). Gate passes. STUBs `chunk-11-perf` recvmmsg → 0. |
| **defer / drop** | | | `multicast_device.c` (224 — niche), `vde_device.c` (137 — nicher), legacy protocol (~400 LOC behind `DISABLE_LEGACY`). LZO/LZ4/zlib all ported (chunk 9+11). `proxy.c` ported+wired (chunk 10+11+). `autoconnect.c` ported+wired (chunk 11). |

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

**Key principle:** `tinc-proto`, `tinc-sptps`, `tinc-graph` are
zero-syscall pure libraries — exhaustively fuzzable and
property-testable without spinning up sockets.

---

## What landed (per-crate)

The original plan had Phase 0-5 milestones; in practice everything
below shipped leaf-first with the daemon assembled last (see the
Status chunk-table at top). Per-crate findings here are the
wire-adjacent ones — anything that affects interop. Full reasoning
lives in source-file doc-comments.

### KAT generators + `tinc-ffi`

`kat/gen_kat.c` (344 LOC) links the crypto C sources directly via
the header-guard suppression trick (`-DTINC_SYSTEM_H ...` makes real
headers no-op; force-include a 50-line shim for `xzalloc`/`xzfree`/
`mem_eq`). Breaks loudly at compile time if upstream renames a
guard. `nix build .#kat-vectors` reproduces `vectors.json`
byte-identically. Same shape for `nix build .#kat-graph`.

`tinc-ffi` wraps **only** `sptps.c` + crypto deps via `cc::Build`
(no bindgen). `csrc/shim.c` provides deterministic `randomize()`
(ChaCha20 keystream, per-test seed). Safe wrapper with lifetime `'k`
tying session to keys (`sptps_t` borrows the `ecdsa_t*`). 6 tests
incl. byte-by-byte dribble feed and re-KEX. The protocol handlers
(`protocol_*.c`) are deliberately NOT wrapped — they `sscanf` and
immediately mutate global splay trees; no parse seam.

**Wire-traffic corpus never built** — superseded by
`tests/crossimpl.rs` (S4), which found wire bugs (UDP-label NUL,
HKDF input) an `LD_PRELOAD` `send_request` replay couldn't have.

### `tinc-crypto` — five bespoke primitives

~1000 LOC, `#![forbid(unsafe_code)]`. All KAT-locked. Doc-comments
in each module are authoritative; key constraints:

- **chapoly** — `ChaCha20Legacy` + `Poly1305::compute_unpadded`.
  Block-0 keystream is the Poly key, then `seek(64)`.
- **ecdh** — `key_exchange.c` does NOT validate the Edwards point
  (raw `fe_frombytes`, mask bit 255, blind birational map). dalek's
  `decompress()` validates and would reject inputs the C accepts.
  Vendored `fe` module: 5×51-bit limbs, ref10 inversion. ~180 LOC.
- **prf** — TLS 1.0 PRF over HMAC-SHA512. `A(0)=zeros` quirk.
  Mirrors C's `[A(i)|seed]` in-place overwrite to get it right.
- **sign** — RFC 8032 standard. `hazmat::ExpandedSecretKey` +
  `raw_sign::<Sha512>`. Uses `verify`, NOT `verify_strict` — strict
  rejects malleable sigs that `verify.c` accepts.
- **b64** — LSB-first packing (`triplet = b[0]|b[1]<<8|b[2]<<16`,
  emit low 6 first). NOT RFC 4648 — different output strings, not
  just decode tables. `tinc_b64([0x48]) == "IB"`, RFC says `"SA"`.
  Hand-rolled both directions; no `base64` crate config produces
  this.

### `tinc-sptps`

Sans-I/O state machine. `start`/`receive`/`send_record` map to C
but **return** bytes instead of invoking callbacks.
`byte_identical_wire_output` is the strongest test: same RNG seed →
same wire bytes. Ed25519 accepts any valid sig over the right
message; byte-identity proves we *built* the right message.

State-machine subtleties caught by byte-identity (not by interop):

- **Re-KEX: responder's SIG and ACK go out under the OLD
  `outcipher`.** `receive_sig` does `send_sig()` → `send_ack()` →
  *then* `chacha_poly1305_set_key(new)`. The natural "set key, then
  send" structure is wrong. `rust_vs_c_rekey` is the test.
- **`outstate` (bool) vs `outcipher` (ctx*) are separate in C**,
  collapsed into `Option<ChaPoly>` in Rust loses one bit during
  re-KEX. `receive_sig` returns `was_rekey: bool` to thread it.
- **Stream-mode `sptps_receive_data` processes ONE record per
  call** — no inner loop. Daemon must loop until `consumed == 0`.

⏸️ `cargo-fuzz` on `Sptps::receive` — replay window + length checks
are where the C has had CVEs.

### `tinc-proto`

~2400 LOC. 41 unit tests (KAT strings transcribed from C
`printf`/`sscanf` format strings) + 11 proptests. `nom` was wrong:
23 sscanf call sites, all `%d`/`%x`/`%s` over space-separated
tokens — a 60-LOC tokenizer covers them all.

- **`AddrStr` is opaque.** `str2sockaddr` has an `AF_UNKNOWN`
  escape that stuffs unparseable input verbatim and round-trips it.
  At the parse layer, address fields are arbitrary whitespace-free
  tokens; `IpAddr::parse` would reject inputs the C accepts and
  forwards. Resolution at `connect()` time, not parse time.
- **Optional trailing fields are atomic pairs.** `add_edge_h`
  accepts `count == 6 || == 8`, never 7. `Option<(_, _)>`.
- **`REQ_KEY` is two messages stapled.** Base `sscanf` + extension
  re-scan. `Option<ReqKeyExt>`; `reqno` stays raw `i32` because
  unknown sub-types are not parse errors (C `default:` logs+continues).
- **MAC tried before v6 in `str2net`** — `1:2:3:4:5:6` is valid for
  both. `mac_shadows_v6` pins the order.
- `protocol_auth.c` deferred to daemon: `id_h` parse + connection-
  state mutation are one `sscanf`-then-if-chain with no cut point.

### `tinc-graph`

~540 LOC + 600 LOC KAT generator (8 hand-built + 10 random cases).
Generator includes real `splay_tree.c`/`list.c` and copies
`mst_kruskal`/`sssp_bfs` bodies verbatim — divergence is a build
break or KAT diff. Arena: `Vec<Node>`, `Vec<Edge>`, typed handles.

- **Indirect→direct upgrade overwrites `distance` but not
  `nexthop`** (`graph.c:180-191`). A node first reached indirectly
  at d=1, then upgraded direct at d=3, ends up `distance=3,
  weighted_distance=<from d=1 path>`. Internally inconsistent —
  but `via` is set unconditionally on revisit, and that's what
  matters. KAT `diamond_indirect` + dedicated trip-wire.
- **Iteration order is part of the contract.** Per-node edges
  `splay_each` by `to->name`; tie-breaks go to alphabetically-
  earlier neighbor. We sort per-node `Vec` on insert.
- **Kruskal-without-union-find rewinds.** Progress-after-skip
  resets iterator to head. KAT `mst_rewind`.
- **One-way edges skipped** (`!e->reverse → continue`). Transient
  between two halves of `ADD_EDGE` pair.
- `sssp` returns a side table, not in-place mutation — borrowck +
  daemon wants old-vs-new diff for `check_reachability`.

### `tinc-conf`

~740 LOC parse + ~430 LOC PEM. PEM body is `b64encode_tinc`
(LSB-first, KAT-locked); only framing tested here. Splay tree →
`Vec` + stable sort (`O(n)` lookup; configs are tens of entries).

- **`config_compare` sorts by `line` BEFORE `file`.** 4-tuple:
  `strcasecmp(var)` → cmdline-first → **`line`** → `strcmp(file)`.
  `conf.d/a.conf:5` sorts after `conf.d/b.conf:3`. This is the
  iteration order for `Subnet`/`ConnectTo` (multi-valued), so it's
  protocol-adjacent. `lookup_line_before_file` pins it.
- **The PEM stripper in `read_config_file` is what makes
  `hosts/foo` work.** Same file holds `Address =` lines AND the key
  armor; parser steps over `BEGIN..END`. `read_pem` reads the same
  file a second time, ignores everything before `BEGIN`. Two passes,
  two lenses.
- `names.c` LOCALSTATEDIR fallback: 3-row truth table; bottom row
  (neither `/var/run/X.pid` nor `confbase/pid` exists → return
  `/var/run` anyway) is the surprise. `unix_socket()` from
  `pidfile()` by string surgery: `> 4` not `>= 4`, case-sensitive.

### `tinc-tools` — `sptps_test`, `sptps_keypair`, `tinc` CLI

`sptps_test`/`sptps_keypair` are `#![forbid(unsafe_code)]`.
`self_roundtrip.rs` 2×2 matrix (each role C or Rust, gated on
`TINC_C_SPTPS_TEST`); stronger than `vs_c.rs` — independent entropy
catches "wire format right but verification wrong". Findings:
dropping a child's stderr pipe end = `SIGPIPE` (bites `script.c`
port too); `Stdin::lock().read()` buffers (use `nix::unistd::read`).

`tinc` CLI: 34/39 commands (`comm -23` vs `tincctl.c:2995-3050`).
5 unported = 2 daemon-gated + 1 daemon-only-RPC + 2 legacy-RSA.
`tincctl.c` is ~3.4k LOC split clean: ~2k filesystem (`init`/
`generate-keys`/`export`/`edit`/`fsck`/`sign`), ~1k RPC (`dump`/
`top`/`pcap`/`log`/`reload`). Hand-rolled `match argv[1]` — clap is
10× deps for ~15 subcommands. Kept the C control protocol (pidfile
`0600` cookie; ssh-agent model). `invitation.c` 1484→~1010 LOC
after dropping HTTP probe / `ifconfig.c` / tty prompts; ifconfig
keywords recognized, placeholder `tinc-up`, no per-platform shell
gen (−300 LOC). Per-command findings in `cmd/*.rs` source docs.

**TODO: hermetic `checks.cross-impl`.** Needs
`rustPlatform.buildRustPackage` to vendor deps; CI uses devshell.

### `tinc-device`

| Platform | C source | Status |
|---|---|---|
| Linux | `linux/device.c` | ✅ `linux.rs` — hand-rolled `libc::ioctl` (nix macro generates `*const`, `TUNSETIFF` writes back). +10 offset trick + testable seam. |
| Dummy | `dummy_device.c` | ✅ trivial |
| `fd` (Android) | `fd_device.c` | ✅ `fd.rs` — the +14 cousin. `pipe()`-testable. nix `recvmsg`+`SCM_RIGHTS`. |
| `raw` (`PF_PACKET`) | `raw_socket_device.c` | ✅ `raw.rs` — the +0. `if_nametoindex` substitutes `SIOCGIFINDEX`. |
| BSD/macOS | `bsd/device.c` | ✅ `bsd.rs` — `cfg(unix)` MODULE, `cfg(bsd)` `open()`: read/write logic tested on Linux via fakes. `to_af_prefix` lives here (`AF_INET6` platform-varying). |
| Windows | `windows/device.c` | `wintun` crate — drop TAP-Windows |
| Multicast | `multicast_device.c` | defer (niche) |
| UML/VDE | `*_device.c` | drop |

Unsafe-shim decision tree (full reasoning in source docs): nix
doesn't wrap → hand-roll; higher-level POSIX exists → substitute;
encoding lies (`TUNSETIFF`) → hand-roll; signal-context → hand-roll
("probably safe" isn't good enough). Don't pattern-match the
neighboring shim. `cfg` gates the smallest platform-varying thing.
RFC values hoist to `ether.rs`; ABI values reference `libc::` at
use site. `read_fd`/`write_fd` stay duplicated (6×8 LOC) — buys six
small `#[allow(unsafe_code)]` scopes vs one crate-wide.

`Device::write` takes `&mut [u8]` — `linux.rs` zeroes `buf[10..12]`,
`bsd.rs` clobbers `buf[10..14]`. C `setup`/`close` = ctor + `Drop`.

`tinc-net` as a separate crate didn't happen — socket setup, proxy,
addrcache, autoconnect all landed as `tincd` modules; no seam
justified a crate boundary. `etherparse` evaluated, dropped:
`packet.rs` is `#[repr(C, packed)]` for build AND parse; once you've
hand-rolled the structs the parse path is `transmute` away.

### `tinc-event` + `tincd`

mio + manual poll, single-threaded. tokio rejected: C's pervasive
shared mutable state (`node_tree`, `connection_list` globals) fights
async borrow rules. One `&mut Daemon` into every handler mirrors the
C globals without `static mut`.

**Dispatch enum, not callbacks.** Can't store `fn(&mut Daemon)`
inside `Daemon`. The cb set is closed (6 io + 7 timer); encode as
`enum IoWhat`/`enum TimerWhat`, loop body is a `match`.
`BTreeMap<(Instant, u64)>` not `BinaryHeap` — all 7 timers re-arm;
heap = tombstone churn. **Deliberate semantic difference**: C
auto-deletes if cb didn't re-arm; we make re-arm explicit. Self-pipe
hand-rolled (`signal-hook` was +3 deps for 90 LOC).
`sigaction(SA_RESTART)`, `pipe2(O_CLOEXEC)`.

SIGHUP reload doesn't rebuild from scratch — walks live trees,
marks `expires=1`, re-reads, sweeps. The C `expires=1` flag is a
splay-tree workaround; ours is `BTreeSet::difference`.

**Legacy RSA + AES-CBC**: not ported. Gate behind `--features
legacy`, keep OpenSSL-via-FFI permanently for RSA — reimplementing
20-year-old PKCS#1 padding to be byte-compatible is a footgun.

### Module mapping (`85236bac`)

~9200 C LOC remaining of the daemon's 12422 (`src_tincd` in `meson.build`). At post-cleanup ratios (1.5× code-only, ~5× file-LOC with table-driven tests), figure ~45k file-LOC remaining.

| C source | LOC | ported | what's done / what's left |
|---|---|---|---|
| `event.c` + `linux/event.c` + `signal.c` | 476 | ✅ | `tinc-event`. `bsd/event.c`/`event_select.c` are mio's job. |
| `dummy_device.c` + `linux/device.c` + `fd_device.c` + `raw_socket_device.c` | ~550 | ✅ | `tinc-device`. `bsd/device.c` open() is a cfg-gated stub (read/write paths tested via pipe fakes). |
| `buffer.c` | 110 | ✅ | `tincd::conn::LineBuf`. The range-invalidation bug from chunk 2 is the load-bearing finding. |
| `connection.c` | 175 | ✅ | `tincd::conn::Connection` + `daemon::dump_connections` inline. `status_value()` builds the GCC-LSB-first bitfield int (only bits we model; rest are 0 anyway at this stage). |
| `meta.c` | 322 | ~85% | `feed`/`feed_sptps` + `dispatch_sptps_outputs`. `Record` arm → `record_body` strip + `check_gate`; `HandshakeDone` arm → `send_ack`. `send()` grew the `sptps_send_record` branch. Left: `tcplen` arm (`:143-152`, `tcppacket_h` body delivery, chunk 8). |
| `protocol.c` | 245 | ✅ | `check_gate` (dispatch) + `seen_request` cache + `age_past_requests` timer + `forward_request` (collect-then-send, slotmap borrow). |
| `protocol_auth.c` | 1066 | ~75% | `id_h` peer+control+invitation (chunk 4a, 4b, 10), `send_ack`/`ack_h`, `send_everything` + tunnelserver gates (chunk 5, 9c). `?` branch (`:340-373`): `IdOk::Invitation` variant + `dispatch_invitation_outputs` (chunk 10). `receive_invitation_sptps`/`finalize_invitation` (`:119-310`): `invitation_serve.rs` hoist. Left: legacy (~400, chunk-never). |
| `keys.c` | 334 | ✅ | `tincd::keys`. The `& ~0100700u` perm-check bug ported as C-is-WRONG #7. |
| `control.c` | 241 | ~50% | 6/12 `REQ_*` arms (STOP, RELOAD, DUMP_{NODES,EDGES,SUBNETS,CONNECTIONS}). CLI client side speaks the full protocol; daemon side is `match` arms. `init_control` landed in chunk 2. Missing arms fall through to `REQ_INVALID` (matches C's default). |
| `pidfile.c` | tiny | ✅ | `Pidfile::read` (CLI side) + write (daemon, chunk 2). |
| `net_socket.c` | 884 | ~80% | `tincd::listen` (listeners + tarpit) + `tincd::outgoing` (`do_outgoing_connection`, `try_outgoing_connections`, `retry_outgoing`, `finish_connecting`, the `handle_meta_io` connecting probe). All proxy modes wired (`daemon.rs:1191` comment is stale). Left: sockopts (`IP_MTU_DISCOVER`, `SO_RCVBUF`, `SO_BINDTODEVICE`, `SO_MARK`), `bind_reusing_port`. |
| `net_setup.c` | 1336 | ~60% | `setup_myself` skeleton + `setup_myself_reloadable` (chunk 10), `load_all_nodes` (chunk 11), `device_enable`/`device_disable` script hooks (`daemon.rs:1667,1893`). Left: `bind_reusing_port`, `add_listen_address` config-walk, the missing config-key parses. |
| `tincd.c` | 735 | ~35% | `main.rs` argv + signal install + SIGHUP→reload (chunk 10). Left: `parse_options` (~160 LOC), `drop_privs`, `umbilical`, `ProcessPriority`, `mlock`, `daemon()`. |
| `node.c` | 232 | ~95% | Three-way model (chunk 5), `NodeId6` UDP id (chunk 7), per-tunnel SPTPS (chunk 7), `dump_nodes` (`22a5ff82`). Left: `dump_traffic` only. |
| `edge.c` | 138 | ✅ | `tinc-graph::add_edge`/`del_edge`/`lookup_edge` (free-list slab) + `on_ack`'s edge-build + `dump_edges` (`22a5ff82`). |
| `subnet.c` | 409 | ~95% | `SubnetTree` + `dump_subnets` + `subnet_update` script firing (chunk 8). Hash cache deleted-by-design. No structural residue. |
| `protocol_edge.c` + `protocol_subnet.c` | 583 | ✅ | All handlers + `forward_request` + `contradicting_*` + tunnelserver/strictsubnets gates (chunk 9c). The chunk-9b idempotence-addr-compare fix (`:144`). |
| `graph.c` | 327 | ✅ | `tinc-graph::sssp`/`mst` + `graph_glue::diff_reachability`/`run_graph`. The sssp→diff→mst order pinned. host-up/down + subnet-up/down script firing (chunk 8). |
| `script.c` | 253 | ✅ | `script.rs` (`984bdfdc`). `Command::envs` not `putenv`; ENOEXEC behavior diff doc'd. |
| `protocol_key.c` | 648 | ~80% | `send_req_key`/`req_key_ext_h`/`ans_key_h` SPTPS + compression-level negotiation (chunk 9a). UDP relay receive (chunk 9b). Reflexive-UDP-addr append/consume (`67e0dc22`). Left: `REQ_PUBKEY`/`ANS_PUBKEY` (we require `hosts/NAME` instead), legacy (chunk-never). |
| `protocol_misc.c` | 376 | ~95% | PING/PONG (chunk 8). UDP_INFO/MTU_INFO gates+handlers wired (`udp_info.rs`, chunk 11). The 7 send-gates as `should_send_* → bool`, receive as `→ enum Action`. PACKET parse-and-swallow (`463b9987` — cross-impl found we crashed on it). PACKET 17 routing (`bc62b722`). Left: nothing structural. |
| `net_packet.c` | 1938 | ~92% | **The hot path.** Chunk 7: send/recv core. Chunk 9: PMTU/compression/`try_tx` chain. `send_sptps_data` relay decision tree (`:965-1056`). All three chunk-12 leaves WIRED: `choose_local_address`/`adapt_socket` (`67e0dc22`), `broadcast_packet` target selection (`2bbd51b0`), `receive_tcppacket_sptps` ladder (`300a8e96` — the architectural-trap fix). Send/receive offset switch-aware (`:696-700`, `:1108`). PACKET 17 send+recv (`bc62b722` — the `:684` `n->connection` gate, **C-is-WRONG #11** at `:708-726`). `choose_initial_maxmtu` (`:1249-1340`, `05ba1f82` — was THE throughput bug). `recvmmsg` batching (`:1845-1895`, `0f120b11`). `overwrite_mac` (`:1557-1562`, `31ea5c79`). Left: `try_harder` (chunk-never), legacy crypto (`:800-960`, chunk-never). |
| `route.c` | 1176 | ~100% | Chunk 7: `route_ipv4`. Chunk 9: v6/ICMP/MSS/ARP/NDP/TTL. **C-is-WRONG #8** (`:344`). `route_mac` (`52f6f348`) + `learn_mac`/`age_subnets` (`bc9f223b`) WIRED in `2bbd51b0`. Full RMODE_SWITCH dispatch (`:1159`). `route_broadcast` (`:559-565`). FMODE_KERNEL (`:1135-1138`). FRAG_NEEDED v4/v6 + the two routing-loop guards (`:649,675`/`:745,770`) wired (`8ea18bed`). All three former NOT-PORTINGs ported: `fragment_ipv4_packet` (`:614-681`, `8b29ca5b`), TIME_EXCEEDED `getsockname` (`:148-169`, `b5ef3f86`), `overwrite_mac` snatching (`:830,972`, `31ea5c79`). |
| `net.c` | 527 | ~85% | `timeout_handler` ping sweep + laptop-suspend (chunk 8), `periodic_handler` storm-detect (chunk 8), `reload_configuration` SIGHUP mark-sweep (chunk 10 — `reload.rs::diff_subnets/conns_to_terminate`). Left: `purge`/`retry` control-socket commands. The mark-sweep is `BTreeSet::difference`; the C's `expires=1` flag is a splay-tree workaround. |
| `address_cache.c` | 284 | ~85% | `addrcache.rs`. Text-format (`SocketAddr::Display`) not C struct dump. next_addr/reset/add_recent/save. Integrated with `Outgoing` (per-outgoing not per-node — the C hangs it on `node_t` but only outgoings read it). Left: lazy hostname resolve at next_addr time (`:170` `str2addrinfo`); current `try_outgoing_connections` does blocking `to_socket_addrs()` at setup. |
| `route.c` `inet_checksum` + headers | ~100 | ✅ | `packet.rs`. `#[repr(C, packed)]` Ipv4Hdr/Ip6Hdr/IcmpHdr/Icmp6Hdr/EtherArp + KAT-locked checksum (native-endian `memcpy` load, RFC 1071 §2(B)). Ready for chunk-9 builders. |
| `process.c` | 243 | 0 | chunk 8. `daemon()`, setuid, scripts. Ship-#1's SIGPIPE-from-dropped-stderr finding applies to script spawn. |
| `proxy.c` | 285 | ✅ | `socks.rs` (`d988b79f`) + wired (`e841d05e`). HTTP CONNECT (`af26db41`). **C-is-WRONG #9** (`:201` size_t→u8). **C-is-WRONG #10** (`protocol.c:148-161` header lines kill the conn — dormant; `proxy.py` sends no headers). `tcplen` multiplexed: pre-SPTPS proxy reply (`read_n`) vs post-SPTPS PACKET (record). All three modes have in-process integration tests. STRICTER: bracket IPv6 in CONNECT authority (C doesn't, never tested). |
| `multicast_device.c` | 224 | defer | niche backend. |
| `autoconnect.c` | 197 | ✅ | `autoconnect.rs` (`a68dbdcb`) + wired in `7ba8bc2d`. `decide() → AutoAction`. The all-node prng IS the backoff. `autoconnect_converges_to_three` (S2, ~15s): 4 daemons, zero ConnectTo, three Address-bearing hosts/ — periodic tick dials one per 5s. |
| `splay_tree.c` + `list.c` | ~800 | drop | std collections. |
| `getopt*.c` | ~1k | drop | clap. |

### Non-goals: specific functions inside ported modules

Distinct from the defer/drop row above (whole modules). These are
functions inside otherwise-ported files, re-tagged NOT-PORTING in
`66bea146` and the residuals sweep. **Four of five were later
ported** — the table is kept as a record of the decisions and their
fates because the IP_MTU one was a load-bearing mistake.

| Item | C source | Gate | Why we said "not" | Ported in |
|---|---|---|---|---|
| `IP_MTU` getsockopt | `net_packet.c:1249-1340` | none (always falls back) | "PMTU converges from MTU=1518 anyway; saves ~2 probes" — **WRONG**. Convergence speed was load-bearing: during the ~3.3s slow-converge window, `route.c:685` fires Frag-Needed at MTU 576, kernel caches per-dst for 10 minutes, TCP MSS → 536, throughput halves. See Rust-is-WRONG #5. | `05ba1f82` |
| `lzo1x_999_compress` | level 11 | minilzo doesn't include it | decompress works; compress falls back to raw | — (only one left) |
| `overwrite_mac` | `net_packet.c:1557-1562` | `Mode=router DeviceType=tap` | nobody uses that config; we don't parse the knob | `31ea5c79` |
| TIME_EXCEEDED `getsockname` | `route.c:148-169` | `DecrementTTL=yes` + relay hop | traceroute IP wrong; nothing else cares | `b5ef3f86` |
| `fragment_ipv4_packet` | `route.c:614-681` | DF clear + `>via_mtu` + relay | modern OS sets DF (PMTUD); UDP-no-DF is the gap | `8b29ca5b` |

### Hot-path concerns (`net_packet.c`)

**Gate passes (median ~115% of C, n=4).** See the Phase-6
"perf to 95%" row for the full chain. The hot path was never slow
— it was running 3× too often because of a NOT-PORTING decision
gone wrong (`choose_initial_maxmtu`; Rust-is-WRONG #5 in
ISSUES.md). The `seal_into` work (`8b6c3b09`, 69.5%→76.6%),
zero-alloc receive (`e49b5af6`), and recvmmsg batching (`0f120b11`)
all landed and were all real improvements, but none was THE
bottleneck.

---

## Coverage gaps (audited at `957f0ec5`)

Function-by-function audit of every C file against `// C file.c:NNN`
ref tags + STUB/TODO/DEFERRED markers. Full 718-line analysis at
`bcc5c3e3`; this section is the index. **31 NOT-PORTED items: 4
HIGH, 16 MEDIUM, 11 LOW.** The four HIGH findings are all IP_MTU-
class: absence causes wrong behavior elsewhere, silently. Port
these next.

The %'s in the module-mapping table above were updated in-place
from this audit (`route.c` 97→~99%, `net_packet.c` 90→~95%,
`control.c` 25→~50%, `net_socket.c` 65→~80%, `net_setup.c` 50→~60%,
`node.c`/`subnet.c` 85→~95%, `tincd.c` 50→~35%).

### HIGH — load-bearing

**`IP_MTU_DISCOVER` not set on UDP socket** (`net_socket.c:349-378`).
The inverse of the IP_MTU lesson: `05ba1f82` made
`choose_initial_maxmtu` *read* the kernel's PMTU cache, but without
`IP_PMTUDISC_DO` the kernel never *populates* that cache. Linux
default is `IP_PMTUDISC_WANT` — DF set only if the route already
has PMTU info. Probes fragment at L3, arrive successfully, `minmtu`
walks up to 1518, `try_fix_mtu` locks it in, the first real >MTU
packet fragments instead of triggering `EMSGSIZE → reduce_mtu` at
`daemon/net.rs:1810`. The whole `pmtu.rs` machinery is decorative.
~15 LOC: `setsockopt` after bind in `listen.rs::open_udp` (nix has
`sockopt::IpMtuDiscover`).

**`DEFAULT_BROADCAST_SUBNETS` structurally absent**
(`net_setup.c:485-505` + `route.c:644-646,738-741`). C inserts
`ff:ff:ff:ff:ff:ff`, `255.255.255.255`, `224.0.0.0/4`, `ff00::/8`
with `owner = NULL`; route matches → `route_broadcast`. Our
`SubnetEntry.owner: String` (not `Option<String>`) — the model
can't represent it. mDNS/DHCP/NDP packets from the kernel hit
`lookup_ipv4` → `None` → `Unreachable{ICMP_NET_UNKNOWN}` → daemon
writes ICMP-unreachable back to its own kernel. Silent (mDNS
doesn't surface ICMP). `Mode = switch` unaffected (floods on miss).
~40 LOC: `Option<String>` or sentinel `""` + 4 hard-coded inserts
+ `BroadcastSubnet` config-walk.

**`Forwarding = off` parsed-but-ignored** (`route.c:658-660,
753-755,1052-1054`). `daemon.rs:1244` parses into
`ForwardingMode::Off`; nothing reads it (`daemon/net.rs:585` checks
`::Kernel` only). The "I'm an endpoint, not a relay" knob silently
no-ops. An operator who set it to prevent transit traffic gets
transit traffic. `gossip.rs:171` checks `== Internal` so `Off` also
changes SPTPS_PACKET relay as a side effect of the `!= Internal`
arm. ~20 LOC: three `if` clauses in `dispatch_route_result`, mirror
the `directonly` gate at `:895` (same ICMP codes).

**`KeyExpire` timer never armed** (`net_setup.c:144-160` →
`protocol_key.c:38-62`). `TimerWhat::KeyExpire` exists
(`daemon.rs:123`); the handler is `unreachable!("timer not armed
yet")`. `Sptps::force_kex` exists (`state.rs:663`); no daemon code
calls it. SPTPS sessions live forever on one key. Receive side
handles inbound `KEY_CHANGED` from C peers (`metaconn.rs:659-684`),
but we never *initiate*. Year-uptime daemon = year of ciphertext
under one key. ~30 LOC: arm the timer in `setup`, walk `tunnels`,
call `force_kex`, dispatch the `Output::Send`.

### MEDIUM / LOW — table

| Item | C source | What we do | Effort | Pri |
|---|---|---|---|---|
| `detach()` | `process.c:200-243` | foreground only | ~40 LOC, or doc "systemd Type=simple" | M |
| `drop_privs` (`-U`/`-R`) | `tincd.c:373-428` | unknown-arg error (loud) | ~60 LOC | M |
| argv flags (`-o`, `-n`, `-d`, `-L`, `-s`, `--logfile`) | `tincd.c:174-331` | 5/11 flags parsed | ~30 LOC for `-o`+`-n` | M / L |
| `umbilical` ready-signal | `tincd.c:549-568,702-709` | `tinc start` would block forever | ~25 LOC | M |
| `REQ_{PURGE,RETRY,DISCONNECT,DUMP_TRAFFIC,PCAP,LOG}` | `control.c:45-148` | fall through to `REQ_INVALID` (matches C default) | ~60+15+40+50 LOC | M (`DUMP_TRAFFIC`, `DISCONNECT`) / L |
| `purge` (node GC) | `net.c:50-93` | nodes accumulate; `O(nodes ever seen)` | ~40 LOC | M |
| `retry` (zero backoffs NOW) | `net.c:460-484` | SIGALRM handler is no-op; wait out 900s backoff | ~20 LOC | M |
| `get_known_addresses` edge-walk | `address_cache.c:31-65,126-148` | cache→config only; skip gossip-learned tier | ~25 LOC | M |
| Lazy `getaddrinfo` + blocking-DNS | `address_cache.c:157-199` | `to_socket_addrs()` once at OPEN; **blocks event loop** | ~50 LOC; blocking is harder | M / L |
| Per-host `IndirectData`/`TCPOnly`/`Weight` in `send_ack` | `protocol_auth.c:844-865` | STUBBED; inherit globals | ~30 LOC | M |
| Global `IndirectData`/`TCPOnly`/`PMTUDiscovery`/`ClampMSS` | `net_setup.c:383-400` | hardcoded C defaults; `lookup` never called | ~15 LOC | M |
| `bind_reusing_port` (`Port=0` → same TCP/UDP port) | `net_setup.c:577-635` | TCP/UDP get different kernel ports | ~20 LOC | M |
| `add_listen_address` config-walk (`BindToAddress`) | `net_setup.c:637-741` | one listener pair on `0.0.0.0` | ~50 LOC | M |
| SIGPIPE / `MSG_NOSIGNAL` | `process.c:204` / `conn.rs:607` | **Rust runtime sets SIG_IGN before main()**; defense-in-depth only | 1 LOC | L |
| `priorityinheritance` (`IP_TOS` copy) | `route.c:668,763,1063` + `net_packet.c:920-946` | DEFERRED; outer packets get default TOS | ~40 LOC | L |
| `dump_traffic` (feeds `tinc top`) | `node.c:226-231` | counters don't exist on `TunnelState` | ~30 LOC | L |
| `send_pcap` (`tinc pcap` backend) | `route.c:1109-1128` | DEFERRED; no `pcap` status bit | ~30 LOC | L |
| `SO_BINDTODEVICE` (`BindToInterface`) | `net_socket.c:111-142` | Deferred; key not parsed | ~15 LOC | L |
| `SO_RCVBUF`/`SO_SNDBUF` (`UDP{Rcv,Snd}Buf`) | `net_socket.c:264-290` | kernel default ~200KB vs C's 1MB | ~15 LOC | L |
| `SO_MARK` (`FWMark`) | `net_socket.c:248,383` | Deferred; key not parsed | ~10 LOC | L |
| `Name = $HOST` / `$ENV` | `net_setup.c:220-233` | `$` fails `check_id` | ~15 LOC | L |
| `ProcessPriority` (`setpriority`) | `tincd.c:670-698` | nothing | ~15 LOC | L |
| `mlockall` (`-L`) | `tincd.c:600-612` | `-L` rejected as unknown | ~10 LOC | L |
| `sd_notify` watchdog | `linux/watchdog.c` | nothing | ~30 LOC (no libsystemd needed) | L |
| Misc config keys (`ScriptsInterpreter`, `ScriptsExtension`, `MaxConnectionBurst`, `ReplayWindow`, `DeviceStandby`, `UDPDiscovery*`) | `net_setup.c` various | C defaults hardcoded | ~5 LOC each | L |

**SIGPIPE downgrade**: the audit flagged this HIGH ("any peer that
half-closes mid-write kills the daemon"). Wrong — Rust's std
runtime does `signal(SIGPIPE, SIG_IGN)` in `sys::pal::unix::init`
before `main()` runs (since 1.0; `-Zon-broken-pipe` exists
*because* the default is SIG_IGN). `SelfPipe::add` calls
`sigaction()` per-signal for TERM/INT/QUIT/HUP/ALRM; doesn't touch
SIGPIPE. `send()` to closed peer → `EPIPE` → conn-terminate
(correct). `MSG_NOSIGNAL` is 1-LOC defense-in-depth for the
library-embed case.

**`REQ_CONNECT` is vestigial in C too**: `tincctl.c:1461` sends it;
`control.c` has no case for it; falls to `REQ_INVALID`. Our default
arm matching C's is correct, not a gap. The audit's "6/14" became
"6/12-that-exist".

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

## LOC accounting

> **Staleness note**: numbers measured at `d88b5cfd` (pre-comment-
> reduction). Seven commits since then dropped ~5.2k comment lines;
> `thiserror` landed (`190a4007`, discussed below as a hypothetical);
> `proto-thin` dropped 5 redundant tests; new code added (recvmmsg
> batch infra, `fragment.rs`, `choose_initial_maxmtu`). The
> logic-vs-logic 1.20× ratio is likely unchanged — the comment
> thinning touched comments not code. Raw line counts will have
> dropped ~5k since.

The naive number is alarming: `crates/**/*.rs` is 68k raw lines vs
`src/**/*.c` at 36k — nearly 2×. Every individual count below is
`tokei` code-only (comments and blanks stripped) unless stated
otherwise. The punchline is at the bottom: **at the actual
logic-vs-logic level we are at 1.20×**, not 2×. The other 0.8× is
tests the C never had, doc-comments at 4× the C density, and an
abstraction tax we pay deliberately.

Method: a small awk pass strips `#[cfg(test)] mod { … }` blocks from
every `crates/*/src/*.rs`, the result goes through `tokei`, and the C
baseline is `tokei src/` minus the directories listed under
[What to Drop](#what-to-drop) minus `#ifndef DISABLE_LEGACY` bodies.

### Top-line

| Slice | Files | Code | Comments | Notes |
|---|---:|---:|---:|---|
| **C `src/**/*.c` total** | 107 | 25,493 | 3,373 | tokei, all of `src/` |
| − crypto subdirs (chacha-poly1305, ed25519, openssl, gcrypt, nolegacy) | 30 | −4,890 | −695 | replaced by `chacha20poly1305` / `ed25519-dalek` crates |
| − vendored libc/utils (getopt×2, splay_tree, list, dropin) | 5 | −1,598 | | replaced by std / clap-is-avoided-anyway |
| − unported device backends (solaris, windows, vde, multicast) | 4 | −≈577 | | per [What to Drop](#what-to-drop) |
| − `#ifndef DISABLE_LEGACY` bodies (RSA/AES, scattered) | — | −806 | | 14 files; balanced-preprocessor count |
| **C effective port surface** | | **≈17,770** | **≈2,550** | what we actually had to rewrite |
| | | | | |
| **Rust `crates/**/*.rs` total** | 117 | 44,684 | 16,467 | tokei (`///` doc-lines counted as comments) |
| − `crates/*/tests/*.rs` (integration) | 18 | −10,362 | −2,767 | S1–S5 strata |
| − in-file `#[cfg(test)] mod tests` | 72 blocks | −12,871 | −2,514 | 19,437 raw → brace-balanced strip → tokei |
| **Rust production code** | 99 | **21,393** | **11,158** | code-vs-code: **1.20× the C** |

C's comment density on the effective surface is ≈13% (2,550 / 20,320
non-blank). Ours is **34%** (11,158 / 32,551). That's deliberate —
the `// C \`file.c:NNN\`` cross-refs are how the audits found 11
bugs — but it's also where the casual reader's "why is this so big"
impression comes from.

### Per-crate vs. C subsystem

| Rust crate | Prod code | C subsystem | C code | Ratio | Notes |
|---|---:|---|---:|---:|---|
| `tincd` | 10,559 | `net*.c`, `protocol*.c`, `route.c`, `meta.c`, `connection.c`, `node.c`, `edge.c`, `subnet*.c`, `address_cache.c`, `autoconnect.c`, `control.c`, `tincd.c`, `process.c`, `script.c`, `names.c` | 9,068 | 1.16× | minus ≈450 LOC of LEGACY ifdefs in `protocol_auth.c`/`net_setup.c` → **1.23×** |
| `tinc-tools` | 6,728 | `tincctl.c`, `fsck.c`, `info.c`, `invitation.c`, `top.c` | 4,714 | 1.43× | minus 285 LOC LEGACY (RSA fsck/genkey, RSA join) → **1.52×** — the worst crate, see §6 |
| `tinc-device` | 703 | `linux/device.c`, `bsd/device.c`, `fd_device.c`, `raw_socket_device.c`, `dummy_device.c` | ≈690 | ≈1.0× | comment density 52% (!) — every ioctl annotated |
| `tinc-sptps` | 520 | `sptps.c` | 492 | 1.06× | the cleanest port; state-machine maps 1:1 |
| `tinc-conf` | 501 | `conf.c`, `conf_net.c` | 335 | 1.50× | §6 — `ReadError` enum is +60, `vars.rs` table is +80 |
| `tinc-graph` | 530 | `graph.c` | 186 | 2.85× | misleading — see below |
| `tinc-proto` | 808 | (parsers split out from `protocol_*.c`; double-counted in `tincd` row) | — | — | wire-format only; no C analogue |
| `tinc-event` | 357 | `linux/event.c`, `bsd/event.c` | ≈280 | 1.27× | mio-on-top-of-epoll wrapper |
| `tinc-crypto` | 518 | (b64/hex/HKDF wrappers; C uses OpenSSL inline) | — | — | thin shims over `chacha20poly1305`/`hkdf` |
| `tinc-ffi` | 169 | (test-only differential bridge) | — | — | not shipped |

**`tinc-graph` 2.85× is misleading.** C `graph.c` does the BFS and the
MST and **nothing else** — node/edge storage is `splay_tree.c` (which
we excluded as "replaced by std"), and add/del/lookup live in
`node.c`+`edge.c` (counted under `tincd`'s C row). `tinc-graph` is
`Graph` struct + slab storage + accessors + `sssp` + `mst` in one
file. The honest comparison is `graph.c`+`node.c`+`edge.c` add/lookup
paths ≈ 350 LOC → 1.5×, in line with everything else.

### 1. Tests we wrote that the C never had

**23,233 code lines.** Intentional. Largest single bucket by far.

| Slice | Code | Raw |
|---|---:|---:|
| `crates/*/tests/*.rs` integration | 10,362 | 14,632 |
| `#[cfg(test)] mod tests` in 72 src files | 12,871 | 19,437 |
| **Total Rust test code** | **23,233** | **34,069** |
| C `test/integration/*.py` | — | 6,061 |
| C `test/unit/*.c` | — | 2,118 |

The C suite is 8.2k raw lines and shells out to a built binary; ours
is 34k raw lines and runs in-process. We have 4.2× the test surface
for a daemon that's ≈1.2× the size. The cross-impl harness
(`tests/crossimpl.rs`, 1,245 lines) alone caught the UDP-label NUL
byte and the PACKET dispatch bug — neither visible Rust↔Rust.

**Redundancy check (route.rs unit vs. two_daemons integration):** Not
redundant. `route.rs`'s 25 unit tests (`route_too_short`,
`route_ipv6_unknown_is_unreachable_addr`, `decrement_ttl_v4_at_1_
sends_icmp`, …) are edge-case probes against a pure function with
hand-built byte slices. `two_daemons.rs`'s 18 tests are happy-path
(`first_packet_across_tunnel`, `three_daemon_relay`). A regression in
`route()` for malformed packets would be caught by the unit test in
<1ms; `two_daemons` would never send a malformed packet. The other
direction — routing works in isolation but the dispatch glue is wrong
— is exactly what the chunk-5 idempotence-addr-compare bug was, and
only `two_daemons` caught that. **Both layers are load-bearing.**

**Possible redundancy:** `proto.rs` has `#[cfg(test)]` starting at
line 1097 (≈770 raw lines of unit tests for `parse_add_edge` /
`parse_add_subnet` / `handle_id` / etc). `tests/stop.rs` (S1, 2,285
lines) sends those same wire-lines to a real daemon. The unit tests
prove the parser; `stop.rs` proves parser + handler + state mutation.
A parser-level regression would trip both. **Candidate for thinning:**
the `proto.rs` unit tests that only assert successful parsing of
well-formed lines (≈8 of ≈20) — `stop.rs` covers those. Keep the
ones asserting *rejection* of malformed lines (`stop.rs` doesn't
fabricate garbage). **Maybe −200 lines.**

### 2. Doc-comments with C source references

**1,762 lines** of `// C \`file.c:NNN\`` cross-references. Intentional
and load-bearing — audits matched Rust against C line-by-line.
Subset of the 11,158 prod-comment total (≈16%).

Distribution: top 5 files hold 30% of all refs.

| File | C-refs | Referenced C files |
|---|---:|---|
| `daemon/net.rs` | 141 | `net_packet.c`, `net_socket.c`, `route.c` |
| `daemon/gossip.rs` | 139 | 8 files (see §6) — it's the protocol nexus |
| `daemon.rs` | 98 | `tincd.c`, `net_setup.c`, `net.c` |
| `cmd/config.rs` | 82 | `tincctl.c` |
| `cmd/fsck.rs` | 80 | `fsck.c` |

**Stale-ref check:** of 789 unique `file.c:NNN` pairs, only 13 point
past EOF and all 13 are subdirectory references written without the
dir prefix (`device.c` for `linux/device.c`, `ecdsa.c` for
`ed25519/ecdsa.c`, `pem.c` which doesn't exist — likely meant
`ed25519/ecdsa.c`'s PEM block). **Not actually stale**, just missing
path qualifiers. Could be normalized to `linux/device.c:NNN` style.
**Removable: 0.** Normalizable: 13.

**Repetitive-ref check:** only 1 single-line match arm carries an
inline `=> … // C \`:NNN\``. The rest are full-line standalone
comments above the code they annotate. No `// C :NNN` carpet-bombing.

The **other 9,400 prod-comment lines** are doc-comments explaining
*why*. Representative example: `top.rs:1-80` is an 80-line module
header explaining the C's qsort stable-sort emulation, why we don't
port it (Rust's `sort` is already stable), and the 3-layer
testability split. The C `top.c` has zero comparable header. This is
**the largest single contributor to the raw-LOC delta** (11.2k vs
2.5k) but also the cheapest to maintain (no compiler, no tests).

### 3. Pure-module + impure-dispatch split

**≈1,170 code lines.** Intentional. The seam that made the
structural-miss bugs visible.

The C `route_ipv4()` does lookup + TTL decrement + `send_packet()` in
one function. We have `route.rs::route()` returning a `RouteResult`
enum, then `daemon/net.rs::dispatch_route_result()` matching on it
and performing I/O. The enum + the match are LOC the C doesn't pay.

| Pure-leaf result enum | LOC | Dispatch site | LOC |
|---|---:|---|---:|
| `RouteResult<T>` (`route.rs:138`) | 40 | `dispatch_route_result` (`net.rs:885-1222`) | 337 |
| `DispatchResult` (`proto.rs:115`) | 31 | `dispatch_sptps_outputs` (`metaconn.rs:797-1096`) | ≈300 |
| `FeedResult` (`conn.rs:414`) | 24 | inline in `metaconn.rs` event loop | ≈40 |
| `TcpRouteDecision<'a>` (`tcp_tunnel.rs:149`) | 35 | `dispatch_tunnel_outputs` (`net.rs:1421-1460`) | 39 |
| `LearnAction` (`route_mac.rs:92`) | 25 | inline in TAP path | ≈20 |
| `UdpInfoAction` (`udp_info.rs:227`) | 23 | `dispatch_invitation_outputs` indirectly | — |
| `MtuInfoAction` (`udp_info.rs:472`) | 18 | inline | ≈15 |
| `AutoAction` (`autoconnect.rs:68`) | 18 | `periodic.rs` timer | ≈25 |
| `PmtuAction` (`pmtu.rs:69`) | 17 | inline | ≈15 |
| `TtlResult` (`route.rs:427`) | 17 | sub-dispatch inside `dispatch_route_result` | — |
| `ScriptResult` (`script.rs:122`) | 13 | inline | ≈10 |
| **Total enum defs** | **261** | **Total dispatch matches** | **≈910** |

The ≈910 dispatch lines are not pure overhead: they're where the C's
logic *moved*. C `route_ipv4` is 818 raw / 619 code; our
`route.rs::route()` is 452 code (0.73×!) — because the I/O moved into
`dispatch_route_result`'s 337 lines. Net is roughly the same. The
**enum definitions** (261 lines) are the actual tax. **Intentional** —
that enum is what `route.rs`'s 25 unit tests assert against. Removing
it means losing the in-process test surface and going back to
integration-test-only coverage for routing.

### 4. Borrow-checker tax

**≈50–70 lines today. Was higher.** Partially removable.

`dcc9ac9c` already deleted `detach_route_result()` (≈30 LOC of
variant-by-variant rebuilding) plus two `to_owned()` wrappers, by
making `RouteResult<T>` generic and instantiating at `T = NodeId`
(which is `Copy`) instead of `T = &str`. Net −41 lines on `net.rs`.

**Remaining siblings:** the dominant pattern is `.name.clone()` to
escape a `&self.graph` borrow before mutating `self.nodes`:

| File | `.name.clone()` | All `.clone()` | Representative |
|---|---:|---:|---|
| `daemon/gossip.rs` | 6 | 22 | `let from = self.graph.node(e.from)?.name.clone();` then `self.send_subnet(…, &from, …)` which takes `&mut self` |
| `daemon/connect.rs` | 5 | 13 | same pattern resolving nexthop name |
| `daemon/net.rs` | 7 | 10 | `source_name = self.name.clone()` for the loop-detection log line |
| `daemon/txpath.rs` | 5 | 10 | nexthop resolution before `&mut self.conns` |
| `daemon/periodic.rs` | 4 | 11 | timer-triggered gossip |
| `daemon/metaconn.rs` | 2 | 6 | |

Most of these clone a `String` (node name, ≈20 bytes). Not a perf
issue. They're a LOC issue because each is typically 3–5 lines
(`let x = { borrow scope }; mutate(self, x)` instead of C's
`mutate(node->name)`).

**What would remove it:** `nodes: HashMap<String, NodeState>` →
`HashMap<NodeId, NodeState>` (or a `SlotMap`). Then graph traversal
returns `NodeId` (Copy), no clone needed, and the daemon does one
name-lookup at the boundary. This is the same shape `dcc9ac9c`
applied to `RouteResult`. **Estimated savings: ≈40–60 lines** across
the six files. Not trivial to do (touches ≈30 sites). **Removable.**

The other clones (`addr.clone()`, `port.clone()` in `gossip.rs:edge_
addrs`) are `String` clones of canonical wire forms we keep around
for ADD_EDGE re-gossip. Could be `Arc<str>` but that's churn for ≈6
lines. **Not worth it.**

### 5. Error type definitions

**≈1,200 lines.** Intentional. C `return false` is 0 lines.

| Component | LOC |
|---|---:|
| 12 × `pub enum *Error` definitions | 550 |
| 12 × `impl Display for *Error` | 460 |
| `impl From<…> for *Error` chains | 194 |
| **Total** | **≈1,204** |

Largest: `SetupError` (`daemon.rs:1915`, daemon boot failures —
confbase missing, key load failed, bind refused, …) and `CmdError`
(`cmd/mod.rs:44`, every CLI failure mode).

C equivalent: `bool` return + an inline `logger(LOG_ERR, "…")` at
each failure site. The C *also* pays for the error-message string —
it's just adjacent to the failure instead of centralized. The honest
tax is: **enum variant** (1 line) + **From impl** (≈3 lines/variant on
average) + **Display match arm above and beyond what the inline
printf would be** (≈1–2 lines/variant for the `Variant => write!(…)`
ceremony). For ≈60 total variants across 12 enums: **≈300–400 net
overhead lines.** The other ≈800 are the error messages themselves,
which C also has, just inline.

**Removable?** Could collapse with `thiserror` derive (−≈200 lines of
`impl Display`/`impl From` boilerplate). Adds a proc-macro dep. We've
avoided proc-macro deps so far (no `clap`, no `serde_derive` outside
test deps). **Tax we chose to pay.**

### 6. tinc-tools at 1.52× — the worst crate

Three compounding causes. None is "ported wrong."

**6a. The Finding-enum-then-Display pattern (≈+320 lines in `fsck.rs`
alone).** C `fsck.c` has 52 inline `fprintf(stderr, "…")` calls
scattered through the check logic. We have:

| `fsck.rs` region | Raw | What it is |
|---|---:|---|
| 1–110 | 110 | imports + module doc |
| `enum Finding` (111–211) | 101 | 23 variants, each with a doc-comment naming the C site |
| `impl Finding::severity()` (227–282) | 56 | C has no severity — it just exits or continues |
| `impl Display for Finding` (283–440) | 158 | the 52 fprintf strings, but each is a match arm |
| `Report` + check fns (441–1235) | 795 | the actual checks — maps to C 412 effective LOC |
| `#[cfg(test)]` (1236–2175) | 940 | C `fsck.c` has zero tests |

`fsck.rs` production at tokei: **527 code, 370 comments**. C `fsck.c`
minus its 85 RSA-LEGACY lines: **412 code**. Ratio at the logic level:
**1.28×**, not the 2.4× the raw counts suggest. The 1.28× breaks down:

- `enum Finding` adds 23 variant-declaration lines C doesn't have
  (C's "variant" is the fprintf call site itself).
- `severity()` (≈30 code lines after stripping doc) is **genuinely
  new logic** — C `fsck.c` has no `--quiet`-filterable severity,
  just "fatal: exit" vs "warning: print and continue." We're
  **stricter** (machine-readable `Report`).
- `Display` match arms add ≈2 lines of `Variant { … } =>
  write!(…)` ceremony per case over an inline fprintf. ×23 ≈ +50.

**6b. `tui.rs` is 136 code lines that C doesn't pay because C links
libncurses.** `top.c` is `#ifdef HAVE_CURSES` and calls `mvprintw()` /
`getch()`. We hand-roll termios raw mode + ANSI escape rendering
(`tui::goto(row, col)`, `tui::poll_key()`). 136 code lines vs 0.
**Intentional** — no ncurses-sys, no FFI, the renderers are
testable as `String`-producing functions. **Not removable** without
adding a TUI dep.

**6c. No clap, but no setup-duplication either.** The `tincctl.c`
monolith (3,380 raw / 2,577 code) split into 16 `cmd/*.rs` files
*could* have duplicated `Paths::resolve()` + `read_tinc_conf()` 16
times. **It doesn't:** `bin/tinc.rs` does argv → `Paths` once and
hands `&Paths` to every `cmd::*::run()`. The most-common-import
check shows 9/16 files importing `crate::names::Paths`, 0 of them
re-resolving it. The 80-line hand-rolled getopt in `bin/tinc.rs`
replaces 1,049 raw lines of vendored `getopt.c` — **net −969 lines.**
No clap (would be +≈40 transitive deps).

**6d. `gossip.rs` references 8 C files** (`graph.c`, `meta.c`,
`net_setup.c`, `node.c`, `protocol_auth.c`, `protocol.c`,
`protocol_edge.c`, `protocol_subnet.c` — sum 2,796 C code lines).
Its 1,030 prod-code lines aren't 4.7× `protocol_edge.c`, they're
0.37× the C surface they actually cover. The earlier 4.7× was a
denominator error (only counted `protocol_edge.c`).

### 7. C `#ifdef`'d-out code we did NOT port

**−806 C lines we correctly skipped.** Verified clean.

14 C files carry `#ifndef DISABLE_LEGACY`. Balanced-preprocessor walk
counts 806 lines inside those guards (largest: `protocol_auth.c` 312,
`keys.c` 105, `tincctl.c` 100, `fsck.c` 85). Spot-check of Rust for
`legacy|RSA|metakey`: every hit is either a comment explaining what
we DON'T do (`bin/tinc.rs:152`: "dropped under DISABLE_LEGACY"), or
a wire-format field that exists for *parsing* legacy peers' messages
without *speaking* legacy (`proto/msg/key.rs:100`:
`Option<ReqKeyExt>`, `None` for the 3-token legacy form). No legacy
crypto, no RSA, no metakey handshake. **Nothing accidentally
ported.** The "legacy peer sent us X, we drop it" paths in
`gossip.rs` / `net.rs` are documented as plain comments (re-tagged
from `STUB(chunk-never)` in `957f0ec5` — they were never work
items, just permanent boundaries). `rg 'STUB\('` now returns only 2
cold-perf items in `txpath.rs` / `tcp_tunnel.rs`.

### 8. Dead code

**≈0 lines.** 3 `#[allow(dead_code)]` annotations in `tincd`, all on
timer-variant enum arms (`TimerWhat::KeyExpire`, `TimerWhat::UdpPing`)
that are scaffolded for chunk-11 but currently `unreachable!()`. One
in `tinc-crypto/tests/kat.rs` on a serde-skipped field. `cargo-udeps`
not in the dev shell; `cargo clippy -D warnings` is, and it's clean,
so no unused-function-level dead code. **Nothing to remove.**

### Summary

Of the **+42,671 raw-line delta** (Rust 68,164 − C 25,493):

| Bucket | Lines | % | Disposition |
|---|---:|---:|---|
| Tests (integration `tests/*.rs` + in-file `#[cfg(test)]`) | +34,069 raw / +23,233 code | 80% | **Intentional.** Found 11 bugs. Maybe −200 redundant proto.rs happy-path unit tests. |
| Doc-comments above C density (11,158 vs C-equivalent ≈2,550) | +8,608 | 20% | **Intentional.** 1,762 of these are C-ref cross-links (load-bearing). 13 need path qualifiers. |
| C code we deliberately don't port (crypto subdirs, getopt, splay, solaris, LEGACY) | −7,871 code | −18% | **Intentional.** Per [What to Drop](#what-to-drop). |
| Typed-error machinery (enum + Display + From) | +≈300–400 net | 1% | **Tax we chose.** `thiserror` would cut ≈200. Proc-macro dep avoided. |
| Pure-module result enums (the dispatch seam) | +261 | <1% | **Intentional.** This IS the unit-test surface. |
| Borrow-checker name-clones | +≈50–70 | <1% | **Removable.** `HashMap<String,_>` → `HashMap<NodeId,_>` (≈30 sites). |
| `tui.rs` (ANSI instead of libncurses) | +136 | <1% | **Intentional.** No FFI, testable renderers. |
| `Finding`-enum-then-Display (fsck/info/config testable-output pattern) | +≈200 net over inline-fprintf | <1% | **Intentional.** `fsck::Report` is machine-readable; C's isn't. |
| Dead code | ≈0 | 0% | clippy-clean. 2 timer variants scaffolded for chunk-11. |

**Logic-vs-logic: 21,393 Rust prod code vs ≈17,770 effective C →
1.20×.** Of that 20%: roughly half is the dispatch-seam +
typed-error tax (intentional, buys testability), a few percent is
borrow-checker workarounds (removable, low-value), and the rest is
idiom (`match Some(x)` is 3 lines where C `if(x)` is 1; `let Ok(y) =
… else { return }` is 3 where C `if(!y) return` is 1). No bucket
shows "ported wrong" — the audits would have caught that, and the
`gossip.rs` 4.7× / `graph.rs` 2.85× outliers were both denominator
errors (wrong C baseline).

---

## Testing Strategy Summary

| Layer | Technique |
|---|---|
| Parsers (`tinc-proto`, `tinc-conf`) | proptest round-trip + differential vs C via FFI |
| SPTPS | Cross-impl handshake (Rust↔C in-process) + cargo-fuzz + KAT vectors |
| Graph | Differential vs C on random graphs |
| Device | Per-OS smoke test in CI (Linux: GitHub Actions; BSD: builds.sr.ht as upstream already does; macOS: GH Actions) |
| End-to-end | Three strata, see below. The `test/integration/*.py` python suite is the SPEC, not the runner. |
| Interop | 3-node mesh in CI: 1× C tincd 1.0, 1× C tincd 1.1, 1× Rust tincd. Ping across all pairs. |
| Performance | `criterion` microbenchmarks on SPTPS seal/open + `iperf3` macro-benchmark in CI with regression gate |

### Three integration-test strata (post chunk-7 / `c32f135e`)

The rewrite has converged on three distinct end-to-end harnesses, ordered
by fidelity-vs-convenience. Each catches a class of bugs the others miss.

| Stratum | File | Daemon device | Kernel? | Runs in | Uniquely catches |
|---|---|---|---|---|---|
| **S1: test-process-as-peer** | `tests/stop.rs` (13) + `tests/security.rs` (5) | n/a — test process IS the peer | No | <100ms | Per-record SPTPS dispatch correctness. Can hand-craft adversarial records (wrong-key, malformed ADD_EDGE, splice MITM, own-ID) that two cooperating daemons never produce. |
| **S2: two-real-daemons, fake TUN** | `tests/two_daemons.rs` (10) + `tests/scripts.rs` (4) | `socketpair(SEQPACKET)` via `DeviceType=fd` or `DeviceType=dummy` | No | <200ms (7s for backoff/keepalive tests) | **Epoll wake-chain bugs.** The mio EPOLLET fall-through (chunk 6). The chunk-5 idempotence-addr-compare bug (chunk 9b) — both invisible to S1. `three_daemon_relay`/`three_daemon_tunnelserver` are 3-node. `tinc_join_against_real_daemon`: REAL `cmd::join` over real TCP. `sighup_reload_subnets`: `kill -HUP` mid-run. `scripts.rs`: shell-appender mechanism found `setup()` skipping `net_setup.c:1273` own-subnet-up. |
| **S3: bwrap netns, real TUN** | `tests/netns.rs` (2) | `/dev/net/tun` via `DeviceType=tun` | Yes | ~3s | `TUNSETIFF`, `IFF_NO_PI`, kernel-generated checksums. `real_tun_unreachable` proves `icmp.rs` byte-for-byte (kernel parses our packet). The `--tmpfs /dev` trick makes this no-root. |
| **S4: cross-impl** | `tests/crossimpl.rs` (2) | real TUN + real C tincd | Yes | ~5s | **Wire bugs invisible to Rust↔Rust.** S1–S3 prove self-consistency; this proves we speak the C dialect. UDP-label NUL byte, PACKET dispatch — both `463b9987`, both ~90 commits old, neither catchable until this ran. devShell sets `TINC_C_TINCD` automatically (`.#tincd-c` fileset is `src/`-only → Rust edits don't invalidate). |
| **S5: throughput** | `tests/throughput.rs` (1, `#[ignore]`) | real TUN + iperf3 + perf | Yes | ~25s | **Load-only bugs.** The EPOLLET drain deadlock (`2b5dda45`): every test fit meta-conn traffic in one 2176-byte read. Ping is 150 bytes b64'd. Only line-rate flushes the queue past one recv. 0.0 → 850 Mbps. `#[ignore]` — runs pre-tag. |

**Dispatch rule for new tests**: protocol-handler logic (parse, gate, mutate-world) → S1. Timing/ordering/reconnect → S2. Anything touching `tinc-device::linux` or asserting on packets the daemon WRITES (ICMP synth, ARP reply) → S3. Anything where the failure mode is "both sides agree on the wrong answer" → S4.

S3/S4 are Linux-only and runtime-skip when bwrap is unavailable (Debian-with-`unprivileged_userns_clone=0`, BSD, macOS). S4 also runtime-skips when `TINC_C_TINCD` is unset (non-nix raw `cargo nextest run`). S2 covers the same daemon code minus the device backend; that's the cross-platform floor.

### `test/integration/*.py` port matrix

The upstream C suite is 35 python files, ~4.8k LOC. The original Phase-0d plan was "parameterize testlib over `TINC_BIN`" — that was optimistic. The python testlib shells out to `tinc cmd` for everything (`ctx.node(init=...)` → `tinc init`, `set Port` → `tinc set`, etc); our CLI has gaps (`cmd_net` connect/disconnect needs chunk-8 daemon-side, `cmd_join` needs chunk-10 invitation server). And `testlib.util.require_root()` for the netns tests is exactly what bwrap-S3 just made unnecessary. Better: **port the test BODIES to the Rust harness** as we close chunks, drop the python.

| `test/integration/*.py` | Covers | Stratum | Chunk-gate | Status |
|---|---|---|---|---|
| `basic.py` | start/tinc-up/stop | S2 | 8 | ✅ `tinc_up_runs` (chunk-8's wire-up test). Script touches a marker file. |
| `ns_ping.py` | netns + TUN + ping | S3 | 7 | ✅ `real_tun_ping`. Plus `real_tun_unreachable` (chunk 9a) which `ns_ping.py` doesn't have. |
| `device_fd.py` | `DeviceType=fd` round-trip | S2 | 7 | ✅ `first_packet_across_tunnel`. Plus `compression_roundtrip` (chunk 9a) using same rig. |
| `cmd_dump.py` | `dump nodes/edges/subnets/connections` formatting | S1 | 7 | partial — all four arms exist; `dump_nodes` compression column real (chunk 9a); the python asserts on FORMAT, our `peer_edge_triggers_reachable` round-trips it. |
| `security.py` | adversarial ID lines, tarpit timing, own-ID rejection | S1 | 4a | ✅ `tests/security.rs` (`2adedf9a`). 5 cases: own-ID, unknown-ID, legacy-minor, id-timeout (upgraded post-chunk-8 to assert EOF), splice. Tarpit omitted (loopback-exempt). |
| `splice.py` | MITM relay attack — `splice` binary connects to both, proxies. Daemon must drop on SIG mismatch. | S1 | 4a | ✅ `splice_mitm_rejected`. **Found a SECOND defense layer** (SPTPS role asymmetry: both Responders → deadlock before label-order matters). |
| `import_export.py` | `tinc export`/`import`/`exchange` host-file round-trip | n/a (CLI-only) | — | tinc-cli already has these; test in `crates/tinc-tools/tests/` |
| `scripts.py` | tinc-up/down, host-up/down, subnet-up/down — order + env vars | S2 | 8 | ✅ `tests/scripts.rs` (`6110347b`). Shell appenders to one log file (no notification socket; `Command::output()` blocks so append order IS firing order). Pins `host-up→hosts/N-up→subnet-up` (`graph.c:273-294`). **Found two bugs by inspection**: `setup()` skips `net_setup.c:1273` own-subnet-up; `Drop` skips `:1298` own-subnet-down. Both fixed. NETNAME skipped (`periodic.rs:266` not threaded through). |
| `net.py::test_tunnel_server` | `TunnelServer = yes` filters indirect ADD_EDGE — foo↔mid↔bar, foo sees 2 nodes not 3 | S2 | 9c | ✅ `three_daemon_tunnelserver` (chunk 9c). **Stronger than the python**: also asserts the data-plane consequence (`ping 10.0.0.2` from alice gets ICMP `NET_UNKNOWN`). |
| `address_cache.py` | addrcache file persistence across restart | S2 | 6 | ✅ `tests/addrcache.rs` (`15d1b8fb`). 3 restart rounds. Round 1: connect with `Address =` → SIGTERM → cache file exists with `127.0.0.1:PORT`. Round 2: `rm -rf cache/` → reconnect → dir recreated. Round 3: rewrite `hosts/bob` WITHOUT `Address =` → restart → connects from cache only — THE proof that `AddressCache::open()` wires into dial path. **SIGTERM not SIGKILL** — `addrcache::Drop` is the disk write. |
| `compression.py` | `Compression = N` per-level (LZO/zlib/LZ4) — netns + TCP-over-tunnel content compare | S2 | 9 | ✅ `compression_roundtrip` (S2 not S3 — don't need real TUN to prove level-negotiation). Asymmetric: alice asks zlib-6, bob asks LZ4. LZO `STUB(chunk-9-lzo)`. |
| `algorithms.py`, `legacy_protocol.py` | RSA+AES legacy crypto | — | never | not done — no `#[ignore]` placeholder file was ever written; the chunk-never boundary is documented inline at the `gossip.rs`/`net.rs` drop paths instead. |
| `bind_address.py`, `bind_port.py` | `BindToAddress`/`ListenAddress`, port-0 reuse | S1 | 10 | the chunk-3 listener worklist |
| `proxy.py` | `Proxy = socks5/http/exec` | S2 | 10 | ✅ all three (`e841d05e` socks5, `1367cfaf` exec, `af26db41` http). `socks5_proxy_roundtrip`: in-process RFC 1928 server, byte-exact. `proxy_exec_roundtrip("cat")`. `http_proxy_roundtrip`: in-process headerless CONNECT server (matching `proxy.py:155`'s minimal form — the C breaks on header-sending proxies, **C-is-WRONG #10**). Agent caught BufReader leftover bug: tinc queues CONNECT+ID in one flush; `into_inner()` would lose ID; `reader.buffer().to_vec()` first. STRICTER: bracket IPv6 in authority (C doesn't). |
| `device.py`, `device_tap.py`, `device_multicast.py`, `device_raw_socket.py` | non-TUN device backends | S3 | 9/10 | ✅ TAP (`2bbd51b0`): `rust_dials_c_switch`/`c_dials_rust_switch` ping over real TAP devices. Found the **TAP race** (IPv6 router solicits on link-up → simultaneous REQ_KEY → handshake loop); three-phase fix (devices up AFTER meta handshake). raw_socket: `tinc-device` module exists, daemon wiring not yet (no demand). multicast: defer. |
| `invite.py`, `invite_tinc_up.py`, `cmd_join.py` | invitation flow end-to-end | S2 | 10 | ✅ `tinc_join_against_real_daemon` (chunk 10). REAL `tinc-tools::cmd::join` against real daemon. Stronger than the python (which shells out to `tinc join`). Single-use proof end-to-end. |
| `cmd_fsck.py`, `cmd_keys.py`, `cmd_sign_verify.py`, `cmd_import.py`, `cmd_misc.py`, `cmd_net.py`, `commandline.py`, `executables.py`, `variables.py` | CLI surface | n/a | — | tinc-cli/tinc-tools tests, not tincd. Some already covered. |
| `sptps_basic.py` | `sptps_test` binary stream/datagram | n/a | — | ✅ `tests/self_roundtrip.rs` is this + 64KiB-forces-fragmentation that the python doesn't have |
| `systemd.py` | `LISTEN_FDS` socket activation | S1 | 10 | |
| `sandbox.py` | seccomp `Sandbox = high` | — | post-10 | linux-only, lands LAST (the seccomp filter has to allowlist every syscall the daemon makes) |

**Post-chunk-12+**: 19 of 35 covered (no `tcponly.py` exists — PACKET 17 covered by `crossimpl.rs` `*_tcponly` variants instead). Was post-chunk-12-switch: (`ns_ping`, `device_fd`, `security`, `splice`, `compression`, `basic`, `sptps_basic`, `net.py::tunnel_server`, `invite/join` ×3, `scripts`, `proxy` (full), `address_cache`, `device_tap` + 2 partial). 9 CLI-only (tinc-tools). 4 deliberately-never (`legacy_protocol`, `algorithms`, `sandbox`, `device_multicast`). 3 remaining gaps: `bind_address.py`/`bind_port.py` (`chunk-12-bind`), `systemd.py` (LISTEN_FDS). `device_raw_socket.py` no demand.

### Three-node S2/S3: the relay path

**`three_daemon_relay` landed** (`18fa47b0`, S2). foo→mid←bar with no direct ConnectTo; packet from alice's TUN routes via mid to bob's TUN. Found a chunk-5 bug en route (the addr-compare in `on_add_edge` idempotence). The harness was 318 LOC of test code, mostly pubkey distribution (each node needs all three's `Ed25519PublicKey =`). The SPTPS_PACKET-over-TCP encapsulation (`send_sptps_tcppacket`, `:975-986`) is `STUB(chunk-9c)` — the test passes via UDP relay; TCP encap is the `tcponly`/PMTU-too-small fallback.

### iperf3 throughput gate (S3+S4, `#[ignore]`)

`tests/throughput.rs`. Three configs (C↔C / R↔R / R↔C) in one bwrap;
`perf record -g` gated on `TINCD_PERF=1`, `perf trace -s` gated on
`TINCD_TRACE=1`. **Gate passes at ~115% of C** (Phase-6 row). The
gate found two of its own bugs en route: the EPOLLET drain deadlock
(0.0 Mbps on first run, `2b5dda45`) and the IP_MTU NOT-PORTING (52%,
`05ba1f82`) — both detailed in ISSUES.md Rust-is-WRONG #4 / #5. The
dev-profile measures ~17 Mbps (chacha20 debug-assert overhead, ~50×);
gate is profile-aware (95% release / 1% dev).

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
| TUN | hand-rolled (`tinc-device::linux`). The `tun` crate doesn't expose `IFF_NO_PI` at the granularity the +10/+14 trick needs. |
| CLI | hand-rolled `match argv[1]` (clap is 10× deps for ~15 subcommands; same call as `sptps_test`) |
| Logging | `log` + `env_logger` |
| Config | hand-rolled (format is trivial, `serde` is overkill) |
| Testing | `proptest` (tinc-conf, tinc-proto roundtrips). No benchmark crate — `throughput.rs` IS the perf gate. |
| Arena | `slotmap` |

---

## Risk Register

Four rows fired and are no longer risks. Kept for the record:

| Risk | Fired? | Outcome |
|---|---|---|
| Bespoke crypto primitive mismatch | ✅ 4× in Phase 0a | KAT-locked. ChaPoly nonce layout, ECDH unvalidated Edwards→Montgomery, PRF label arithmetic, on-disk key format. None made it past Phase 0. |
| SPTPS state-machine subtle incompatibility | ✅ 2× | Phase 2 caught sig-verify ordering. S4 cross-impl caught UDP-label NUL (`463b9987`) — NOT catchable in-process, both sides agree on the wrong answer. |
| `net_packet.c` perf regression | ✅ spectacularly | 0.0 Mbps. Not a packet-path bug — EPOLLET drain semantics (`2b5dda45`). 850 Mbps post-fix. The throughput gate did its job on first run. |
| `route.c` packet-parsing edge cases | ✅ as C-is-WRONG #8 | `route.c:344` reads wrong offsets. 14yo. Benign. Ported faithfully, doc'd. Not a Rust risk — a C bug we now know about. |

Live risks:

| Risk | Likelihood | Mitigation |
|---|---|---|
| `chacha20` crate drops `ChaCha20Legacy` | Low | No feature flag involved (unconditional export in 0.9). Pin `=0.9` and check on bumps. Fallback: vendor DJB ChaCha (~200 LOC). |
| `curve25519-dalek` exposes `FieldElement` | Would let us delete the vendored `fe` module | Monitor. Until then, the ~180 LOC stays. |
| Legacy protocol RSA padding mismatch | High (if ever ported) | Keep using OpenSSL via FFI for legacy auth indefinitely. Currently `STUB(chunk-never)`. |
| Windows TUN driver churn | Medium | Switch to wintun (WireGuard's); better-maintained than TAP-Windows. Not yet started. |
| Scope creep into "let's redesign the protocol" | High | **Hard rule:** byte-compatible port only. Protocol v18 ideas go in a separate doc. |

---

## Appendix: Stub audit (post-chunk-5, FROZEN)

> **⚠ Historical, superseded.** Exhaustive walk of all 66 markers at
> `83de6651` (when `daemon.rs` was 9043 LOC, pre-split). Found 9
> wrong C-line-refs, 5 re-chunks, 4 stale markers, 4 unmarked gaps;
> all closed. The 5 dark-stub retaliate paths
> (`owner == myself` / `from == myself` in `protocol_{edge,subnet}.c`)
> got `debug_assert!(false, ...)` — reachable in a real mesh (stale
> 3rd-party gossip about us), dark in 2-node tests. Full inventory
> tables removed `957f0ec5`; the markers themselves were the
> source of truth and have all since been resolved or re-tagged.
> Current STUB count: `rg 'STUB\(' crates/` = 2 (cold-perf only).
