//! `tinc join URL` — accept an invitation and bootstrap a new node.
//!
//! ## What `join` does
//!
//! The pair to `invite`. You receive a URL out-of-band, run join, get
//! a populated confbase. Mechanically:
//!
//! ```text
//! 1. Parse URL → (host, port, key_hash, cookie).
//! 2. Generate a throwaway keypair for the SPTPS handshake.
//! 3. TCP connect(host:port).
//! 4. Send "0 ?<our-throwaway-pubkey-b64> 17.1\n".
//!    The `?` prefix is what tells the daemon "this is an invitation
//!    redemption, not a normal node connection".
//! 5. Receive two lines:
//!    - "0 <daemon-name> 17.x\n" — its ID greeting.
//!    - "4 <invitation-pubkey-b64>\n" — ACK with the invitation key.
//! 6. Verify: sha512(invitation-pubkey-b64)[..18] == key_hash.
//!    If not, the URL doesn't match this daemon. Bail.
//! 7. Start SPTPS: us=initiator, our key=throwaway, their key=invitation.
//!    Label = "tinc invitation" (15 bytes, fixed). Stream framing.
//! 8. SPTPS handshake completes → send cookie as record type 0.
//! 9. Daemon recovers filename from sha512(cookie || fingerprint),
//!    renames file to .used (single-use!), reads it, sends contents
//!    in chunks as type-0 records, then a zero-length type-1 record
//!    as terminator.
//! 10. We accumulate type-0 chunks, type-1 triggers finalize_join.
//! 11. finalize_join: parse the blob, write tinc.conf + hosts/*,
//!     generate our REAL node key, send pubkey back as type-1 record.
//! 12. Daemon writes pubkey to hosts/OURNAME, sends type-2 (zero-len)
//!     as ack, we mark success and shut down.
//! ```
//!
//! ## Layering for testability
//!
//! | Piece | Input | Output | I/O |
//! |---|---|---|---|
//! | `parse_url` | `&str` | `ParsedUrl` | none |
//! | `finalize_join` | `&[u8]`, `&Paths`, `force` | `JoinResult` (incl. pubkey-to-send) | filesystem only |
//! | `join` | `&str`, `&Paths`, `force` | `()` | TCP + filesystem |
//!
//! `finalize_join` is the testable seam. The contract test:
//! `invite()` → in-process server stub ↔ SPTPS → `finalize_join()`
//! writes a confbase that `read_private` accepts. No subprocess.
//!
//! ## What we drop from upstream
//!
//! - **Netname re-derivation loop**: random `join_DEADBEEF` netname
//!   if `-n vpn` is already populated. We require `-c` or empty
//!   confbase.
//! - **`ifconfig` script generation**: per-platform `ip`/`ifconfig`/
//!   `netsh` synthesis (~300 LOC). We write a placeholder;
//!   `Ifconfig`/`Route` keywords are recognized but not acted on.
//! - **tty prompts**: same "no prompts" deviation as init/genkey/fsck.
//! - **RSA keygen**: `DISABLE_LEGACY`.
//! - **`check_port`**: stub.
//!
//! ## What we tighten
//!
//! - **Data accumulation cap.** Upstream `xrealloc` grows unbounded.
//!   We cap at 1 MiB (a 1000-node mesh's invitation is ~50 KiB).
//! - **Variable filter is exact, not prefix.** We use
//!   `tinc-conf::vars::lookup` directly. Same `VAR_SAFE` table.

mod finalize;
mod server_stub;
mod url;
mod wire;

#[cfg(all(test, unix))]
mod tests;

pub use finalize::finalize_join;
pub use url::{ParsedUrl, parse_url};

#[cfg_attr(not(test), allow(unused_imports))]
pub(crate) use server_stub::server_receive_cookie;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rand_core::OsRng;
use tinc_crypto::b64;
use tinc_crypto::invite::fingerprint_hash;
use tinc_crypto::sign::PUBLIC_LEN;
use tinc_sptps::{Framing, Output, Role, Sptps};

use crate::keypair;
use crate::names::Paths;

use super::{CmdError, io_err, makedir};

use wire::{PROT_MAJOR, parse_greeting_line1, parse_greeting_line2, recv_line};

/// SPTPS handshake label. Both sides hardcode this string; the 15 is
/// `strlen("tinc invitation")`. Passed as `label.into()` so the
/// trailing NUL is NOT included (matching upstream's explicit `15`,
/// not `sizeof`).
pub(crate) const INVITE_LABEL: &[u8] = b"tinc invitation";

/// `PROT_MINOR` in the *outgoing* greeting is hardcoded `1`, NOT 7.
/// Upstream builds the full version string with the real `PROT_MINOR`
/// then *throws it away* and sends `1` instead. The daemon overwrites
/// `c->protocol_minor = 2` anyway. So the value we send is dead, but
/// we match the bytes because that's what hits the wire.
const PROT_MINOR_SENT: u32 = 1;

/// Hard cap on accumulated invitation data. Upstream grows unbounded
/// (`xrealloc(data, datalen + len + 1)` in a loop). 1 MiB is ~20×
/// a realistic invitation from a 1000-node mesh.
const MAX_DATA: usize = 1 << 20;

/// Socket read timeout. Upstream's `wait_socket_recv` `select`s with
/// `tv_sec = 5`. We use the same.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

// finalize_join — the testable seam

/// Result of consuming an invitation blob. The pubkey goes back over
/// SPTPS (type-1 record); the rest is informational.
///
/// Why this isn't `()`: `finalize_join` doesn't touch the SPTPS
/// connection — that's a layer above. It returns what the SPTPS
/// layer needs to send. Upstream has the `sptps_send_record` *inside*
/// `finalize_join` because `sptps` is a global there. We split:
/// `finalize_join` is pure-fs, the caller does the send.
#[derive(Debug)]
pub struct JoinResult {
    /// `Name = X` from chunk 1, line 1. The new node's name.
    pub name: String,
    /// The new node's pubkey, as the b64 string the daemon expects.
    /// `b64::encode(pk)`, 43 chars. Goes back as type-1 record body.
    /// NOT secret — it's the public key.
    pub pubkey_b64: String,
    /// Names of host files written from secondary chunks. For tests
    /// and for the binary's "Configuration stored" summary. Upstream
    /// doesn't surface this; we do because it's free.
    pub hosts_written: Vec<String>,
}

// cmd_join — the TCP+SPTPS shell

/// `tinc join URL`.
///
/// `paths` should be a *fresh* confbase (no `tinc.conf`). We check
/// via `finalize_join` (which re-checks), but doing it up front means
/// failure happens *before* we open a TCP connection and burn a
/// single-use cookie on the daemon side.
///
/// # Errors
/// - `BadInput`: bad URL, daemon greeting wrong, key_hash mismatch,
///   blob parse failed.
/// - `Io`: connect/read/write failed, fs writes from `finalize_join`.
///
/// # Panics
/// Only via `keypair::generate`'s entropy source.
// Sequence of distinct steps sharing local state (sockets, SPTPS
// pump, accumulated blob). Upstream is one function for the same
// reason — the steps share too much state to split cleanly.
#[allow(clippy::too_many_lines)]
pub fn join(url: &str, paths: &Paths, force: bool) -> Result<(), CmdError> {
    // ─── Parse URL
    let parsed =
        parse_url(url).ok_or_else(|| CmdError::BadInput("Invalid invitation URL.".into()))?;

    // ─── Preflight: confbase must be fresh
    // Do this BEFORE connecting — the cookie is single-use on the
    // daemon side (rename to .used). If we connect, send cookie,
    // daemon renames, then WE fail on "tinc.conf exists" — the
    // invitation is burned.
    //
    // makedirs(DIR_CONFDIR | DIR_CONFBASE) — created here (and
    // `finalize_join` re-creates with HOSTS|CACHE). We need confbase
    // to exist for the `access` check below.
    if let Some(confdir) = &paths.confdir {
        makedir(confdir, 0o755)?;
    }
    makedir(&paths.confbase, 0o755)?;

    let tinc_conf = paths.tinc_conf();
    if tinc_conf.exists() {
        return Err(CmdError::BadInput(format!(
            "Configuration file {} already exists!",
            tinc_conf.display()
        )));
    }

    // ─── Generate throwaway key
    // This key is ONLY for the SPTPS handshake; it's not the node's
    // identity. The daemon doesn't store it. (The real node key is
    // generated inside `finalize_join`.)
    let throwaway = keypair::generate();
    let throwaway_b64 = b64::encode(throwaway.public_key());

    // ─── Connect
    // `TcpStream::connect((host, port))` does the getaddrinfo loop
    // internally (resolves all addrs, tries each). We lose the
    // per-addr "Could not connect to X port Y" stderr lines, but
    // gain not reimplementing getaddrinfo iteration.
    eprintln!("Connecting to {} port {}...", parsed.host, parsed.port);
    let port: u16 = parsed
        .port
        .parse()
        .map_err(|_| CmdError::BadInput(format!("Invalid port: {}", parsed.port)))?;
    let mut sock = TcpStream::connect((parsed.host.as_str(), port)).map_err(|e| {
        CmdError::BadInput(format!(
            "Could not connect to inviter ({} port {}): {e}. \
             Please make sure the URL you entered is valid.",
            parsed.host, parsed.port
        ))
    })?;
    sock.set_read_timeout(Some(READ_TIMEOUT))
        .map_err(io_err("set_read_timeout"))?;
    eprintln!("Connected to {} port {}...", parsed.host, parsed.port);

    // ─── Meta-greeting exchange
    // Two lines out, two lines in.
    //
    // OUT: "0 ?<throwaway-pubkey-b64> 17.1\n"
    //   `0` = ID request type. `?` prefix tells `id_h` "invitation".
    //   `17.1` = PROT_MAJOR.PROT_MINOR_SENT. The minor is dead (daemon
    //   overwrites it), but we match upstream's bytes.
    let greeting = format!("0 ?{throwaway_b64} {PROT_MAJOR}.{PROT_MINOR_SENT}\n");
    sock.write_all(greeting.as_bytes())
        .map_err(io_err("send"))?;

    // IN line 1: "0 <daemon-name> 17.x\n" — daemon's send_id.
    // IN line 2: "4 <invitation-pubkey-b64>\n" — daemon's ACK with key.
    //
    // `BufStream` would be cleaner but we need byte-level control
    // for the SPTPS phase (any over-read past the second \n would
    // eat SPTPS handshake bytes — that's the leftover after the two
    // recvline calls). So: hand-rolled buffered reader that we can
    // drain into the SPTPS pump.
    let mut buf = Vec::with_capacity(4096);
    let line1 = recv_line(&mut sock, &mut buf)?;
    let line2 = recv_line(&mut sock, &mut buf)?;

    // Parse line 1: `code != 0 || major != PROT_MAJOR ||
    // !check_id(hisname)`. We split on whitespace; `%s` consumes a
    // single non-whitespace token, so do we.
    parse_greeting_line1(&line1)?;

    // Parse line 2. The fingerprint is everything after `"4 "`.
    let fingerprint = parse_greeting_line2(&line2)?;

    // ─── Verify key_hash
    // The whole point of the URL's first 24 chars: prove the daemon
    // holds the invitation key.
    //
    // `fingerprint_hash`, not `key_hash`: `key_hash` takes a raw
    // pubkey and re-b64s it. The daemon sent us the b64 string
    // directly; hashing it directly is `key_hash`'s body. Upstream
    // never decodes the wire string back to bytes — re-encoding
    // could produce a different alphabet (`+/` vs `-_`) and the
    // hash would differ. Hash exactly what arrived.
    if fingerprint_hash(fingerprint) != parsed.key_hash {
        return Err(CmdError::BadInput(format!(
            "Peer has an invalid key. Please make sure you're using the correct URL.\n{fingerprint}"
        )));
    }

    // Decode the daemon's pubkey for SPTPS.
    let his_pub = b64::decode(fingerprint)
        .filter(|v| v.len() == PUBLIC_LEN)
        .map(|v| {
            let mut a = [0u8; PUBLIC_LEN];
            a.copy_from_slice(&v);
            a
        })
        .ok_or_else(|| CmdError::BadInput("Invalid pubkey from peer".into()))?;

    // ─── Start SPTPS
    // initiator=true (we connected), datagram=false (TCP stream).
    // replaywin=0 (stream mode ignores it; matches the test harness).
    let (mut sptps, init_out) = Sptps::start(
        Role::Initiator,
        Framing::Stream,
        throwaway,
        his_pub,
        INVITE_LABEL,
        0,
        &mut OsRng,
    );

    // ─── SPTPS pump
    // The upstream structure is callback-based: `invitation_send`
    // writes to sock, `invitation_receive` accumulates type-0, calls
    // `finalize_join` on type-1, sets `success=true` on type-2. We
    // do the same with explicit state in this loop.
    //
    // The `buf` from the meta-greeting may have leftover bytes (the
    // first SPTPS record could've arrived in the same recv as line 2).
    // We feed `buf` first, then loop on recv.

    let mut data: Vec<u8> = Vec::new(); // accumulated type-0 records
    let mut success = false;
    let mut pubkey_to_send: Option<String> = None;
    let mut joined_name: Option<String> = None;

    // Helper: push outputs onto sock + state. Returns the type-1
    // record body that needs to go back (the pubkey), if any.
    // Factored as a closure so the state variables are in scope.
    macro_rules! drain {
        ($outputs:expr_2021) => {{
            for o in $outputs {
                match o {
                    Output::Wire { bytes, .. } => {
                        sock.write_all(&bytes).map_err(io_err("send"))?;
                    }
                    Output::Record { record_type, bytes } => match record_type {
                        // case 0: accumulate.
                        0 => {
                            if data.len() + bytes.len() > MAX_DATA {
                                return Err(CmdError::BadInput(
                                    "Invitation data exceeds size limit".into(),
                                ));
                            }
                            data.extend_from_slice(&bytes);
                        }
                        // case 1: finalize. Upstream calls
                        // `finalize_join()` which has the
                        // `sptps_send_record` *inside* it. We split:
                        // finalize returns the pubkey, we send.
                        1 => {
                            let r = finalize_join(&data, paths, force)?;
                            pubkey_to_send = Some(r.pubkey_b64);
                            joined_name = Some(r.name);
                        }
                        // case 2: server acked our pubkey. Done.
                        2 => {
                            eprintln!("Invitation successfully accepted.");
                            success = true;
                        }
                        // Unexpected record type kills the SPTPS
                        // callback.
                        _ => {
                            return Err(CmdError::BadInput(format!(
                                "Unexpected record type {record_type} from server"
                            )));
                        }
                    },
                    Output::HandshakeDone => {
                        // Handshake done → send cookie.
                        let cookie_out = sptps
                            .send_record(0, &parsed.cookie[..])
                            .map_err(|e| CmdError::BadInput(format!("SPTPS send: {e:?}")))?;
                        // Recurse one level to flush the cookie's
                        // wire bytes. Can't be a function call because
                        // it borrows sock+state. The macro avoids
                        // closure-borrow gymnastics.
                        for o in cookie_out {
                            if let Output::Wire { bytes, .. } = o {
                                sock.write_all(&bytes).map_err(io_err("send"))?;
                            }
                        }
                    }
                }
            }
        }};
    }

    // Send initial KEX (start() returned it).
    drain!(init_out);

    // Feed leftover from greeting buf, if any.
    if !buf.is_empty() {
        let leftover = std::mem::take(&mut buf);
        let mut off = 0;
        while off < leftover.len() {
            let (n, outs) = sptps
                .receive(&leftover[off..], &mut OsRng)
                .map_err(|e| CmdError::BadInput(format!("SPTPS receive: {e:?}")))?;
            if n == 0 {
                // Partial record at end of leftover; the recv loop
                // below will deliver more bytes. Put it back.
                buf.extend_from_slice(&leftover[off..]);
                break;
            }
            off += n;
            drain!(outs);
            if let Some(pk) = pubkey_to_send.take() {
                let pk_out = sptps
                    .send_record(1, pk.as_bytes())
                    .map_err(|e| CmdError::BadInput(format!("SPTPS send: {e:?}")))?;
                drain!(pk_out);
            }
            if success {
                break;
            }
        }
    }

    // Main recv loop.
    let mut chunk = vec![0u8; 4096];
    while !success {
        let n = sock.read(&mut chunk).map_err(|e| {
            CmdError::BadInput(format!(
                "Error reading data from {} port {}: {e}",
                parsed.host, parsed.port
            ))
        })?;
        if n == 0 {
            // Peer closed before we got type-2.
            break;
        }

        // Append to buf (which may have a partial record from earlier).
        buf.extend_from_slice(&chunk[..n]);

        // Feed to SPTPS until it consumes everything (or stalls on
        // partial).
        let mut off = 0;
        while off < buf.len() {
            let (consumed, outs) = sptps
                .receive(&buf[off..], &mut OsRng)
                .map_err(|e| CmdError::BadInput(format!("SPTPS receive: {e:?}")))?;
            if consumed == 0 {
                break; // partial record; need more bytes from recv
            }
            off += consumed;
            drain!(outs);

            // After type-1, send our pubkey. (Can't do it inside
            // `drain!` because that's already inside a `for o in
            // outputs` loop and `send_record` borrows `sptps`.)
            if let Some(pk) = pubkey_to_send.take() {
                let pk_out = sptps
                    .send_record(1, pk.as_bytes())
                    .map_err(|e| CmdError::BadInput(format!("SPTPS send: {e:?}")))?;
                drain!(pk_out);
            }
            if success {
                break;
            }
        }
        // Compact: drop consumed bytes, keep partial at front.
        buf.drain(..off);
    }

    if !success {
        return Err(CmdError::BadInput(
            "Invitation cancelled. Please try again and contact the inviter \
             for assistance if this error persists."
                .into(),
        ));
    }

    eprintln!("Configuration stored in: {}", paths.confbase.display());
    if let Some(name) = joined_name {
        eprintln!("Joined as: {name}");
    }

    Ok(())
}
