//! `tinc join URL` — accept an invitation and bootstrap a new node.
//!
//! C reference: `src/invitation.c:1218-1484` (`cmd_join`) and
//! `src/invitation.c:723-1129` (`finalize_join`).
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
//!    redemption, not a normal node connection". Daemon's id_h
//!    (protocol_auth.c:339) branches on name[0]=='?'.
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
//! ## What we drop from the C
//!
//! - **Netname re-derivation loop** (`invitation.c:751-781`): random
//!   `join_DEADBEEF` netname if `-n vpn` is already populated. We
//!   require `-c` or empty confbase.
//! - **`ifconfig.c` script generation** (`invitation.c:882-906`):
//!   per-platform `ip`/`ifconfig`/`netsh` synthesis (~300 LOC). We
//!   write a placeholder; `Ifconfig`/`Route` keywords are recognized
//!   but not acted on.
//! - **tty prompts** (`invitation.c:1031-1061`, `:1068-1112`): same
//!   "no prompts" deviation as init/genkey/fsck.
//! - **RSA keygen** (`invitation.c:1009-1024`): `DISABLE_LEGACY`.
//! - **`check_port`** (`invitation.c:1026`): stub.
//!
//! ## What we tighten
//!
//! - **Data accumulation cap.** C `xrealloc` grows unbounded. We cap
//!   at 1 MiB (a 1000-node mesh's invitation is ~50 KiB).
//! - **Variable filter is exact, not prefix.** We use
//!   `tinc-conf::vars::lookup` directly. Same `VAR_SAFE` table.

use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use rand_core::OsRng;
use tinc_conf::vars::{self, VarFlags};
use tinc_crypto::b64;
use tinc_crypto::invite::{COOKIE_LEN, SLUG_LEN, fingerprint_hash, parse_slug};
use tinc_crypto::sign::{PUBLIC_LEN, SigningKey};
use tinc_sptps::{Framing, Output, Role, Sptps};
use zeroize::Zeroizing;

use crate::keypair;
use crate::names::{Paths, check_id};

use super::{CmdError, io_err, makedir};

/// SPTPS handshake label. `invitation.c:1424`, `protocol_auth.c:372`.
/// Both sides hardcode this string; the 15 is `strlen("tinc invitation")`.
/// Passed as `label.into()` so the trailing NUL is NOT included
/// (matching C's explicit `15`, not `sizeof`).
pub(crate) const INVITE_LABEL: &[u8] = b"tinc invitation";

/// Wire protocol constants. C `protocol.h:29`.
///
/// `PROT_MINOR` in the *outgoing* greeting is hardcoded `1`, NOT 7.
/// `invitation.c:1372`: `sendline(sock, "0 ?%s %d.%d", b64_pubkey,
/// PROT_MAJOR, 1)`. The `1` is literal — the C builds the full version
/// string at line 1368 with `PROT_MINOR` then *throws it away* and
/// sends `1` instead. The daemon overwrites `c->protocol_minor = 2`
/// anyway (`protocol_auth.c:370`). So the value we send is dead, but
/// we match the C bytes because that's what hits the wire.
const PROT_MAJOR: u32 = 17;
const PROT_MINOR_SENT: u32 = 1;
/// `ACK = 4` from `protocol.h:44` enum. The daemon's second line
/// starts with this.
const ACK: u32 = 4;

/// Hard cap on accumulated invitation data. C grows unbounded
/// (`xrealloc(data, datalen + len + 1)` in a loop). 1 MiB is ~20×
/// a realistic invitation from a 1000-node mesh.
const MAX_DATA: usize = 1 << 20;

/// Socket read timeout. C `wait_socket_recv` (`invitation.c:1203`)
/// `select`s with `tv_sec = 5`. We use the same.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

// URL parsing

/// `host[:port]/slug`, parsed. `invitation.c:1267-1310`.
///
/// `[derive(Debug)]` deliberately omitted — `Debug` would print the
/// cookie. The host/port aren't secret but the cookie is. If you
/// need to debug, log host and port explicitly.
pub struct ParsedUrl {
    pub host: String,
    pub port: String,
    /// First 18 bytes of `sha512(b64(invitation_pubkey))`. Not secret
    /// — it's a commitment, not a key. Used to verify the daemon's
    /// greeting.
    pub key_hash: [u8; COOKIE_LEN],
    /// 18 random bytes. Secret — bearer token.
    pub cookie: Zeroizing<[u8; COOKIE_LEN]>,
}

/// Parse the invitation URL. `invitation.c:1267-1310`.
///
/// Accepts: `host:port/SLUG`, `host/SLUG`, `[v6]:port/SLUG`,
/// `[v6]/SLUG`. Port defaults to `"655"`. Slug is exactly 48 b64-url
/// chars.
///
/// The C does this with destructive `strchr` + `*p++ = 0` walking.
/// We slice. Same accept set: rejects garbage at every step,
/// `goto invalid` in C → `None` here. The caller maps `None` to
/// `CmdError::BadInput("Invalid invitation URL.")` — same message
/// the C prints.
///
/// Doesn't validate that `host` is a real hostname or that `port`
/// is numeric — `getaddrinfo`/`TcpStream::connect` will fail on
/// garbage and that's a clearer error than "Invalid URL".
#[must_use]
pub fn parse_url(url: &str) -> Option<ParsedUrl> {
    // C: `slash = strchr(invitation, '/'); if(!slash) goto invalid;`
    let slash = url.find('/')?;
    let (addr_part, slug_with_slash) = url.split_at(slash);
    let slug = &slug_with_slash[1..]; // skip '/'

    // C: `if(strlen(slash) != 48) goto invalid;`
    if slug.len() != SLUG_LEN {
        return None;
    }

    // C: `if(*address == '[') { ... }` — bracketed IPv6.
    // The brackets are URL syntax, NOT part of the address. Strip
    // them; `TcpStream::connect`'s `(&str, port)` form takes the
    // unbracketed literal.
    let (host, port) = if let Some(v6_body) = addr_part.strip_prefix('[') {
        // C: `bracket = strchr(address, ']'); if(!bracket) goto invalid;`
        let close = v6_body.find(']')?;
        let host = &v6_body[..close];
        let after = &v6_body[close + 1..];
        // C: `if(bracket[1] == ':') port = bracket + 2;`
        // Anything between `]` and `/` that isn't `:PORT` is garbage.
        // The C silently ignores trailing garbage (`]garbage/slug`
        // would parse with port = NULL → 655). We're stricter: only
        // `:PORT` or empty.
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => p,
            None if after.is_empty() => "655",
            _ => return None, // `]garbage` or `]:` (empty port)
        };
        (host.to_owned(), port.to_owned())
    } else {
        // C: `port = strchr(address, ':'); if(port) *port++ = 0;`
        // Non-bracketed: split on FIRST colon. `1.2.3.4:655` works.
        // Unbracketed `::1/slug` would split at the first `:` and
        // treat `:1` as the port — broken, same as C. Use brackets.
        // C: `if(!port || !*port) port = "655";`. So `host:` (empty
        // port) and `host` (no colon) both default. C does both;
        // unusual but harmless.
        match addr_part.split_once(':') {
            Some((h, p)) if !p.is_empty() => (h.to_owned(), p.to_owned()),
            Some((h, _empty)) => (h.to_owned(), String::from("655")),
            None => (addr_part.to_owned(), String::from("655")),
        }
    };

    if host.is_empty() {
        return None;
    }

    // C: `if(!b64decode_tinc(slash, hash, 24) || !b64decode_tinc(slash+24, cookie, 24))`
    // parse_slug already KAT-tested; it does the length check and
    // alphabet check.
    let (key_hash, cookie) = parse_slug(slug)?;

    Some(ParsedUrl {
        host,
        port,
        key_hash,
        cookie: Zeroizing::new(cookie),
    })
}

// finalize_join — the testable seam

/// Result of consuming an invitation blob. The pubkey goes back over
/// SPTPS (type-1 record); the rest is informational.
///
/// Why this isn't `()`: `finalize_join` doesn't touch the SPTPS
/// connection — that's a layer above. It returns what the SPTPS
/// layer needs to send. C has `sptps_send_record(&sptps, 1, b64_pubkey,
/// strlen(b64_pubkey))` *inside* `finalize_join` (`invitation.c:1004`)
/// because `sptps` is a global there. We split: `finalize_join` is
/// pure-fs, the caller does the send.
#[derive(Debug)]
pub struct JoinResult {
    /// `Name = X` from chunk 1, line 1. The new node's name.
    pub name: String,
    /// The new node's pubkey, as the b64 string the daemon expects.
    /// `b64::encode(pk)`, 43 chars. Goes back as type-1 record body.
    /// NOT secret — it's the public key.
    pub pubkey_b64: String,
    /// Names of host files written from secondary chunks. For tests
    /// and for the binary's "Configuration stored" summary. C doesn't
    /// surface this; we do because it's free.
    pub hosts_written: Vec<String>,
}

/// Parse `data` and write a fresh confbase. `invitation.c:723-1129`.
///
/// `data` is the invitation file body (what `cmd_invite` wrote, what
/// `protocol_auth.c::receive_invitation_sptps` sends). Chunk 1 is
/// the new node's bootstrap config, filtered through `VAR_SAFE`;
/// chunks 2+ are host files, separated by `Name = X` lines.
///
/// `force = false` → unsafe vars dropped with a warning (the default).
/// `force = true` → unsafe vars accepted with a warning. Same gate
/// as `cmd_import`'s `--force`. The C checks the global `force`
/// directly (`invitation.c:913`).
///
/// Preconditions the caller must check (the C does these in
/// `cmd_join` before the SPTPS loop, `invitation.c:1227-1243`):
/// - `paths.confbase` is writable (or creatable)
/// - `paths.tinc_conf()` does NOT already exist
///
/// We re-check the second one because TOCTOU between `cmd_join`'s
/// check and this call is possible (the SPTPS handshake takes
/// nonzero time). But the first one is on the caller — if `makedir`
/// fails here, you get a fs error mid-write, not a clean "no
/// permission" up front.
///
/// # Errors
/// - `BadInput`: blob is malformed (no `Name = X` first line, invalid
///   name, secondary chunk would clobber our own host file).
/// - `Io`: any filesystem write.
///
/// # Panics
/// Only via `keypair::generate`'s `OsRng::fill_bytes` if the OS
/// entropy source is broken.
// Sequence of distinct steps sharing local state (open file handles,
// the line iterator). C `finalize_join` is 400 lines for the same
// reason; it does it with goto.
#[allow(clippy::too_many_lines)]
pub fn finalize_join(data: &[u8], paths: &Paths, force: bool) -> Result<JoinResult, CmdError> {
    // ─── Validate blob is text
    // The C treats `data` as a NUL-terminated C string
    // (`strchr(*data, '\n')`, `strlen(*data)`). Embedded NUL would
    // truncate the C parser silently. We accept any UTF-8 (which
    // includes ASCII, which is all the file should be). Non-UTF-8
    // → bail; better than silently truncating.
    //
    // Why not `&str` parameter: the SPTPS receive path delivers
    // `Vec<u8>` (it doesn't know the payload is text). The
    // bytes→str is the SPTPS↔config boundary.
    let data = std::str::from_utf8(data)
        .map_err(|_| CmdError::BadInput("Invitation data is not valid UTF-8".into()))?;

    // ─── Parse first chunk's first line: must be `Name = OURNAME`
    // C `invitation.c:724`: `name = get_value(data, "Name");`
    // `get_value` parses the *first* line and checks if it's the
    // requested key. Not a search — first-line-only. So the
    // invitation file format is rigid: `Name = X` MUST be line 1.
    // `cmd_invite` writes it that way (`invite.rs:build_invitation_file`
    // emits `Name` first). The contract test pins this.
    let mut lines = data.lines();
    let first = lines
        .next()
        .ok_or_else(|| CmdError::BadInput("No Name found in invitation!".into()))?;
    let name = parse_name_line(first)
        .ok_or_else(|| CmdError::BadInput("No Name found in invitation!".into()))?;

    // C: `if(!check_id(name)) bail`.
    if !check_id(name) {
        return Err(CmdError::BadInput(
            "Invalid Name found in invitation!".into(),
        ));
    }
    let name = name.to_owned();

    // ─── NetName: ignored
    // C `invitation.c:735-749`: if no `-n` was given, grep blob for
    // `NetName`, set the global, then re-derive paths. We don't do
    // dynamic path re-derivation (Paths is immutable, by design).
    // The caller already picked confbase via `-c` or `-n`. If the
    // blob's `NetName` disagrees with what they picked, the join
    // succeeds anyway — the netname is just a directory name, not a
    // wire concept. The C's loop is for "I didn't pick a netname,
    // use the one from the invite"; we say "pick one".
    //
    // The `NetName` line in chunk 1 is *recognized* (not "unknown
    // variable") and dropped, same as C `else if(!strcasecmp(l,
    // "NetName")) continue;` (`invitation.c:870`).

    // ─── Check tinc.conf doesn't exist
    // C `invitation.c:767`: `if(!access(tinc_conf, F_OK))`. The
    // join_XXXXXXXX random-netname dance is here in C; we just bail.
    let tinc_conf = paths.tinc_conf();
    if tinc_conf.exists() {
        return Err(CmdError::BadInput(format!(
            "Configuration file {} already exists!",
            tinc_conf.display()
        )));
    }

    // ─── makedirs(DIR_HOSTS | DIR_CONFBASE | DIR_CACHE)
    // C `invitation.c:781`. Same mode 0755 as init.
    if let Some(confdir) = &paths.confdir {
        makedir(confdir, 0o755)?;
    }
    makedir(&paths.confbase, 0o755)?;
    makedir(&paths.hosts_dir(), 0o755)?;
    makedir(&paths.cache_dir(), 0o755)?;

    // ─── Open three output files
    // C `invitation.c:785-830`. tinc.conf, hosts/NAME, invitation-data
    // (raw blob for debugging). The C also opens `tinc-up.invitation`
    // for `ifconfig_*`; we write a placeholder later, no streaming
    // build.
    //
    // Keep `fh` (hosts/NAME) open across the chunk-1 loop AND the
    // keygen step — the pubkey goes in *after* the chunk-1 vars,
    // matching C's write order. Close `f` (tinc.conf) right after
    // chunk 1.
    let mut f = fs::File::create(&tinc_conf).map_err(io_err(&tinc_conf))?;
    // C `invitation.c:792`: `fprintf(f, "Name = %s\n", name);`.
    // FIRST line of tinc.conf. Everything else is appended below.
    writeln!(f, "Name = {name}").map_err(io_err(&tinc_conf))?;

    let host_file = paths.host_file(&name);
    let mut fh = fs::File::create(&host_file).map_err(io_err(&host_file))?;

    // C `invitation.c:804-819`: `invitation-data` — the raw blob,
    // for debugging "what did the daemon send?". Write the whole
    // thing now; nothing reads it programmatically.
    let inv_data_path = paths.confbase.join("invitation-data");
    fs::write(&inv_data_path, data).map_err(io_err(&inv_data_path))?;

    // ─── Chunk 1: filter through variables[]
    // C `invitation.c:841-922`. The hand-rolled tokenizer again
    // (sixth instance). We use `vars::lookup`.
    //
    // The loop semantics are subtle. C's `while((l = get_line(...)))`
    // walks until `Name = X` where X != name (chunk boundary), `break`.
    // Then the `while(l && !strcasecmp(l, "Name"))` loop picks up
    // *with l still set to that Name line*. We replicate by tracking
    // the current line across the chunk-1/chunk-2 boundary via
    // `lines.by_ref()` — chunk 1 loop pushes the boundary line back
    // by storing it.
    let mut boundary: Option<(&str, &str)> = None; // (name_of_next_chunk, value)

    for line in lines.by_ref() {
        // C: `if(*l == '#') continue;`. Skip comments. The separator
        // line `#---...---#` starts with `#` and is correctly skipped.
        if line.starts_with('#') {
            continue;
        }

        // C tokenizer: `len = strcspn(l, "\t ="); value = l + len;
        // value += strspn(value, "\t "); if(*value == '=')
        // value += 1 + strspn(value+1, "\t "); l[len] = 0;`
        // Splits at first of `\t` ` ` `=`, then skips ws+`=`+ws to
        // the value. `Port=655` → key="Port", val="655". `Port =
        // 655` → same. `Port655` → key="Port655", val="".
        let Some((key, val)) = split_var(line) else {
            // Empty key: C `if(!*l) continue;`. Blank lines, ws-only.
            continue;
        };

        // C: `if(!strcasecmp(l, "Name")) { if(strcmp(value, name))
        // break; else continue; }`.
        // `Name = ourname` → skip (already wrote it). `Name = other`
        // → chunk boundary, exit loop with `boundary` set.
        if key.eq_ignore_ascii_case("Name") {
            if val == name {
                continue;
            }
            boundary = Some((key, val));
            break;
        }

        // C: `else if(!strcasecmp(l, "NetName")) continue;`.
        // Recognized, dropped. See comment above.
        if key.eq_ignore_ascii_case("NetName") {
            continue;
        }

        // C: lookup in `variables[]`. `for(i...) if(!strcasecmp)
        // { found=true; break; }`.
        let Some(var) = vars::lookup(key) else {
            // C: `if(!strcasecmp(l, "Ifconfig")) { ... } else if
            // ("Route") { ... }`. Then `fprintf("Ignoring unknown")`.
            // We recognize Ifconfig/Route (so no "unknown" warning)
            // but stub the action.
            if key.eq_ignore_ascii_case("Ifconfig") || key.eq_ignore_ascii_case("Route") {
                // TODO(ifconfig.c port): generate platform-specific
                // shell commands in tinc-up.invitation. -300 LOC.
                // For now: silent no-op. The placeholder tinc-up
                // (written below) covers the "you need to configure
                // your interface" message.
                continue;
            }
            // C: `fprintf(stderr, "Ignoring unknown variable '%s' in invitation.\n", l);`
            eprintln!("Ignoring unknown variable '{key}' in invitation.");
            continue;
        };

        // C: `if(!(variables[i].type & VAR_SAFE)) { if(force) warn;
        // else { warn; continue; } }`. Non-SAFE vars are an attack
        // vector (the inviter could set `ScriptsInterpreter = /bin/sh`
        // and own you). `--force` is the "I trust this inviter" knob.
        if !var.flags.contains(VarFlags::SAFE) {
            if force {
                eprintln!("Warning: unsafe variable '{key}' in invitation.");
            } else {
                eprintln!("Ignoring unsafe variable '{key}' in invitation.");
                continue;
            }
        }

        // C: `fprintf((variables[i].type & VAR_HOST) ? fh : f,
        // "%s = %s\n", l, value);`. HOST vars → hosts/NAME, SERVER
        // vars → tinc.conf. Dual-tagged (SERVER|HOST) go to
        // hosts/NAME since `& VAR_HOST` matches — e.g. `Subnet` from
        // the inviter goes to our host file (it's our subnet).
        //
        // We write `var.name` (canonical case from the table), not
        // `key` (what the inviter wrote). C writes `l`, which after
        // the tokenizer is the original case. We canonicalize. The
        // daemon's config reader is case-insensitive so this doesn't
        // change behavior; it just normalizes the output. Same
        // canonicalization as `cmd_set` will do.
        let target = if var.flags.contains(VarFlags::HOST) {
            &mut fh
        } else {
            &mut f
        };
        writeln!(target, "{} = {}", var.name, val).map_err(io_err(&tinc_conf))?;
    }

    // tinc.conf done. Close before the chunk-2 loop opens more files.
    drop(f);

    // ─── Chunk 2+: host files, unfiltered
    // C `invitation.c:928-972`. Each chunk is `Name = X\n` then
    // verbatim lines until the next `Name = X` or EOF. The separator
    // `#--...--#` is recognized and dropped (`strcmp(l, SEPARATOR)`).
    //
    // "Unfiltered" means no `variables[]` check. The host file is
    // a *peer's* config; you don't filter what a peer publishes
    // about themselves. (You DO filter what they tell you about
    // YOUR config — that's chunk 1.)
    //
    // C's loop structure: outer `while(l && Name)` { open file;
    // inner `while(get_line)` until next Name; close }. `l` carries
    // across iterations. We do the same with `boundary` carrying.
    let mut hosts_written = Vec::new();

    while let Some((_, host_name)) = boundary.take() {
        // C: `if(!check_id(value)) { fprintf("Invalid Name"); return false; }`.
        if !check_id(host_name) {
            return Err(CmdError::BadInput(
                "Invalid Name found in invitation.".into(),
            ));
        }
        // C: `if(!strcmp(value, name)) { fprintf("would overwrite");
        // return false; }`. Secondary chunk with our own name would
        // clobber the hosts/NAME we just opened. Malicious inviter
        // detection.
        if host_name == name {
            return Err(CmdError::BadInput(
                "Secondary chunk would overwrite our own host config file.".into(),
            ));
        }

        let host_path = paths.host_file(host_name);
        let mut hf = fs::File::create(&host_path).map_err(io_err(&host_path))?;
        hosts_written.push(host_name.to_owned());

        // Inner loop: lines until next `Name = X` or EOF.
        for line in lines.by_ref() {
            // C: `if(!strcmp(l, "#--...--#")) continue;`. Exact match
            // — the separator. (Regular `#` comments are NOT skipped
            // here, unlike chunk 1. The host file is verbatim.)
            if line == super::invite::SEPARATOR {
                continue;
            }

            // C tokenizer for `Name = X` detection: `len =
            // strcspn(l, "\t ="); if(len == 4 && !strncasecmp(l,
            // "Name", 4)) { ...; break; }`. Only checks if the
            // FIRST token is exactly "Name" (4 chars). `Namespace
            // = foo` passes through (len=9). Same as the strcspn
            // dance in `copy_host_replacing_port`.
            //
            // We use `split_var` (the chunk-1 tokenizer) and check
            // for "Name". split_var's `=` handling differs slightly
            // from the C's len==4 check (split_var splits AT `=`,
            // C's strcspn here splits AT `\t =` so len includes
            // chars before any of those). For `Name = X` and
            // `Name=X`: both tokenizers produce key="Name". Good
            // enough — `cmd_invite` writes the canonical form.
            if let Some((k, v)) = split_var(line) {
                if k.eq_ignore_ascii_case("Name") {
                    boundary = Some((k, v));
                    break;
                }
            }

            // C: `fputs(l, f); fputc('\n', f);`. The C `get_line`
            // strips the newline; `fputc` adds it back. We're
            // iterating `.lines()` which also strips, so add back.
            // (Yes, this means a host file with no trailing newline
            // *gains* one. C does the same. Harmless.)
            writeln!(hf, "{line}").map_err(io_err(&host_path))?;
        }
    }

    // ─── Generate our real node key
    // C `invitation.c:975-1005`. Same as `init`: PEM private key at
    // 0600, b64 pubkey as config line in hosts/NAME. The pubkey goes
    // back over SPTPS so the daemon writes our hosts entry on its end.
    //
    // The C also writes RSA here under `#ifndef DISABLE_LEGACY`. Nope.
    let sk = keypair::generate();
    let pubkey_b64 = b64::encode(sk.public_key());

    {
        let priv_path = paths.ed25519_private();
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let f = opts.open(&priv_path).map_err(io_err(&priv_path))?;
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::pem::write_pem(&mut w, "ED25519 PRIVATE KEY", &sk.to_blob())
            .map_err(io_err(&priv_path))?;
        w.flush().map_err(io_err(&priv_path))?;
    }

    // C: `fprintf(fh, "Ed25519PublicKey = %s\n", b64_pubkey);`.
    // Appended *after* whatever chunk-1 HOST vars went in.
    writeln!(fh, "Ed25519PublicKey = {pubkey_b64}").map_err(io_err(&host_file))?;
    drop(fh);

    // ─── Write tinc-up placeholder
    // C `invitation.c:1112-1126` (the no-ifconfig branch):
    // `rename(tinc-up.invitation, tinc-up); chmod(tinc-up, 0755)`.
    // We write directly. Same content as `init`'s placeholder
    // (`init.rs:243-269`). The `Ifconfig`/`Route` lines from chunk 1
    // would have populated this with real commands; we write the
    // "edit me" comment instead.
    write_tinc_up_placeholder(paths)?;

    Ok(JoinResult {
        name,
        pubkey_b64,
        hosts_written,
    })
}

/// `init.rs`'s tinc-up content, lifted. Mode 0755, `O_EXCL`.
///
/// Not factored to a shared helper because the two call sites have
/// different surrounding context (init is the only writer; join might
/// later grow ifconfig.c integration that writes a *different* body).
/// Dead-code rule applies: unify when there's a third caller.
fn write_tinc_up_placeholder(paths: &Paths) -> Result<(), CmdError> {
    let path = paths.tinc_up();
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o755);
    }
    let mut f = opts.open(&path).map_err(io_err(&path))?;
    // Same body as init. The C `ifconfig_footer` writes a similar
    // "configure your interface" comment when no Ifconfig/Route
    // were given (`ifconfig.c:54-71`).
    writeln!(f, "#!/bin/sh").map_err(io_err(&path))?;
    writeln!(f, "echo 'Unconfigured tinc-up script, please edit '$0'!'").map_err(io_err(&path))?;

    // chmod after write because umask may have stripped the x bit
    // from the create mode. C does `chmod(filename2, 0755)` after
    // rename for the same reason.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).map_err(io_err(&path))?;
    }
    Ok(())
}

/// Parse the `Name = X` line specifically. C `get_value(data, "Name")`.
///
/// Returns `Some(value)` only if the line's key is `Name` (case-
/// insensitive). Unlike `split_var`, this checks the key.
fn parse_name_line(line: &str) -> Option<&str> {
    let (k, v) = split_var(line)?;
    if k.eq_ignore_ascii_case("Name") {
        Some(v)
    } else {
        None
    }
}

/// The C tokenizer. `strcspn(l, "\t =")` then `strspn` past `\t `,
/// then optionally `=`, then `strspn` past `\t ` again.
///
/// `Port = 655` → ("Port", "655"). `Port=655` → ("Port", "655").
/// `Port` → ("Port", ""). `  ` → None. `# comment` → ("#", "comment")
/// — the caller checks `starts_with('#')` first.
///
/// Returns `None` only for empty key (C `if(!*l) continue;`).
fn split_var(line: &str) -> Option<(&str, &str)> {
    // Find end of key: first of \t, space, =. The C `strcspn` set.
    let key_end = line.find(['\t', ' ', '=']).unwrap_or(line.len());
    let key = &line[..key_end];
    if key.is_empty() {
        return None;
    }

    // Skip past the separator. C: `value += strspn(value, "\t ");
    // if(*value == '=') value += 1 + strspn(value+1, "\t ");`
    let rest = &line[key_end..];
    let rest = rest.trim_start_matches([' ', '\t']);
    let rest = rest.strip_prefix('=').unwrap_or(rest);
    let val = rest.trim_start_matches([' ', '\t']);

    Some((key, val))
}

// In-process server stub (test seam + daemon seed)

/// What the daemon's `receive_invitation_sptps` does, minus daemon
/// state. C `protocol_auth.c:185-310`.
///
/// This is the *seed* for the daemon's invitation handler (per the
/// plan). The daemon version will take `&mut Connection` instead of
/// `&Paths`, and the `name` extracted from the file will go into
/// `c->name`. But the cookie→filename recovery, the rename-to-.used,
/// the file read, the Name validation — same code. When the daemon
/// lands, this function moves to `tincd::auth` mostly unchanged.
///
/// Exposed `pub(crate)` for the in-process roundtrip test. NOT
/// `pub` — it's not API surface yet.
///
/// Returns: (file contents, name from first line, .used path).
/// The caller pumps `contents` over SPTPS as type-0 records, sends
/// type-1 zero-len, receives the joiner's pubkey as type-1, writes
/// `hosts/NAME`, sends type-2 zero-len. We split the steps because
/// the SPTPS pumping is the test harness's job, not this function's.
///
/// `myname` is the daemon's own name — `protocol_auth.c:277` checks
/// `!strcmp(name, myself->name)` and bails (you can't invite yourself).
///
/// `now` parameterized for tests (the expiry check). C uses
/// `now.tv_sec`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn server_receive_cookie(
    paths: &Paths,
    inv_key: &SigningKey,
    cookie: &[u8; COOKIE_LEN],
    myname: &str,
    now: std::time::SystemTime,
) -> Result<(Vec<u8>, String, std::path::PathBuf), CmdError> {
    use tinc_crypto::invite::cookie_filename;

    // C `protocol_auth.c:201-207`: recover filename from cookie+key.
    // KAT-tested in tinc-crypto::invite — this is the same
    // composition `cmd_invite` used to *name* the file.
    let filename = cookie_filename(cookie, inv_key.public_key());
    let inv_path = paths.invitations_dir().join(&filename);
    let used_path = paths.invitations_dir().join(format!("{filename}.used"));

    // C `protocol_auth.c:216-223`: atomic rename to .used.
    // Single-use: a second join with the same cookie hits ENOENT
    // here. The .used file is unlinked at the end (`:305`); if the
    // daemon crashes between rename and unlink, the .used file
    // sits there as evidence. (The expiry sweep skips it: 24 chars
    // + ".used" = 29, doesn't match the 24-char filter.)
    fs::rename(&inv_path, &used_path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            CmdError::BadInput("non-existing invitation".into())
        } else {
            CmdError::Io {
                path: inv_path,
                err: e,
            }
        }
    })?;

    // C `protocol_auth.c:226-237`: stat for mtime, check against
    // `now - invitation_lifetime`. Daemon uses `invitation_lifetime`
    // config var; we use the same week default as the sweep.
    let meta = fs::metadata(&used_path).map_err(io_err(&used_path))?;
    let mtime = meta
        .modified()
        .map_err(|_| CmdError::BadInput("cannot read mtime".into()))?;
    let deadline = now
        .checked_sub(super::invite::EXPIRY)
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    if mtime < deadline {
        return Err(CmdError::BadInput("expired invitation".into()));
    }

    // C `protocol_auth.c:240-257`: read first line, parse `Name = X`.
    // The C does this with a hand-rolled tokenizer (yes, again). We
    // read the whole file (it's small — invite caps it at a few KB)
    // then `parse_name_line` on line 1.
    let contents = fs::read(&used_path).map_err(io_err(&used_path))?;
    let first_line = contents
        .iter()
        .position(|&b| b == b'\n')
        .map_or(&contents[..], |i| &contents[..i]);
    let first_line = std::str::from_utf8(first_line)
        .map_err(|_| CmdError::BadInput("Invalid invitation file".into()))?;

    // C `protocol_auth.c:277`: `!*buf || !*name || strcasecmp(buf,
    // "Name") || !check_id(name) || !strcmp(name, myself->name)`.
    // All five checks in one error.
    let chunk_name = parse_name_line(first_line)
        .filter(|n| check_id(n))
        .filter(|n| *n != myname)
        .map(str::to_owned)
        .ok_or_else(|| CmdError::BadInput("Invalid invitation file".into()))?;

    Ok((contents, chunk_name, used_path))
}

// cmd_join — the TCP+SPTPS shell

/// `tinc join URL`. `invitation.c:1218`.
///
/// `paths` should be a *fresh* confbase (no `tinc.conf`). The C
/// checks this in `cmd_join` itself (`invitation.c:1239`):
/// `if((netname || confbasegiven) && !access(tinc_conf, F_OK)) bail`.
/// We check via `finalize_join` (which re-checks), but doing it up
/// front means failure happens *before* we open a TCP connection
/// and burn a single-use cookie on the daemon side.
///
/// # Errors
/// - `BadInput`: bad URL, daemon greeting wrong, key_hash mismatch,
///   blob parse failed.
/// - `Io`: connect/read/write failed, fs writes from `finalize_join`.
///
/// # Panics
/// Only via `keypair::generate`'s entropy source.
// Sequence of distinct steps sharing local state (sockets, SPTPS
// pump, accumulated blob). C `cmd_join` is one function for the
// same reason — the steps share too much state to split cleanly.
#[allow(clippy::too_many_lines)]
pub fn join(url: &str, paths: &Paths, force: bool) -> Result<(), CmdError> {
    // ─── Parse URL
    let parsed =
        parse_url(url).ok_or_else(|| CmdError::BadInput("Invalid invitation URL.".into()))?;

    // ─── Preflight: confbase must be fresh
    // C `invitation.c:1227-1243`. Do this BEFORE connecting — the
    // cookie is single-use on the daemon side (rename to .used). If
    // we connect, send cookie, daemon renames, then WE fail on
    // "tinc.conf exists" — the invitation is burned.
    //
    // makedirs(DIR_CONFDIR | DIR_CONFBASE) — C creates them here
    // (and `finalize_join` re-creates with HOSTS|CACHE). We need
    // confbase to exist for the `access` check below.
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
    // C `invitation.c:1315`. This key is ONLY for the SPTPS handshake;
    // it's not the node's identity. The daemon doesn't store it.
    // (The real node key is generated inside `finalize_join`.)
    let throwaway = keypair::generate();
    let throwaway_b64 = b64::encode(throwaway.public_key());

    // ─── Connect
    // C `invitation.c:1323-1360`: getaddrinfo loop, try each addr.
    // `TcpStream::connect((host, port))` does the same loop
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
    // C `invitation.c:1368-1398`. Two lines out, two lines in.
    //
    // OUT: "0 ?<throwaway-pubkey-b64> 17.1\n"
    //   `0` = ID request type. `?` prefix tells `id_h` "invitation".
    //   `17.1` = PROT_MAJOR.PROT_MINOR_SENT. The minor is dead (daemon
    //   overwrites it), but C sends `1` so we send `1`.
    let greeting = format!("0 ?{throwaway_b64} {PROT_MAJOR}.{PROT_MINOR_SENT}\n");
    sock.write_all(greeting.as_bytes())
        .map_err(io_err("send"))?;

    // IN line 1: "0 <daemon-name> 17.x\n" — daemon's send_id.
    // IN line 2: "4 <invitation-pubkey-b64>\n" — daemon's ACK with key.
    //
    // `BufStream` would be cleaner but we need byte-level control
    // for the SPTPS phase (any over-read past the second \n would
    // eat SPTPS handshake bytes — that's `blen` in the C, the
    // leftover after the two recvline calls). So: hand-rolled
    // buffered reader that we can drain into the SPTPS pump.
    let mut buf = Vec::with_capacity(4096);
    let line1 = recv_line(&mut sock, &mut buf)?;
    let line2 = recv_line(&mut sock, &mut buf)?;

    // Parse line 1. C: `sscanf(line, "%d %4095s %d.%d", &code,
    // hisname, &hismajor, &hisminor) < 3 || code != 0 ||
    // hismajor != PROT_MAJOR || !check_id(hisname)`.
    //
    // We split on whitespace. The C `%s` consumes a single
    // non-whitespace token, so do we.
    parse_greeting_line1(&line1)?;

    // Parse line 2. C: `sscanf(line, "%d ", &code) != 1 || code !=
    // ACK || strlen(line) < 3`. Then `fingerprint = line + 2`.
    //
    // The fingerprint is everything after `"4 "`. C's `+ 2` skips
    // `"4 "` (one digit, one space). We slice the same way.
    let fingerprint = parse_greeting_line2(&line2)?;

    // ─── Verify key_hash
    // C `invitation.c:1400-1410`. The whole point of the URL's first
    // 24 chars: prove the daemon holds the invitation key.
    //
    // `fingerprint_hash`, not `key_hash`: `key_hash` takes a raw
    // pubkey and re-b64s it. The daemon sent us the b64 string
    // directly; hashing it directly is `key_hash`'s body. The C
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
    // C `invitation.c:1424`: `sptps_start(&sptps, NULL, true, false,
    // key, hiskey, "tinc invitation", 15, invitation_send,
    // invitation_receive)`.
    //
    // initiator=true (we connected), datagram=false (TCP stream).
    // replaywin=0 (stream mode ignores it; matches the C harness).
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
    // The C structure is callback-based: `invitation_send` writes
    // to sock, `invitation_receive` accumulates type-0, calls
    // `finalize_join` on type-1, sets `success=true` on type-2.
    // We do the same with explicit state in this loop.
    //
    // The `buf` from the meta-greeting may have leftover bytes (the
    // first SPTPS record could've arrived in the same recv as line 2).
    // C handles this with `sptps_receive_data(&sptps, buffer, blen)`
    // immediately after sptps_start. We feed `buf` first, then loop
    // on recv.

    let mut data: Vec<u8> = Vec::new(); // accumulated type-0 records
    let mut success = false;
    let mut pubkey_to_send: Option<String> = None;
    let mut joined_name: Option<String> = None;

    // Helper: push outputs onto sock + state. Returns the type-1
    // record body that needs to go back (the pubkey), if any.
    // Factored as a closure so the state variables are in scope.
    macro_rules! drain {
        ($outputs:expr) => {{
            for o in $outputs {
                match o {
                    Output::Wire { bytes, .. } => {
                        sock.write_all(&bytes).map_err(io_err("send"))?;
                    }
                    Output::Record { record_type, bytes } => match record_type {
                        // C `invitation_receive` (`invitation.c:1152`):
                        // case 0: accumulate.
                        0 => {
                            if data.len() + bytes.len() > MAX_DATA {
                                return Err(CmdError::BadInput(
                                    "Invitation data exceeds size limit".into(),
                                ));
                            }
                            data.extend_from_slice(&bytes);
                        }
                        // case 1: finalize. C calls `finalize_join()`
                        // which has `sptps_send_record(&sptps, 1,
                        // b64_pubkey, ...)` *inside* it. We split:
                        // finalize returns the pubkey, we send.
                        1 => {
                            let r = finalize_join(&data, paths, force)?;
                            pubkey_to_send = Some(r.pubkey_b64);
                            joined_name = Some(r.name);
                        }
                        // case 2: server acked our pubkey. Done.
                        // C: `success = true; shutdown(sock, SHUT_RDWR)`.
                        2 => {
                            eprintln!("Invitation successfully accepted.");
                            success = true;
                        }
                        // C: `default: return false;` — unexpected
                        // record type kills the SPTPS callback, which
                        // makes `sptps_receive_data` return false.
                        _ => {
                            return Err(CmdError::BadInput(format!(
                                "Unexpected record type {record_type} from server"
                            )));
                        }
                    },
                    Output::HandshakeDone => {
                        // C `case SPTPS_HANDSHAKE: return
                        // sptps_send_record(&sptps, 0, cookie, sizeof
                        // cookie)`. Handshake done → send cookie.
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

    // Feed leftover from greeting buf, if any. C `invitation.c:1428`:
    // `sptps_receive_data(&sptps, buffer, blen)`.
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

    // Main recv loop. C `invitation.c:1433-1470`.
    let mut chunk = vec![0u8; 4096];
    while !success {
        let n = sock.read(&mut chunk).map_err(|e| {
            CmdError::BadInput(format!(
                "Error reading data from {} port {}: {e}",
                parsed.host, parsed.port
            ))
        })?;
        if n == 0 {
            // Peer closed before we got type-2. C: `while(...recv...)`
            // exits on 0, then `if(!success) fprintf("cancelled")`.
            break;
        }

        // Append to buf (which may have a partial record from earlier).
        buf.extend_from_slice(&chunk[..n]);

        // Feed to SPTPS until it consumes everything (or stalls on
        // partial). C `invitation.c:1458-1467`: `while(len) { done =
        // sptps_receive_data(...); len -= done; }`.
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

    // C `invitation.c:1128`: `fprintf(stderr, "Configuration stored
    // in: %s\n", confbase);`.
    eprintln!("Configuration stored in: {}", paths.confbase.display());
    if let Some(name) = joined_name {
        eprintln!("Joined as: {name}");
    }

    Ok(())
}

/// Read one line from `sock` into a returned String, using `buf` as
/// the leftover accumulator. C `recvline` (`tincctl.c:499-534`).
///
/// `buf` carries bytes between calls — `recv()` may deliver multiple
/// lines (or a line plus the start of SPTPS data) in one syscall. The
/// C uses static `buffer[4096]`/`blen` for the same reason; we make
/// the state explicit.
///
/// The line is returned WITHOUT the trailing `\n`. C does the same
/// (`line[len] = 0` where len is the offset of `\n`).
fn recv_line(sock: &mut TcpStream, buf: &mut Vec<u8>) -> Result<String, CmdError> {
    loop {
        // C: `while(!(newline = memchr(buffer, '\n', blen)))`.
        if let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            // C: `memcpy(line, buffer, len); line[len] = 0;
            // memmove(buffer, newline+1, blen-len-1); blen -= len+1;`
            let line: Vec<u8> = buf.drain(..=nl).take(nl).collect();
            return String::from_utf8(line)
                .map_err(|_| CmdError::BadInput("Cannot read greeting from peer".into()));
        }

        // C `tincctl.c:511`: `recv(fd, buffer+blen, sizeof buffer
        // - blen, 0)`. We grow `buf` (no fixed cap; the lines are
        // short, ~60 bytes, so this isn't a DoS surface — and we
        // bail at 4096 just in case).
        if buf.len() >= 4096 {
            return Err(CmdError::BadInput("Cannot read greeting from peer".into()));
        }

        let mut chunk = [0u8; 1024];
        let n = sock.read(&mut chunk).map_err(io_err("recv"))?;
        if n == 0 {
            return Err(CmdError::BadInput("Cannot read greeting from peer".into()));
        }
        buf.extend_from_slice(&chunk[..n]);
    }
}

/// Validate `"0 NAME 17.x"` greeting. Returns `()` because we only
/// care that it's well-formed; the daemon's *name* and *minor*
/// don't affect anything (the C reads them and discards). C
/// `invitation.c:1383`.
fn parse_greeting_line1(line: &str) -> Result<(), CmdError> {
    let bad = || CmdError::BadInput("Cannot read greeting from peer".into());

    let mut tok = line.split_ascii_whitespace();
    // `code` must be 0 (= ID).
    let code: u32 = tok.next().ok_or_else(bad)?.parse().map_err(|_| bad())?;
    if code != 0 {
        return Err(bad());
    }
    // `hisname` must pass check_id. C: `!check_id(hisname)`.
    let his_name = tok.next().ok_or_else(bad)?;
    if !check_id(his_name) {
        return Err(bad());
    }
    // `hismajor` must equal PROT_MAJOR. Minor is don't-care: the C
    // sscanf `%d.%d` on "17\0" stops at the `.` mismatch but still
    // returns 3 (the mismatch is after 3 conversions). So minor is
    // optional. We replicate: parse `MAJOR` or `MAJOR.MINOR`.
    let ver = tok.next().ok_or_else(bad)?;
    let major: u32 = ver
        .split('.')
        .next()
        .unwrap_or(ver)
        .parse()
        .map_err(|_| bad())?;
    if major != PROT_MAJOR {
        return Err(bad());
    }
    Ok(())
}

/// Extract fingerprint from `"4 FINGERPRINT"`. C `invitation.c:1391`.
///
/// Returns the fingerprint as `&str` borrowing from the input — we
/// hash it immediately, no need to own.
fn parse_greeting_line2(line: &str) -> Result<&str, CmdError> {
    let bad = || CmdError::BadInput("Cannot read greeting from peer".into());

    // C: `sscanf(line, "%d ", &code) != 1 || code != ACK ||
    // strlen(line) < 3`. The trailing space in `"%d "` matches
    // zero-or-more whitespace. So `"4X"` parses `4` and leaves `X`.
    // The `strlen >= 3` is "4 " plus at least one fingerprint char.
    //
    // We're stricter: split on first space, check first token is "4".
    // `"4X"` would fail here (no space). The daemon always sends
    // `"4 FINGERPRINT"` (`protocol_auth.c:364`: `send_request(c,
    // "%d %s", ACK, mykey)` — `send_request` adds a space between
    // `%d` and `%s`).
    let (code, rest) = line.split_once(' ').ok_or_else(bad)?;
    let code: u32 = code.parse().map_err(|_| bad())?;
    if code != ACK || rest.is_empty() {
        return Err(bad());
    }
    // C: `fingerprint = line + 2`. Same as `rest`.
    Ok(rest)
}

// Tests

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::cmd::init;
    use crate::cmd::invite;
    use crate::names::PathsInput;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::time::SystemTime;
    use tinc_crypto::invite::SLUG_PART_LEN;

    fn paths_at(dir: &Path) -> Paths {
        Paths::for_cli(&PathsInput {
            confbase: Some(dir.to_owned()),
            ..Default::default()
        })
    }

    // parse_url

    /// `parse_url` Ok-path table: `(prefix, expected_host, expected_port)`.
    /// The slug is appended; we only test host/port extraction here.
    #[test]
    fn url_ok() {
        let slug = "a".repeat(SLUG_LEN);
        #[rustfmt::skip]
        let cases: &[(&str, &str, &str)] = &[
            //          (prefix,               host,           port)
            ("host.example:1234/",  "host.example", "1234"),
            // default port
            ("host.example/",       "host.example", "655"),
            // IPv6 with brackets → brackets stripped
            ("[::1]:655/",          "::1",          "655"),
            // IPv6 no port
            ("[fe80::1]/",          "fe80::1",      "655"),
        ];
        for (prefix, host, port) in cases {
            let url = format!("{prefix}{slug}");
            let p = parse_url(&url).unwrap();
            assert_eq!(p.host, *host, "url: {url:?}");
            assert_eq!(p.port, *port, "url: {url:?}");
        }
    }

    #[test]
    fn url_roundtrip_with_invite() {
        // Real URL from invite() — proves the producer/consumer agree.
        let dir = tempfile::tempdir().unwrap();
        let inviter = paths_at(&dir.path().join("inviter"));
        init::run(&inviter, "alice").unwrap();
        let mut h = fs::OpenOptions::new()
            .append(true)
            .open(inviter.host_file("alice"))
            .unwrap();
        writeln!(h, "Address = vpn.example").unwrap();
        drop(h);

        let r = invite::invite(&inviter, None, "bob", SystemTime::now()).unwrap();
        let p = parse_url(&r.url).unwrap();
        assert_eq!(p.host, "vpn.example");
        assert_eq!(p.port, "655");

        // The key_hash from the URL must match the invitation key on
        // disk. (This is the same check `invite_full_flow` does, but
        // through `parse_url` instead of `parse_slug`.)
        let inv_key = keypair::read_private(&inviter.invitation_key()).unwrap();
        assert_eq!(
            p.key_hash,
            tinc_crypto::invite::key_hash(inv_key.public_key())
        );
    }

    #[test]
    fn url_err() {
        let long = "a".repeat(SLUG_LEN + 1);
        let bad_b64 = "!".repeat(SLUG_LEN); // `!` not in either b64 alphabet
        for url in [
            // bad slug length: short
            "host/short".to_owned(),
            // bad slug length: long
            format!("host/{long}"),
            // no slash at all
            "host:655".to_owned(),
            // 48 chars but not valid b64-url
            format!("host/{bad_b64}"),
        ] {
            assert!(parse_url(&url).is_none(), "url: {url:?}");
        }
    }

    // split_var — the C tokenizer

    #[test]
    fn split_var_forms() {
        assert_eq!(split_var("Port = 655"), Some(("Port", "655")));
        assert_eq!(split_var("Port=655"), Some(("Port", "655")));
        assert_eq!(split_var("Port\t655"), Some(("Port", "655")));
        assert_eq!(split_var("Port"), Some(("Port", "")));
        assert_eq!(split_var(""), None);
        assert_eq!(split_var(" "), None); // ws-only → empty key
        assert_eq!(split_var("=655"), None); // empty key (= at pos 0)
    }

    // greeting parsers

    #[test]
    fn greeting_line1() {
        assert!(parse_greeting_line1("0 alice 17.7").is_ok());
        assert!(parse_greeting_line1("0 alice 17").is_ok()); // no minor
        assert!(parse_greeting_line1("1 alice 17.7").is_err()); // wrong code
        assert!(parse_greeting_line1("0 alice 16.7").is_err()); // wrong major
        assert!(parse_greeting_line1("0 ../etc 17.7").is_err()); // bad name
        assert!(parse_greeting_line1("0 alice").is_err()); // no version
    }

    #[test]
    fn greeting_line2() {
        assert_eq!(parse_greeting_line2("4 SOMEKEY").unwrap(), "SOMEKEY");
        assert!(parse_greeting_line2("3 KEY").is_err()); // wrong code (3=CHAL_REPLY)
        assert!(parse_greeting_line2("4 ").is_err()); // empty fingerprint
        assert!(parse_greeting_line2("4").is_err()); // no space
    }

    // finalize_join — the testable seam

    /// Minimal valid blob: chunk 1 with Name only, no chunk 2.
    /// Shouldn't happen in practice (invite always emits chunk 2)
    /// but `finalize_join` must handle it — proves the chunk-2 loop
    /// is a `while`, not a `do while`.
    #[test]
    fn finalize_minimal_blob() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        let blob = b"Name = bob\n";
        let r = finalize_join(blob, &p, false).unwrap();

        assert_eq!(r.name, "bob");
        assert_eq!(r.pubkey_b64.len(), 43); // 32 bytes → 43 b64
        assert!(r.hosts_written.is_empty());

        // tinc.conf has just Name.
        assert_eq!(fs::read_to_string(p.tinc_conf()).unwrap(), "Name = bob\n");
        // hosts/bob has just the pubkey.
        let host = fs::read_to_string(p.host_file("bob")).unwrap();
        assert_eq!(host, format!("Ed25519PublicKey = {}\n", r.pubkey_b64));
        // Private key written, mode 0600, loadable.
        let mode = fs::metadata(p.ed25519_private())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let sk = keypair::read_private(&p.ed25519_private()).unwrap();
        // Pubkey from disk matches what's going back over SPTPS.
        assert_eq!(b64::encode(sk.public_key()), r.pubkey_b64);
    }

    /// `VAR_SAFE` filter. `Mode` is SERVER|SAFE → tinc.conf.
    /// `Subnet` is HOST|MULTIPLE|SAFE → hosts/bob.
    /// `Device` is SERVER but NOT SAFE → dropped (without --force).
    #[test]
    fn finalize_var_safe_filter() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        let blob = b"\
Name = bob
Mode = switch
Subnet = 10.0.0.2/32
Device = /dev/net/tun
ConnectTo = alice
";
        let r = finalize_join(blob, &p, false).unwrap();

        let conf = fs::read_to_string(p.tinc_conf()).unwrap();
        // Mode (SERVER|SAFE) → tinc.conf. ConnectTo too.
        assert!(conf.contains("Mode = switch\n"));
        assert!(conf.contains("ConnectTo = alice\n"));
        // Device NOT in tinc.conf — it's not SAFE, dropped.
        assert!(!conf.contains("Device"));

        let host = fs::read_to_string(p.host_file("bob")).unwrap();
        // Subnet (HOST|SAFE) → hosts/bob.
        assert!(host.contains("Subnet = 10.0.0.2/32\n"));
        // Ed25519PublicKey appended after.
        assert!(host.contains(&format!("Ed25519PublicKey = {}\n", r.pubkey_b64)));
    }

    /// `--force` accepts unsafe vars (with a warning, which we don't
    /// capture here — eprintln in lib code).
    #[test]
    fn finalize_force_accepts_unsafe() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        // Device is SERVER but not SAFE.
        let blob = b"Name = bob\nDevice = /dev/evil\n";
        finalize_join(blob, &p, true).unwrap();

        let conf = fs::read_to_string(p.tinc_conf()).unwrap();
        assert!(conf.contains("Device = /dev/evil\n"));
    }

    /// Unknown vars dropped silently (well, with eprintln, but no error).
    #[test]
    fn finalize_unknown_var_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        let blob = b"Name = bob\nNonexistentVariable = foo\n";
        finalize_join(blob, &p, false).unwrap();

        let conf = fs::read_to_string(p.tinc_conf()).unwrap();
        assert!(!conf.contains("Nonexistent"));
    }

    /// `Ifconfig`/`Route` are recognized (no "unknown variable" warning),
    /// not acted on (stub). The placeholder tinc-up is what gets written.
    #[test]
    fn finalize_ifconfig_recognized_stubbed() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        let blob = b"\
Name = bob
Ifconfig = 10.0.0.2/24
Route = 10.0.0.0/8
";
        finalize_join(blob, &p, false).unwrap();

        // Neither went anywhere — they're not in variables[], they're
        // not config lines. They WOULD have generated shell commands
        // in tinc-up.invitation. We just write the placeholder.
        let conf = fs::read_to_string(p.tinc_conf()).unwrap();
        assert!(!conf.contains("Ifconfig"));
        assert!(!conf.contains("Route"));

        // Placeholder tinc-up written, mode 0755.
        let up = p.tinc_up();
        let mode = fs::metadata(&up).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o755);
        let body = fs::read_to_string(up).unwrap();
        assert!(body.starts_with("#!/bin/sh"));
    }

    /// Chunk 2+: host files written verbatim (no SAFE filter), separator
    /// dropped, multiple chunks.
    #[test]
    fn finalize_secondary_chunks() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        let sep = invite::SEPARATOR;
        let blob = format!(
            "Name = bob\n\
             ConnectTo = alice\n\
             {sep}\n\
             Name = alice\n\
             Ed25519PublicKey = AAAA\n\
             Address = vpn.example\n\
             {sep}\n\
             Name = carol\n\
             Address = carol.example\n"
        );
        let r = finalize_join(blob.as_bytes(), &p, false).unwrap();

        assert_eq!(r.hosts_written, vec!["alice", "carol"]);

        // alice's host file: verbatim from chunk 2.
        let alice = fs::read_to_string(p.host_file("alice")).unwrap();
        assert_eq!(alice, "Ed25519PublicKey = AAAA\nAddress = vpn.example\n");
        // carol's: verbatim from chunk 3.
        let carol = fs::read_to_string(p.host_file("carol")).unwrap();
        assert_eq!(carol, "Address = carol.example\n");

        // bob's host file (chunk-1 HOST vars + pubkey): NO Address
        // (alice's Address went to alice's file, not bob's).
        let bob_host = fs::read_to_string(p.host_file("bob")).unwrap();
        assert!(!bob_host.contains("vpn.example"));
    }

    /// Secondary chunk with our own name → bail. Malicious inviter
    /// trying to clobber our host file. C `invitation.c:936`.
    ///
    /// The blob shape matters: `Name = bob\nName = bob\n...` does NOT
    /// trigger this — the second `Name = bob` matches `val == name`
    /// and is `continue`'d *inside chunk 1* (`invitation.c:868`).
    /// You can only get to the chunk-2 self-clobber check by first
    /// breaking chunk-1 on a *different* name. The attack vector is
    /// `chunk 2 = alice` (legit) then `chunk 3 = bob` (clobber).
    #[test]
    fn finalize_self_clobber_detected() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        // chunk 1: Name=bob. chunk 2: Name=alice (legit). chunk 3:
        // Name=bob — the clobber attempt.
        let blob = b"\
Name = bob
Name = alice
Address = x
Name = bob
Ed25519PublicKey = EVIL
";
        let err = finalize_join(blob, &p, false).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert!(msg.contains("overwrite our own"));
    }

    /// First line not `Name = X` → bail. C `get_value(data, "Name")`
    /// returns NULL.
    #[test]
    fn finalize_no_name() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        let err = finalize_join(b"Mode = switch\n", &p, false).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert!(msg.contains("No Name"));
    }

    /// Invalid name → bail. Same check_id as everywhere else.
    #[test]
    fn finalize_bad_name() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("vpn"));

        let err = finalize_join(b"Name = ../etc\n", &p, false).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert!(msg.contains("Invalid Name"));
    }

    /// tinc.conf already exists → bail before writing anything.
    #[test]
    fn finalize_existing_tinc_conf() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("vpn");
        let p = paths_at(&confbase);
        fs::create_dir_all(&confbase).unwrap();
        fs::write(p.tinc_conf(), "Name = existing\n").unwrap();

        let err = finalize_join(b"Name = bob\n", &p, false).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert!(msg.contains("already exists"));
        // Nothing else touched.
        assert!(!p.host_file("bob").exists());
    }

    // server_receive_cookie — the daemon stub

    /// Full server-side flow on a real invitation file from invite().
    #[test]
    fn server_stub_recovers_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("inviter"));
        init::run(&p, "alice").unwrap();
        let mut h = fs::OpenOptions::new()
            .append(true)
            .open(p.host_file("alice"))
            .unwrap();
        writeln!(h, "Address = x").unwrap();
        drop(h);

        let r = invite::invite(&p, None, "bob", SystemTime::now()).unwrap();
        let parsed = parse_url(&r.url).unwrap();
        let inv_key = keypair::read_private(&p.invitation_key()).unwrap();

        let (contents, name, used_path) =
            server_receive_cookie(&p, &inv_key, &parsed.cookie, "alice", SystemTime::now())
                .unwrap();

        assert_eq!(name, "bob");
        // First line is `Name = bob`.
        let s = std::str::from_utf8(&contents).unwrap();
        assert!(s.starts_with("Name = bob\n"));
        // The .used file exists, original is gone.
        assert!(used_path.exists());
        // The C uses `.used` literally (`protocol_auth.c:213` snprintf);
        // case-sensitive is the port-faithful comparison.
        #[allow(clippy::case_sensitive_file_extension_comparisons)]
        let has_used = used_path.to_str().unwrap().ends_with(".used");
        assert!(has_used);
    }

    /// Single-use: second call with same cookie → ENOENT → "non-existing".
    #[test]
    fn server_stub_single_use() {
        let dir = tempfile::tempdir().unwrap();
        let p = paths_at(&dir.path().join("inviter"));
        init::run(&p, "alice").unwrap();
        let mut h = fs::OpenOptions::new()
            .append(true)
            .open(p.host_file("alice"))
            .unwrap();
        writeln!(h, "Address = x").unwrap();
        drop(h);

        let r = invite::invite(&p, None, "bob", SystemTime::now()).unwrap();
        let parsed = parse_url(&r.url).unwrap();
        let inv_key = keypair::read_private(&p.invitation_key()).unwrap();

        // First use: ok.
        server_receive_cookie(&p, &inv_key, &parsed.cookie, "alice", SystemTime::now()).unwrap();
        // Second use: file is gone (renamed to .used).
        let err = server_receive_cookie(&p, &inv_key, &parsed.cookie, "alice", SystemTime::now())
            .unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert!(msg.contains("non-existing"));
    }

    // The CONTRACT TEST: full invite ↔ join roundtrip, in-process

    /// **The contract.** invite() writes a file → server stub reads
    /// it → SPTPS ping-pong → finalize_join writes a confbase →
    /// the confbase loads. No subprocess. No real socket. Two
    /// `Sptps` structs ping-ponging.
    ///
    /// This is the proof that:
    /// 1. The invitation file format `cmd_invite` writes is the
    ///    format `finalize_join` reads. (`build_invitation_file` ↔
    ///    `finalize_join`'s parser agree on chunk boundaries,
    ///    SAFE filter, etc.)
    /// 2. The SPTPS record-type protocol (0=data, 1=finalize,
    ///    2=ack) works end-to-end with our SPTPS state machine.
    /// 3. The cookie→filename recovery in `server_receive_cookie`
    ///    matches `cmd_invite`'s filename derivation. (Already KAT-
    ///    tested in `tinc-crypto`, but this is the integration.)
    /// 4. The pubkey we send back is the one on disk.
    ///
    /// What this DOESN'T test: the meta-greeting exchange, the TCP
    /// layer. Those need a real socket. The integration test in
    /// `tinc_cli.rs` (when the daemon stub gets a listen socket)
    /// will cover those. For now, the SPTPS layer + format layer
    /// are the high-value seams.
    #[test]
    #[allow(
        // The test is long because it transcribes the full SPTPS
        // protocol — 4-phase handshake, cookie, file chunks, pubkey
        // echo, ack — with assertions at each step. Splitting would
        // mean threading 8 pieces of state through helpers; the
        // monolith is the readable form. Same justification as the
        // C `cmd_join` itself (also one function).
        clippy::too_many_lines,
        // ServerPhase enum defined inside the test body, after the
        // setup vars. Moving it before the `let dir = ...` would
        // separate it from its sole use site by 60 lines.
        clippy::items_after_statements,
    )]
    fn invite_join_roundtrip_in_process() {
        let dir = tempfile::tempdir().unwrap();

        // ─── Inviter side: alice invites bob
        let inviter = paths_at(&dir.path().join("inviter"));
        init::run(&inviter, "alice").unwrap();
        {
            let mut h = fs::OpenOptions::new()
                .append(true)
                .open(inviter.host_file("alice"))
                .unwrap();
            writeln!(h, "Address = vpn.example").unwrap();
        }
        // Add a Mode (SERVER|SAFE) so we exercise the chunk-1 filter.
        {
            let mut tc = fs::OpenOptions::new()
                .append(true)
                .open(inviter.tinc_conf())
                .unwrap();
            writeln!(tc, "Mode = switch").unwrap();
        }

        let inv_result = invite::invite(&inviter, Some("acme"), "bob", SystemTime::now()).unwrap();
        let parsed = parse_url(&inv_result.url).unwrap();

        // Load invitation key. Both the server stub and the joiner's
        // SPTPS need it (server uses it as identity; joiner uses
        // its pubkey to verify key_hash and as `hiskey`).
        let inv_key = keypair::read_private(&inviter.invitation_key()).unwrap();
        let inv_pub = *inv_key.public_key();

        // ─── Joiner setup
        let joiner_paths = paths_at(&dir.path().join("joiner"));
        let throwaway = keypair::generate();
        let throwaway_pub = *throwaway.public_key();

        // ─── Start both SPTPS sessions
        // Joiner = initiator. Server = responder. Stream framing.
        // Same label, same as the C wire bytes.
        let (mut joiner, j_init) = Sptps::start(
            Role::Initiator,
            Framing::Stream,
            throwaway,
            inv_pub,
            INVITE_LABEL,
            0,
            &mut OsRng,
        );
        let (mut server, s_init) = Sptps::start(
            Role::Responder,
            Framing::Stream,
            // The server's full SigningKey is the invitation key.
            // We just loaded it; clone via blob roundtrip (no Clone
            // on SigningKey, by design — keys shouldn't be copied
            // casually).
            SigningKey::from_blob(&inv_key.to_blob()),
            throwaway_pub,
            INVITE_LABEL,
            0,
            &mut OsRng,
        );

        // ─── The pump
        // Two unidirectional byte queues. `Output::Wire` from one
        // side → enqueue → `receive()` on the other. Loop until both
        // queues are empty AND no new wire bytes were produced
        // (steady state).
        //
        // State tracked across the loop, mirroring the C globals:
        //   data: type-0 record accumulator (joiner side)
        //   server_phase: what the server expects next
        //   join_result: filled when type-1 arrives, used after loop
        //   success: type-2 arrived
        let mut to_server: Vec<u8> = Vec::new();
        let mut to_joiner: Vec<u8> = Vec::new();

        let mut data: Vec<u8> = Vec::new();
        let mut join_result: Option<JoinResult> = None;
        let mut success = false;

        // Server protocol state. The C uses `c->status.invitation_used`
        // to gate "have we sent the file yet". We're more explicit.
        #[derive(PartialEq, Debug)]
        enum ServerPhase {
            WaitCookie, // expect type-0 with cookie
            WaitPubkey, // file sent, expect type-1 with joiner's pubkey
            Done,       // type-2 sent
        }
        let mut server_phase = ServerPhase::WaitCookie;
        let mut joiner_pubkey: Option<String> = None;

        // Seed the queues with the initial KEX bytes from start().
        for o in j_init {
            if let Output::Wire { bytes, .. } = o {
                to_server.extend_from_slice(&bytes);
            }
        }
        for o in s_init {
            if let Output::Wire { bytes, .. } = o {
                to_joiner.extend_from_slice(&bytes);
            }
        }

        // Pending sends — records to push AFTER draining a receive's
        // outputs. We can't `send_record` *inside* the drain loop
        // because the drain loop is iterating Outputs from the same
        // Sptps. Same constraint as `pubkey_to_send` in `join()`.
        let mut joiner_pending: Vec<(u8, Vec<u8>)> = Vec::new();
        let mut server_pending: Vec<(u8, Vec<u8>)> = Vec::new();

        // Loop bound. The handshake is 4 round trips, the file is
        // a few records, the pubkey echo is 1. If we loop 100 times
        // something's wedged.
        for _iter in 0..100 {
            if to_server.is_empty()
                && to_joiner.is_empty()
                && joiner_pending.is_empty()
                && server_pending.is_empty()
            {
                break;
            }

            // ─── Server processes its inbox
            if !to_server.is_empty() {
                let inp = std::mem::take(&mut to_server);
                let mut off = 0;
                while off < inp.len() {
                    let (n, outs): (usize, Vec<Output>) =
                        server.receive(&inp[off..], &mut OsRng).unwrap();
                    if n == 0 {
                        to_server.extend_from_slice(&inp[off..]);
                        break;
                    }
                    off += n;
                    for o in outs {
                        match o {
                            Output::Wire { bytes, .. } => {
                                to_joiner.extend_from_slice(&bytes);
                            }
                            Output::HandshakeDone => {
                                // Server doesn't act on handshake-done;
                                // the joiner sends the cookie unprompted.
                                // C `protocol_auth.c:188`: `if(type ==
                                // 128) return true;` — swallow.
                            }
                            Output::Record {
                                record_type: 0,
                                bytes,
                            } if server_phase == ServerPhase::WaitCookie => {
                                // C `protocol_auth.c:196`: `if(type !=
                                // 0 || len != 18) return false;`.
                                assert_eq!(bytes.len(), COOKIE_LEN);
                                let mut cookie = [0u8; COOKIE_LEN];
                                cookie.copy_from_slice(&bytes);

                                // Recover the file. (KAT-tested
                                // composition.)
                                let (contents, name, used) = server_receive_cookie(
                                    &inviter,
                                    &inv_key,
                                    &cookie,
                                    "alice",
                                    SystemTime::now(),
                                )
                                .unwrap();
                                assert_eq!(name, "bob");

                                // C `protocol_auth.c:294-301`: send
                                // file in 1024-byte chunks as type-0.
                                // We chunk at 512 to exercise the
                                // joiner's accumulator (proves it
                                // handles multi-record data).
                                for chunk in contents.chunks(512) {
                                    server_pending.push((0, chunk.to_vec()));
                                }
                                // C `:303`: type-1, zero-len. The
                                // "finalize" trigger.
                                server_pending.push((1, Vec::new()));
                                // C `:305`: `unlink(usedname)`.
                                fs::remove_file(used).unwrap();
                                server_phase = ServerPhase::WaitPubkey;
                            }
                            Output::Record {
                                record_type: 1,
                                bytes,
                            } if server_phase == ServerPhase::WaitPubkey => {
                                // C `protocol_auth.c:192`: `return
                                // finalize_invitation(c, data, len)`.
                                // Body: `fprintf(f, "Ed25519PublicKey
                                // = %s\n", data)` then `sptps_send
                                // _record(&c->sptps, 2, data, 0)`.
                                let pk = String::from_utf8(bytes).unwrap();
                                assert_eq!(pk.len(), 43);
                                joiner_pubkey = Some(pk);
                                // type-2, zero-len. The ack.
                                server_pending.push((2, Vec::new()));
                                server_phase = ServerPhase::Done;
                            }
                            Output::Record { record_type, .. } => {
                                panic!(
                                    "unexpected server-side record type {record_type} \
                                     in phase {server_phase:?}"
                                );
                            }
                        }
                    }
                }
            }

            // Flush server's pending sends.
            for (ty, body) in server_pending.drain(..) {
                for o in server.send_record(ty, &body).unwrap() {
                    if let Output::Wire { bytes, .. } = o {
                        to_joiner.extend_from_slice(&bytes);
                    }
                }
            }

            // ─── Joiner processes its inbox
            // This is `cmd_join`'s SPTPS loop, transcribed for in-
            // process testing. Same structure: type-0 accumulate,
            // type-1 finalize, type-2 success.
            if !to_joiner.is_empty() {
                let inp = std::mem::take(&mut to_joiner);
                let mut off = 0;
                while off < inp.len() {
                    let (n, outs): (usize, Vec<Output>) =
                        joiner.receive(&inp[off..], &mut OsRng).unwrap();
                    if n == 0 {
                        to_joiner.extend_from_slice(&inp[off..]);
                        break;
                    }
                    off += n;
                    for o in outs {
                        match o {
                            Output::Wire { bytes, .. } => {
                                to_server.extend_from_slice(&bytes);
                            }
                            Output::HandshakeDone => {
                                // Send cookie. C `invitation.c:1154`.
                                joiner_pending.push((0, parsed.cookie.to_vec()));
                            }
                            Output::Record {
                                record_type: 0,
                                bytes,
                            } => {
                                data.extend_from_slice(&bytes);
                            }
                            Output::Record { record_type: 1, .. } => {
                                // The seam.
                                let r = finalize_join(&data, &joiner_paths, false).unwrap();
                                joiner_pending.push((1, r.pubkey_b64.clone().into_bytes()));
                                join_result = Some(r);
                            }
                            Output::Record { record_type: 2, .. } => {
                                success = true;
                            }
                            Output::Record { record_type, .. } => {
                                panic!("unexpected joiner record type {record_type}");
                            }
                        }
                    }
                }
            }

            for (ty, body) in joiner_pending.drain(..) {
                for o in joiner.send_record(ty, &body).unwrap() {
                    if let Output::Wire { bytes, .. } = o {
                        to_server.extend_from_slice(&bytes);
                    }
                }
            }
        }

        // ─── Asserts
        assert!(success, "type-2 never arrived; pump stalled");
        assert_eq!(server_phase, ServerPhase::Done);
        let r = join_result.unwrap();

        // 1. Joiner's confbase is populated. tinc.conf has Name +
        //    Mode (the SAFE var that threaded through).
        let conf = fs::read_to_string(joiner_paths.tinc_conf()).unwrap();
        assert!(conf.starts_with("Name = bob\n"));
        assert!(conf.contains("Mode = switch\n"));
        assert!(conf.contains("ConnectTo = alice\n"));

        // 2. Joiner's hosts/alice has alice's pubkey (from chunk 2).
        //    This is the "secondary chunk written verbatim" half.
        let alice_host = fs::read_to_string(joiner_paths.host_file("alice")).unwrap();
        assert!(alice_host.contains("Ed25519PublicKey = "));
        assert!(alice_host.contains("Address = vpn.example"));

        // 3. Joiner's private key loads. Same key as the pubkey
        //    that went back over SPTPS.
        let sk = keypair::read_private(&joiner_paths.ed25519_private()).unwrap();
        assert_eq!(b64::encode(sk.public_key()), r.pubkey_b64);
        assert_eq!(joiner_pubkey.unwrap(), r.pubkey_b64);

        // 4. Joiner's hosts/bob has bob's pubkey — the same one.
        let bob_host = fs::read_to_string(joiner_paths.host_file("bob")).unwrap();
        assert!(bob_host.contains(&format!("Ed25519PublicKey = {}\n", r.pubkey_b64)));

        // 5. Inviter's invitation file is GONE (renamed + unlinked).
        //    Single-use enforced.
        let inv_dir = inviter.invitations_dir();
        let leftover: Vec<_> = fs::read_dir(&inv_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n.len() == SLUG_PART_LEN)
            .collect();
        assert!(
            leftover.is_empty(),
            "invitation file should be consumed: {leftover:?}"
        );

        // 6. fsck passes on the joiner's confbase. The contract:
        //    join produces a confbase that fsck approves of. If join
        //    ever writes something fsck flags, this fires.
        let report = crate::cmd::fsck::run(&joiner_paths, false).unwrap();
        assert!(
            report.ok,
            "join should produce fsck-clean confbase: {:?}",
            report.findings
        );
    }
}
