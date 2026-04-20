//! `finalize_join` — parse the invitation blob and write a confbase.
//!
//! The testable seam: pure-filesystem, no network. Input is the
//! decrypted SPTPS payload; output is a `JoinResult` carrying what
//! needs to go back over the wire.

use std::fs;
use std::io::Write;

use tinc_conf::vars::{self, VarFlags};
use tinc_crypto::b64;

use crate::cmd::{CmdError, OpenKind, create_nofollow, io_err, makedir};
use crate::keypair;
use crate::names::{Paths, check_id};

use super::JoinResult;

/// Keys dropped from chunk-2 host blocks: paths/exec the daemon would
/// honour. Chunk-2 is otherwise written verbatim.
const CHUNK2_DROP_KEYS: &[&str] = &[
    "Proxy",
    "ScriptsInterpreter",
    "Ed25519PublicKeyFile",
    "Ed25519PrivateKeyFile",
    "PublicKeyFile",
    "PrivateKeyFile",
];

/// Parse `data` and write a fresh confbase.
///
/// `data` is the invitation file body (what `cmd_invite` wrote, what
/// the daemon's `receive_invitation_sptps` sends). Chunk 1 is the new
/// node's bootstrap config, filtered through `VAR_SAFE`; chunks 2+
/// are host files, separated by `Name = X` lines.
///
/// `force = false` → unsafe vars dropped with a warning (the default).
/// `force = true` → unsafe vars accepted with a warning. Same gate
/// as `cmd_import`'s `--force`.
///
/// Preconditions the caller must check (`cmd_join` does these before
/// the SPTPS loop):
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
// the line iterator). Upstream is 400 lines for the same reason; it
// does it with goto.
pub fn finalize_join(data: &[u8], paths: &Paths, force: bool) -> Result<JoinResult, CmdError> {
    let mut created: Vec<std::path::PathBuf> = Vec::new();
    let r = finalize_join_inner(data, paths, force, &mut created);
    if r.is_err() {
        // Best-effort rollback of files this run created.
        for p in created.iter().rev() {
            let _ = fs::remove_file(p);
        }
    }
    r
}

fn finalize_join_inner(
    data: &[u8],
    paths: &Paths,
    force: bool,
    created: &mut Vec<std::path::PathBuf>,
) -> Result<JoinResult, CmdError> {
    // ─── Validate blob is text
    // Upstream treats `data` as a NUL-terminated C string. Embedded
    // NUL would truncate the parser silently. We accept any UTF-8
    // (which includes ASCII, which is all the file should be).
    // Non-UTF-8 → bail; better than silently truncating.
    //
    // Why not `&str` parameter: the SPTPS receive path delivers
    // `Vec<u8>` (it doesn't know the payload is text). The
    // bytes→str is the SPTPS↔config boundary.
    let data = std::str::from_utf8(data)
        .map_err(|_| CmdError::BadInput("Invitation data is not valid UTF-8".into()))?;

    // ─── Parse first chunk's first line: must be `Name = OURNAME`
    // `get_value(data, "Name")` parses the *first* line and checks
    // if it's the requested key. Not a search — first-line-only. So
    // the invitation file format is rigid: `Name = X` MUST be line 1.
    // `cmd_invite` writes it that way (`invite.rs:build_invitation_
    // file` emits `Name` first). The contract test pins this.
    let mut lines = data.lines();
    let first = lines
        .next()
        .ok_or_else(|| CmdError::BadInput("No Name found in invitation!".into()))?;
    let name = parse_name_line(first)
        .ok_or_else(|| CmdError::BadInput("No Name found in invitation!".into()))?;

    if !check_id(name) {
        return Err(CmdError::BadInput(
            "Invalid Name found in invitation!".into(),
        ));
    }
    let name = name.to_owned();

    // ─── NetName: ignored
    // Upstream: if no `-n` was given, grep blob for `NetName`, set
    // the global, then re-derive paths. We don't do dynamic path
    // re-derivation (Paths is immutable, by design). The caller
    // already picked confbase via `-c` or `-n`. If the blob's
    // `NetName` disagrees with what they picked, the join succeeds
    // anyway — the netname is just a directory name, not a wire
    // concept. The upstream loop is for "I didn't pick a netname,
    // use the one from the invite"; we say "pick one".
    //
    // The `NetName` line in chunk 1 is *recognized* (not "unknown
    // variable") and dropped.

    // ─── Check tinc.conf doesn't exist
    // The join_XXXXXXXX random-netname dance is here upstream; we
    // just bail.
    let tinc_conf = paths.tinc_conf();
    if tinc_conf.exists() {
        return Err(CmdError::BadInput(format!(
            "Configuration file {} already exists!",
            tinc_conf.display()
        )));
    }

    // ─── makedirs(DIR_HOSTS | DIR_CONFBASE | DIR_CACHE)
    // Same mode 0755 as init.
    if let Some(confdir) = &paths.confdir {
        makedir(confdir, 0o755)?;
    }
    makedir(&paths.confbase, 0o755)?;
    makedir(&paths.hosts_dir(), 0o755)?;
    makedir(&paths.cache_dir(), 0o755)?;

    // ─── Open three output files
    // tinc.conf, hosts/NAME, invitation-data (raw blob for
    // debugging). Upstream also opens `tinc-up.invitation` for
    // `ifconfig_*`; we write a placeholder later, no streaming build.
    //
    // Keep `fh` (hosts/NAME) open across the chunk-1 loop AND the
    // keygen step — the pubkey goes in *after* the chunk-1 vars,
    // matching upstream's write order. Close `f` (tinc.conf) right
    // after chunk 1.
    let mut f = create_nofollow(&tinc_conf)?;
    created.push(tinc_conf.clone());
    // FIRST line of tinc.conf. Everything else is appended below.
    writeln!(f, "Name = {name}").map_err(io_err(&tinc_conf))?;

    let host_file = paths.host_file(&name);
    let mut fh = create_nofollow(&host_file)?;
    created.push(host_file.clone());

    // `invitation-data` — the raw blob, for debugging "what did the
    // daemon send?". Write the whole thing now; nothing reads it
    // programmatically.
    let inv_data_path = paths.confbase.join("invitation-data");
    fs::write(&inv_data_path, data).map_err(io_err(&inv_data_path))?;
    created.push(inv_data_path);

    // ─── Chunk 1: filter through variables[]
    // The hand-rolled tokenizer again (sixth instance). We use
    // `vars::lookup`.
    //
    // The loop semantics are subtle. Upstream walks until `Name = X`
    // where X != name (chunk boundary), `break`. Then the next loop
    // picks up *with l still set to that Name line*. We replicate by
    // tracking the current line across the chunk-1/chunk-2 boundary
    // via `lines.by_ref()` — chunk 1 loop pushes the boundary line
    // back by storing it.
    let mut boundary: Option<(&str, &str)> = None; // (name_of_next_chunk, value)

    for line in lines.by_ref() {
        // Skip comments. The separator line `#---...---#` starts
        // with `#` and is correctly skipped.
        if line.starts_with('#') {
            continue;
        }

        // The tokenizer: splits at first of `\t` ` ` `=`, then skips
        // ws+`=`+ws to the value. `Port=655` → key="Port", val="655".
        // `Port = 655` → same. `Port655` → key="Port655", val="".
        let Some((key, val)) = split_var(line) else {
            // Empty key: blank lines, ws-only.
            continue;
        };

        // `Name = ourname` → skip (already wrote it). `Name = other`
        // → chunk boundary, exit loop with `boundary` set.
        if key.eq_ignore_ascii_case("Name") {
            if val == name {
                continue;
            }
            boundary = Some((key, val));
            break;
        }

        // Recognized, dropped. See comment above.
        if key.eq_ignore_ascii_case("NetName") {
            continue;
        }

        let Some(var) = vars::lookup(key) else {
            // We recognize Ifconfig/Route (so no "unknown" warning)
            // but stub the action.
            if key.eq_ignore_ascii_case("Ifconfig") || key.eq_ignore_ascii_case("Route") {
                // TODO(ifconfig port): generate platform-specific
                // shell commands in tinc-up.invitation. -300 LOC.
                // For now: silent no-op. The placeholder tinc-up
                // (written below) covers the "you need to configure
                // your interface" message.
                continue;
            }
            eprintln!("Ignoring unknown variable {key:?} in invitation.");
            continue;
        };

        // Non-SAFE vars are an attack vector (the inviter could set
        // `ScriptsInterpreter = /bin/sh` and own you). `--force` is
        // the "I trust this inviter" knob.
        if !var.flags.contains(VarFlags::SAFE) {
            if force {
                eprintln!("Warning: unsafe variable {key:?} in invitation.");
            } else {
                eprintln!("Ignoring unsafe variable {key:?} in invitation.");
                continue;
            }
        }

        // HOST vars → hosts/NAME, SERVER vars → tinc.conf.
        // Dual-tagged (SERVER|HOST) go to hosts/NAME since
        // `& VAR_HOST` matches — e.g. `Subnet` from the inviter
        // goes to our host file (it's our subnet).
        //
        // We write `var.name` (canonical case from the table), not
        // `key` (what the inviter wrote). Upstream writes the
        // original case. We canonicalize. The daemon's config reader
        // is case-insensitive so this doesn't change behavior; it
        // just normalizes the output. Same canonicalization as
        // `cmd_set` will do.
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
    // Each chunk is `Name = X\n` then verbatim lines until the next
    // `Name = X` or EOF. The separator `#--...--#` is recognized and
    // dropped.
    //
    // "Unfiltered" means no `variables[]` check. The host file is
    // a *peer's* config; you don't filter what a peer publishes
    // about themselves. (You DO filter what they tell you about
    // YOUR config — that's chunk 1.)
    //
    // Loop structure: outer `while(l && Name)` { open file; inner
    // `while(get_line)` until next Name; close }. `l` carries across
    // iterations. We do the same with `boundary` carrying.
    let mut hosts_written = Vec::new();

    while let Some((_, host_name)) = boundary.take() {
        if !check_id(host_name) {
            return Err(CmdError::BadInput(
                "Invalid Name found in invitation.".into(),
            ));
        }
        // Secondary chunk with our own name would clobber the
        // hosts/NAME we just opened. Case-insensitive: `hosts/Bob`
        // and `hosts/bob` are the same inode on case-folding FS.
        if host_name.eq_ignore_ascii_case(&name) {
            return Err(CmdError::BadInput(
                "Secondary chunk would overwrite our own host config file.".into(),
            ));
        }

        let host_path = paths.host_file(host_name);
        let mut hf = create_nofollow(&host_path)?;
        created.push(host_path.clone());
        hosts_written.push(host_name.to_owned());

        // Inner loop: lines until next `Name = X` or EOF.
        for line in lines.by_ref() {
            // Exact match — the separator. (Regular `#` comments are
            // NOT skipped here, unlike chunk 1. The host file is
            // verbatim.)
            if line == crate::cmd::invite::SEPARATOR {
                continue;
            }

            // Upstream's tokenizer here only checks if the FIRST
            // token is exactly "Name" (4 chars). `Namespace = foo`
            // passes through (len=9).
            //
            // We use `split_var` (the chunk-1 tokenizer) and check
            // for "Name". Its `=` handling differs slightly from the
            // strcspn check (split_var splits AT `=`, the strcspn
            // here splits AT `\t =` so len includes chars before any
            // of those). For `Name = X` and `Name=X`: both produce
            // key="Name". Good enough — `cmd_invite` writes the
            // canonical form.
            if let Some((k, v)) = split_var(line) {
                if k.eq_ignore_ascii_case("Name") {
                    boundary = Some((k, v));
                    break;
                }
                if CHUNK2_DROP_KEYS.iter().any(|d| k.eq_ignore_ascii_case(d)) {
                    eprintln!(
                        "Ignoring unsafe variable '{k}' in invitation host file for {host_name}."
                    );
                    continue;
                }
            }

            // `.lines()` strips the newline; add it back. (Yes, this
            // means a host file with no trailing newline *gains* one.
            // Upstream does the same. Harmless.)
            writeln!(hf, "{line}").map_err(io_err(&host_path))?;
        }
    }

    // ─── Generate our real node key
    // Same as `init`: PEM private key at 0600, b64 pubkey as config
    // line in hosts/NAME. The pubkey goes back over SPTPS so the
    // daemon writes our hosts entry on its end.
    let sk = keypair::generate();
    let pubkey_b64 = b64::encode(sk.public_key());

    {
        let priv_path = paths.ed25519_private();
        crate::cmd::write_private_key(&priv_path, &sk, OpenKind::CreateExcl)?;
        created.push(priv_path);
    }

    // Appended *after* whatever chunk-1 HOST vars went in.
    writeln!(fh, "Ed25519PublicKey = {pubkey_b64}").map_err(io_err(&host_file))?;
    drop(fh);

    // ─── Write tinc-up placeholder (shared with `init`)
    if let Some(p) = crate::cmd::init::write_tinc_up_placeholder(paths)? {
        created.push(p);
    }

    Ok(JoinResult {
        name,
        pubkey_b64,
        hosts_written,
    })
}

/// Parse the `Name = X` line specifically.
///
/// Returns `Some(value)` only if the line's key is `Name` (case-
/// insensitive). Unlike `split_var`, this checks the key.
pub(super) fn parse_name_line(line: &str) -> Option<&str> {
    let (k, v) = split_var(line)?;
    if k.eq_ignore_ascii_case("Name") {
        Some(v)
    } else {
        None
    }
}

/// `tinc_conf::split_kv` plus the empty-key → `None` convention this
/// module's callers want. `# comment` → ("#", "comment") — callers
/// check `starts_with('#')` first.
pub(super) fn split_var(line: &str) -> Option<(&str, &str)> {
    let (key, val) = tinc_conf::split_kv(line);
    if key.is_empty() {
        None
    } else {
        Some((key, val))
    }
}
