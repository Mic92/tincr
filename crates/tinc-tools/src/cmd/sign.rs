//! `cmd_sign` + `cmd_verify`.
//!
//! Detached-ish signature over an arbitrary file. NOT a PEM envelope.
//! NOT GPG-style ASCII armor. Format:
//!
//! ```text
//! Signature = <name> <unix-time> <86-char-tinc-b64>\n
//! <file contents, byte-exact>
//! ```
//!
//! The header is exactly one line, exactly that `sscanf` shape. The
//! body is the original file, unmodified — `verify` strips the header
//! and writes the rest to stdout, so `sign | verify` is identity on
//! the file contents.
//!
//! ## The signed message is NOT what's in the output
//!
//! This is the load-bearing subtlety. The signature input is:
//!
//! ```text
//! <file_contents> || " " || <name> || " " || <unix_time>
//! ```
//!
//! Note the **leading space** before name. That space is in the
//! format, not an artifact. The trailer is appended after the file
//! bytes, then signed. The trailer is **not** in the output — only
//! in the signature input.
//!
//! The trailer binds name+time inside the signed message; without it
//! they'd be unsigned header metadata, freely rewritable. The leading
//! space is a separator between file contents and trailer. No
//! trailing newline on the trailer.
//!
//! ## `verify`'s signer argument
//!
//! - `.` → own name (`get_my_name`). "Verify this was signed by me."
//! - `*` → any. Use the `<name>` from the header, look up
//!   `hosts/<name>` for the pubkey. "Verify this was signed by
//!   *someone we know*."
//! - anything else → `check_id`, then must `strcmp`-match the header's
//!   `<name>`. "Verify this was signed specifically by alice."
//!
//! The `*` case is the interesting one — it's how you'd verify a
//! signature without knowing in advance who signed it (you trust your
//! `hosts/` directory as a keyring).
//!
//! ## `get_pubkey`
//!
//! We use `tinc-conf::parse_file`, falling back to a PEM block for
//! host files without an `Ed25519PublicKey =` config line.
//!
//! ## Time parameterized for tests
//!
//! Time is a parameter for deterministic golden-output tests; the
//! binary wrapper supplies `SystemTime::now()`.
//!
//! ## Replicated quirks
//!
//! - File slurped whole (no size limit). Don't sign 10 GB files.
//! - `verify` writes nothing on failure.
//! - 2048 cap on header line — malformed-input sanity check.
//! - `t == 0` rejected. Defensive; unreachable on the happy path.

use std::io::{Read, Write};
use std::path::Path;

use crate::cmd::exchange::get_my_name;
use crate::cmd::{CmdError, io_err};
use crate::keypair;
use crate::names::{Paths, check_id};

use tinc_crypto::b64;
use tinc_crypto::sign::{PUBLIC_LEN, SIG_LEN, verify};

/// 64-byte raw signature → 86-char tinc-b64. `ceil(64 * 4 / 3) = 86`.
/// `const _:` is the no-runtime-cost form of asserting our arithmetic
/// matches. If `SIG_LEN` changes (it won't — Ed25519 signatures are
/// 64 bytes by definition) this fails at compile time.
const SIG_B64_LEN: usize = 86;
const _: () = assert!((SIG_LEN * 4).div_ceil(3) == SIG_B64_LEN);

/// Header (without the `\n`) longer than 2048 bytes is rejected. Our
/// parsed line is already without the `\n` (we slice at it).
const MAX_HEADER_LEN: usize = 2048;

/// Slurp `path` or stdin. `path = None` → stdin.
fn slurp(path: Option<&Path>) -> Result<Vec<u8>, CmdError> {
    let mut buf = Vec::new();
    match path {
        Some(p) => {
            std::fs::File::open(p)
                .and_then(|mut f| f.read_to_end(&mut buf))
                .map_err(io_err(p))?;
        }
        None => {
            std::io::stdin()
                .read_to_end(&mut buf)
                .map_err(io_err("<stdin>"))?;
        }
    }
    Ok(buf)
}

/// Build the signed message: `data || " " || name || " " || t`.
/// **Leading space is load-bearing** — see module doc.
///
/// `t` formatted decimal, no padding. `name` is already validated
/// (`get_my_name` runs `check_id`; `verify` runs `check_id(signer)`).
/// No spaces in `name`, no ambiguity — but nobody parses the trailer
/// anyway. It's signed-then-discarded.
fn signed_message(data: &[u8], name: &str, t: i64) -> Vec<u8> {
    use std::fmt::Write as _;
    // Preallocate. `data.len()` for the body + `1 + name.len() + 1
    // + 20` for the trailer (space + name + space + up to 20 digits
    // for an i64). Slightly over; `Vec` doesn't care.
    let mut msg = Vec::with_capacity(data.len() + name.len() + 22);
    msg.extend_from_slice(data);
    // The trailer. `write!` into a `Vec<u8>` would need a wrapper;
    // easier to format into a `String` then push the bytes. The
    // trailer is short (sub-100 bytes); the alloc is one-shot.
    let mut trailer = String::with_capacity(name.len() + 22);
    write!(trailer, " {name} {t}").unwrap(); // String write never fails
    msg.extend_from_slice(trailer.as_bytes());
    msg
}

/// `cmd_sign`. The header + body, written to `out`.
///
/// `t` is the unix time to embed. Caller supplies the current time;
/// tests supply a fixed value. `i64` — won't overflow until 292
/// billion years from now.
///
/// # Errors
///
/// `BadInput` if `tinc.conf` missing or no `Name`. `Io` for the
/// private key open or the input file open. **Not** for the signature
/// itself — `SigningKey::sign` returns `[u8; 64]` directly.
pub fn sign(paths: &Paths, input: Option<&Path>, t: i64, out: impl Write) -> Result<(), CmdError> {
    let name = get_my_name(paths)?;
    let sk = keypair::read_private(&paths.ed25519_private())
        .map_err(|e| CmdError::BadInput(e.to_string()))?;
    // `LoadError` → `BadInput` because there's no `Io` variant that
    // takes a pre-stringified inner error. `LoadError::Display`
    // already includes the path. Slight loss of structure (caller
    // can't `match` on Io-vs-Pem) but this is leaf-level — the caller
    // is the binary, which prints + exits.

    // ─── Slurp input
    let data = slurp(input)?;

    let msg = signed_message(&data, &name, t);
    let sig_raw = sk.sign(&msg);
    let sig_b64 = b64::encode(&sig_raw);
    // Sanity. `SIG_B64_LEN` const check at the top proves the
    // arithmetic; this proves `b64::encode` agrees with the
    // arithmetic. Belt and suspenders. If this ever fires, the
    // problem is in `tinc-crypto::b64`, not here.
    debug_assert_eq!(sig_b64.len(), SIG_B64_LEN);

    // ─── Emit
    // The body is the *original* `data`, NOT `msg` (which has the
    // trailer). Load-bearing.
    let mut out = out;
    writeln!(out, "Signature = {name} {t} {sig_b64}").map_err(io_err("<stdout>"))?;
    out.write_all(&data).map_err(io_err("<stdout>"))?;
    Ok(())
}

/// `verify`'s signer argument, post-resolution.
///
/// See module doc "`verify`'s signer argument". The `.` case is
/// resolved by the caller (it needs `Paths` for `get_my_name`, and
/// keeping `Paths` out of this enum keeps the parse pure). So by the
/// time we have a `Signer`, `.` is already a concrete name.
#[derive(Debug)]
pub enum Signer {
    /// `*` — accept any signer in `hosts/`. The header's `<name>` is
    /// looked up.
    Any,
    /// Specific name. Either user-supplied (and `check_id`-passed),
    /// or `.` resolved to own name.
    Named(String),
}

impl Signer {
    /// Parse the user-supplied arg. `paths` for the `.` case.
    ///
    /// # Errors
    ///
    /// `BadInput` if `arg` is neither `.` nor `*` and fails
    /// `check_id` (i.e., it's not a valid node name). `BadInput` if
    /// `.` and `tinc.conf` is missing/nameless (propagated from
    /// `get_my_name`).
    pub fn parse(arg: &str, paths: &Paths) -> Result<Self, CmdError> {
        // `.` then `*` then check_id. `.` and `*` are NOT validated
        // as names — they're metasyntax (and would fail `check_id`
        // anyway: not alnum-or-underscore).
        match arg {
            "." => Ok(Signer::Named(get_my_name(paths)?)),
            "*" => Ok(Signer::Any),
            name => {
                if check_id(name) {
                    Ok(Signer::Named(name.to_owned()))
                } else {
                    Err(CmdError::BadInput("Invalid node name".into()))
                }
            }
        }
    }
}

/// What `verify` discovers. The body (header-stripped input) and the
/// signer's name (relevant when `Signer::Any` — caller might want to
/// know *who* signed it). We return it so tests can assert on the
/// body without capturing stdout. The binary wrapper writes `body`
/// to stdout.
#[derive(Debug)]
pub struct Verified {
    /// The signer's name. For `Signer::Named(n)` this is just `n`.
    /// For `Signer::Any` it's whatever the header said.
    pub signer: String,
    /// The original signed file, byte-exact. Header line stripped,
    /// trailing newline (if the file had one) preserved.
    pub body: Vec<u8>,
}

/// `cmd_verify`. Validates the signature, returns the body.
///
/// # Errors
///
/// `BadInput("Invalid input")` for any header parse failure (no
/// newline, header too long, shape mismatch, sig length wrong,
/// `t == 0`, signer fails `check_id`). All bundled into one message.
///
/// `BadInput("Signature is not made by NAME")` if `Signer::Named` and
/// the header's signer doesn't match.
///
/// `BadInput("Invalid signature")` if the crypto fails. Covers both
/// b64-decode failure and Ed25519 verify failure.
///
/// `Io` for host-file open failure.
///
/// `BadInput("Could not read public key from PATH")` if the host file
/// exists but has neither `Ed25519PublicKey =` line nor PEM block.
/// (Distinct from `Io` — the file opened fine, the contents are
/// wrong.)
pub fn verify_blob(paths: &Paths, signer: &Signer, blob: &[u8]) -> Result<Verified, CmdError> {
    // ─── Find the header line
    // No newline, or header too long → fail.
    let nl = blob
        .iter()
        .position(|&b| b == b'\n')
        .ok_or_else(|| CmdError::BadInput("Invalid input".into()))?;
    if nl > MAX_HEADER_LEN {
        return Err(CmdError::BadInput("Invalid input".into()));
    }
    // Header is `[0, nl)`, body is `[nl+1, end)`. The `\n` itself is
    // dropped — it's a separator, not part of either.
    let header = &blob[..nl];
    let body = &blob[nl + 1..];

    // ─── Parse header
    // Split on single spaces, expect exactly 5 fields:
    // `["Signature", "=", name, t, sig]`. Stricter than upstream's
    // sscanf (which accepts extra/missing whitespace), but sign
    // always emits the canonical form. The only way to get a
    // non-canonical header is hand-editing; the answer is "don't".
    let header =
        std::str::from_utf8(header).map_err(|_| CmdError::BadInput("Invalid input".into()))?;
    let mut fields = header.split(' ');
    let (Some("Signature"), Some("="), Some(signer_name), Some(t_str), Some(sig_b64), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(CmdError::BadInput("Invalid input".into()));
    };

    // Do this before b64-decode — cheaper, catches truncation early.
    if sig_b64.len() != SIG_B64_LEN {
        return Err(CmdError::BadInput("Invalid input".into()));
    }

    // `parse()` rejects trailing garbage. Same outcome as upstream
    // (non-digit after time is rejected), different layer.
    let t: i64 = t_str
        .parse()
        .map_err(|_| CmdError::BadInput("Invalid input".into()))?;
    if t == 0 {
        return Err(CmdError::BadInput("Invalid input".into()));
    }

    // Node names are alnum-or-underscore. A signer name with `/` or
    // `..` would let `*` mode read `hosts/../../../etc/passwd`.
    if !check_id(signer_name) {
        return Err(CmdError::BadInput("Invalid input".into()));
    }

    // ─── Match signer
    let resolved_signer = match signer {
        Signer::Any => signer_name,
        Signer::Named(n) => {
            if n != signer_name {
                // Use `n` (what the user asked for) not `signer_name`
                // (what the blob claims).
                return Err(CmdError::BadInput(format!("Signature is not made by {n}")));
            }
            signer_name
        }
    };

    // ─── Load public key
    let host_path = paths.host_file(resolved_signer);
    let pubkey = load_host_pubkey(&host_path)?;

    // ─── Decode sig + reconstruct trailer + verify
    // Both b64-decode failure and Ed25519 verify failure map to
    // "Invalid signature".
    let sig_raw =
        b64::decode(sig_b64).ok_or_else(|| CmdError::BadInput("Invalid signature".into()))?;
    let sig_raw: [u8; SIG_LEN] = sig_raw
        .try_into()
        .map_err(|_| CmdError::BadInput("Invalid signature".into()))?;

    // Reconstruct the trailer using the *header's* signer name and
    // time — not anything the verifier knows independently. Correct:
    // the trailer is *inside* the signature, so if the header lies
    // about name/time, the reconstructed trailer differs from what
    // was signed, and verify fails. The signature *binds* the header
    // fields.
    let msg = signed_message(body, resolved_signer, t);

    verify(&pubkey, &msg, &sig_raw).map_err(|_| CmdError::BadInput("Invalid signature".into()))?;

    Ok(Verified {
        signer: resolved_signer.to_owned(),
        body: body.to_vec(),
    })
}

/// `cmd_verify`, full pipeline. Slurp + `verify_blob` + write body.
///
/// Separated from `verify_blob` so tests can supply the blob directly
/// without filesystem/stdin choreography.
///
/// # Errors
///
/// See [`verify_blob`]. Plus `Io` for input file open.
pub fn verify_cmd(
    paths: &Paths,
    signer: &Signer,
    input: Option<&Path>,
    out: impl Write,
) -> Result<(), CmdError> {
    let blob = slurp(input)?;
    let v = verify_blob(paths, signer, &blob)?;
    // Body, byte-exact. Only on success — error paths return before here.
    let mut out = out;
    out.write_all(&v.body).map_err(io_err("<stdout>"))?;
    Ok(())
}

/// Read `hosts/NAME`, look for `Ed25519PublicKey = <b64>`, fall back
/// to a `-----BEGIN ED25519 PUBLIC KEY-----` PEM block. We re-read
/// from the path for the fallback (kernel cached the inode).
fn load_host_pubkey(host_path: &Path) -> Result<[u8; PUBLIC_LEN], CmdError> {
    // ─── Try config-line form
    // `parse_file` errors on file-not-found. That's the right error
    // here (verify fails if you don't have `hosts/SIGNER`). The
    // `ReadError` Display includes the path.
    //
    // If the file *exists* but has *only* a PEM block (no config
    // lines), `parse_file` returns `Ok(vec![])` (PEM lines are
    // skipped — see `tinc-conf::parse_reader`'s "blank/comment BEFORE
    // PEM" ordering). Then `lookup` finds nothing, fall through.
    let cfg = tinc_conf::Config::read(host_path).map_err(|e| CmdError::BadInput(e.to_string()))?;

    if let Some(entry) = cfg.lookup("Ed25519PublicKey").next() {
        let raw = b64::decode(&entry.value).ok_or_else(|| {
            CmdError::BadInput(format!(
                "Could not read public key from {}",
                host_path.display()
            ))
        })?;
        let pk: [u8; PUBLIC_LEN] = raw.try_into().map_err(|_| {
            CmdError::BadInput(format!(
                "Could not read public key from {}",
                host_path.display()
            ))
        })?;
        return Ok(pk);
    }

    // ─── Fall back to PEM block
    // `keypair::read_public` does the open + read_pem + length check.
    // It errors `LoadError::Pem(NotFound)` if there's no PEM block.
    // That's our "neither form found" terminal error.
    keypair::read_public(host_path).map_err(|_| {
        // Don't expose `LoadError` details — the actionable info is
        // "this host file has no pubkey".
        CmdError::BadInput(format!(
            "Could not read public key from {}",
            host_path.display()
        ))
    })
}

// Tests

#[cfg(test)]
mod tests;
