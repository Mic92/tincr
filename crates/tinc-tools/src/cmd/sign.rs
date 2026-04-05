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

/// `cmd_verify`, full pipeline. Slurp + verify_blob + write body.
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
    let entries =
        tinc_conf::parse_file(host_path).map_err(|e| CmdError::BadInput(e.to_string()))?;
    let mut cfg = tinc_conf::Config::new();
    cfg.merge(entries);

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
mod tests {
    use super::*;
    use crate::names::PathsInput;
    use std::fs;

    /// Set up a confbase with `init`-equivalent contents: tinc.conf
    /// with `Name = NAME`, ed25519_key.priv, hosts/NAME with the
    /// pubkey config line. Same shape as `cmd::init::run` produces,
    /// but inline so we don't depend on init's correctness here.
    fn fake_init(dir: &tempfile::TempDir, name: &str) -> Paths {
        let confbase = dir.path().join(name);
        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase.clone()),
            ..Default::default()
        });

        fs::create_dir_all(confbase.join("hosts")).unwrap();
        fs::write(confbase.join("tinc.conf"), format!("Name = {name}\n")).unwrap();

        let sk = keypair::generate();
        // Private key PEM.
        let mut buf = Vec::new();
        tinc_conf::pem::write_pem(&mut buf, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
        fs::write(confbase.join("ed25519_key.priv"), buf).unwrap();
        // Host file with pubkey config line.
        fs::write(
            confbase.join("hosts").join(name),
            format!("Ed25519PublicKey = {}\n", b64::encode(sk.public_key())),
        )
        .unwrap();

        paths
    }

    /// **The contract test.** Sign, then verify. Body round-trips
    /// byte-exact. This is what `tinc sign | tinc verify .` does.
    #[test]
    fn sign_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        let data = b"hello world\nsecond line\n";
        // Write to a file (not stdin — testing the file path).
        let input = dir.path().join("payload");
        fs::write(&input, data).unwrap();

        let mut signed = Vec::new();
        sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

        // ─── Shape check on the output
        // First line is the header, rest is the body byte-exact.
        let nl = signed.iter().position(|&b| b == b'\n').unwrap();
        let header = std::str::from_utf8(&signed[..nl]).unwrap();
        assert!(header.starts_with("Signature = alice 1700000000 "));
        // Sig is the 5th space-separated field.
        let sig_b64 = header.rsplit(' ').next().unwrap();
        assert_eq!(sig_b64.len(), SIG_B64_LEN);
        // Body is the original data, byte-exact.
        assert_eq!(&signed[nl + 1..], data);

        // ─── Verify
        let v = verify_blob(&paths, &Signer::Named("alice".into()), &signed).unwrap();
        assert_eq!(v.signer, "alice");
        assert_eq!(v.body, data);
    }

    /// `Signer::Any` (`*`) — verify against whoever the header says.
    /// Uses the `verify_blob` seam (the blob is the testable layer;
    /// `verify_cmd` adds stdin-slurp on top, which blocks under test).
    #[test]
    fn verify_any_signer() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        let input = dir.path().join("payload");
        fs::write(&input, b"data").unwrap();
        let mut signed = Vec::new();
        sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

        // `*` accepts whatever the header says. Header says "alice".
        let v = verify_blob(&paths, &Signer::Any, &signed).unwrap();
        assert_eq!(v.signer, "alice");
        assert_eq!(v.body, b"data");
    }

    /// `Signer::Named` mismatch → `"Signature is not made by NAME"`.
    #[test]
    fn verify_signer_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        let input = dir.path().join("payload");
        fs::write(&input, b"data").unwrap();
        let mut signed = Vec::new();
        sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

        // We don't have `hosts/bob`, but the signer-mismatch check
        // runs *before* the pubkey load. So we hit the mismatch
        // error, not "no host file".
        let err = verify_blob(&paths, &Signer::Named("bob".into()), &signed).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!("wrong variant")
        };
        assert_eq!(msg, "Signature is not made by bob");
    }

    /// Tampered body → "Invalid signature". The signature binds the
    /// body; flip one byte and the crypto rejects it.
    #[test]
    fn verify_tampered_body() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        let input = dir.path().join("payload");
        fs::write(&input, b"hello").unwrap();
        let mut signed = Vec::new();
        sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

        // Flip the last byte (in the body, not the header).
        *signed.last_mut().unwrap() ^= 1;

        let err = verify_blob(&paths, &Signer::Any, &signed).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert_eq!(msg, "Invalid signature");
    }

    /// Tampered header time → "Invalid signature". The trailer
    /// (reconstructed from the header) is inside the signed message,
    /// so changing `t` in the header changes the trailer, which
    /// changes the message, which invalidates the sig.
    ///
    /// This is the test that proves the trailer scheme works. Without
    /// the trailer, time is unsigned metadata and you could rewrite
    /// it freely.
    #[test]
    fn verify_tampered_time() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        let input = dir.path().join("payload");
        fs::write(&input, b"hello").unwrap();
        let mut signed = Vec::new();
        sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();

        // Swap `1700000000` → `1700000001` in the header.
        let s = std::str::from_utf8(&signed).unwrap();
        let tampered = s.replace("1700000000", "1700000001");

        let err = verify_blob(&paths, &Signer::Any, tampered.as_bytes()).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert_eq!(msg, "Invalid signature");
    }

    /// Tampered signer name → also rejected. With `Signer::Any`, the
    /// header's name *is* trusted to pick the host file — but the
    /// signature was made over the *original* trailer with the
    /// *original* name, so changing the name in the header changes
    /// the reconstructed trailer, sig fails.
    ///
    /// (You'd also need a `hosts/evilname` file for the verify to
    /// even get to the crypto. We test with a name that *does* exist
    /// but has a different key — that's the realistic attack.)
    #[test]
    fn verify_tampered_signer_name() {
        let dir = tempfile::tempdir().unwrap();
        // Two nodes. alice signs; we tamper the header to say bob.
        let alice = fake_init(&dir, "alice");
        let bob = fake_init(&dir, "bob");

        let input = dir.path().join("payload");
        fs::write(&input, b"hello").unwrap();
        let mut signed = Vec::new();
        sign(&alice, Some(&input), 1_700_000_000, &mut signed).unwrap();

        // Tamper: header says bob now. We verify from bob's confbase
        // (which has hosts/bob, with bob's real pubkey).
        let s = std::str::from_utf8(&signed).unwrap();
        let tampered = s.replace("= alice ", "= bob ");

        // Bob's confbase. `Signer::Any` so it uses the header's name
        // → looks up hosts/bob → bob's pubkey. Sig was made by alice's
        // key over `... alice 1700000000`. Reconstructed trailer is
        // `... bob 1700000000`. Wrong key AND wrong message. Fails.
        let err = verify_blob(&bob, &Signer::Any, tampered.as_bytes()).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert_eq!(msg, "Invalid signature");
    }

    /// **Leading space in trailer is load-bearing.** Prove it: build
    /// the signed message *without* the leading space, sign it, verify
    /// fails (because `verify_blob` reconstructs the trailer *with*
    /// the space). This pins the format.
    #[test]
    fn trailer_leading_space() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");
        let sk = keypair::read_private(&paths.ed25519_private()).unwrap();

        let body = b"hello";
        // Build a *wrong* signed message (no leading space).
        let mut wrong_msg = Vec::from(&body[..]);
        wrong_msg.extend_from_slice(b"alice 1700000000"); // NO leading space
        let sig = sk.sign(&wrong_msg);
        let sig_b64 = b64::encode(&sig);

        // Assemble the blob: correct header, body. The sig is over
        // the spaceless trailer. Verify reconstructs *with* space →
        // different message → sig fails.
        let blob = format!("Signature = alice 1700000000 {sig_b64}\nhello");
        let err = verify_blob(&paths, &Signer::Any, blob.as_bytes()).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert_eq!(msg, "Invalid signature");

        // Contrast: with the space, it works. (This is the same as
        // the roundtrip test but reduced to first principles.)
        let mut right_msg = Vec::from(&body[..]);
        right_msg.extend_from_slice(b" alice 1700000000"); // WITH leading space
        let sig = sk.sign(&right_msg);
        let sig_b64 = b64::encode(&sig);
        let blob = format!("Signature = alice 1700000000 {sig_b64}\nhello");
        let v = verify_blob(&paths, &Signer::Any, blob.as_bytes()).unwrap();
        assert_eq!(v.body, body);
    }

    /// `signed_message` is the same function for sign and verify.
    /// Prove it directly: same inputs, same output. (Tautological for
    /// a single fn, but if someone refactors sign/verify to inline
    /// the trailer construction separately, this catches drift.)
    #[test]
    fn signed_message_format() {
        let msg = signed_message(b"data", "alice", 1_700_000_000);
        // Exact bytes. The trailer is ` alice 1700000000` (leading
        // space, no trailing newline).
        assert_eq!(msg, b"data alice 1700000000");

        // Empty body.
        let msg = signed_message(b"", "bob", 1);
        assert_eq!(msg, b" bob 1");

        // Body with no trailing newline (common for hand-typed files).
        // The space separates body from name regardless.
        let msg = signed_message(b"no newline at end", "carol", 999);
        assert_eq!(msg, b"no newline at end carol 999");
    }

    /// Header parse: malformed → "Invalid input". Not "Invalid
    /// signature" — that's reserved for crypto failure. The
    /// distinction matters for diagnostics: parse failure means the
    /// file isn't a tinc-signed file at all; crypto failure means it
    /// *looks* like one but the sig is wrong.
    #[test]
    fn verify_malformed_header() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        for bad in [
            // No newline at all.
            "no newline".as_bytes(),
            // Wrong prefix.
            b"NotSignature = alice 1 xxx\nbody",
            // Missing fields.
            b"Signature = alice 1\nbody",
            // Too many fields.
            b"Signature = alice 1 xxx extra\nbody",
            // Sig wrong length (85 not 86).
            format!("Signature = alice 1 {}\nbody", "x".repeat(85)).as_bytes(),
            // Time zero. `!t` check.
            format!("Signature = alice 0 {}\nbody", "x".repeat(86)).as_bytes(),
            // Time non-numeric.
            format!("Signature = alice notanumber {}\nbody", "x".repeat(86)).as_bytes(),
            // Signer fails check_id (has a dash).
            format!("Signature = bad-name 1 {}\nbody", "x".repeat(86)).as_bytes(),
        ] {
            let err = verify_blob(&paths, &Signer::Any, bad).unwrap_err();
            let CmdError::BadInput(msg) = err else {
                panic!("input {bad:?}: wrong error variant")
            };
            assert_eq!(msg, "Invalid input", "input {bad:?}");
        }
    }

    /// Header longer than `MAX_HEADER_LEN` → "Invalid input".
    #[test]
    fn verify_header_too_long() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        // 2049-char header (one over the limit).
        let long_header = format!("{}\nbody", "x".repeat(MAX_HEADER_LEN + 1));
        let err = verify_blob(&paths, &Signer::Any, long_header.as_bytes()).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert_eq!(msg, "Invalid input");
    }

    /// `Signer::parse` cases. `.`, `*`, valid name, invalid name.
    #[test]
    fn signer_parse() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        // `.` → own name.
        match Signer::parse(".", &paths).unwrap() {
            Signer::Named(n) => assert_eq!(n, "alice"),
            Signer::Any => panic!(),
        }
        // `*` → Any.
        assert!(matches!(Signer::parse("*", &paths).unwrap(), Signer::Any));
        // Valid name → Named (NOT looked up — that happens at verify
        // time, not parse time).
        match Signer::parse("bob", &paths).unwrap() {
            Signer::Named(n) => assert_eq!(n, "bob"),
            Signer::Any => panic!(),
        }
        // Invalid name (dash) → error.
        assert!(Signer::parse("bad-name", &paths).is_err());
    }

    /// `load_host_pubkey` PEM fallback. Host file has no
    /// `Ed25519PublicKey =` line but does have a PEM block.
    #[test]
    fn load_host_pubkey_pem_fallback() {
        let dir = tempfile::tempdir().unwrap();
        // Don't `fake_init` — we want a non-standard host file.
        let confbase = dir.path().join("alice");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        fs::write(confbase.join("tinc.conf"), "Name = alice\n").unwrap();

        let sk = keypair::generate();
        // Private key normal.
        let mut buf = Vec::new();
        tinc_conf::pem::write_pem(&mut buf, "ED25519 PRIVATE KEY", &sk.to_blob()).unwrap();
        fs::write(confbase.join("ed25519_key.priv"), buf).unwrap();

        // Host file: PEM block, NO config line.
        let mut buf = Vec::new();
        tinc_conf::pem::write_pem(&mut buf, "ED25519 PUBLIC KEY", sk.public_key()).unwrap();
        fs::write(confbase.join("hosts/alice"), buf).unwrap();

        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        // Now sign + verify roundtrips through the PEM-fallback path.
        let input = dir.path().join("payload");
        fs::write(&input, b"data").unwrap();
        let mut signed = Vec::new();
        sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();
        let v = verify_blob(&paths, &Signer::Any, &signed).unwrap();
        assert_eq!(v.body, b"data");
    }

    /// `load_host_pubkey` neither-form → error.
    #[test]
    fn load_host_pubkey_no_key() {
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("alice");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        // Host file with no key at all. Just an Address.
        fs::write(confbase.join("hosts/alice"), "Address = 1.2.3.4\n").unwrap();

        let err = load_host_pubkey(&confbase.join("hosts/alice")).unwrap_err();
        let CmdError::BadInput(msg) = err else {
            panic!()
        };
        assert!(msg.contains("Could not read public key from"));
        assert!(msg.contains("hosts/alice"));
    }

    /// Binary body (NUL bytes, high bytes). The body is `&[u8]`, not
    /// `&str` — sign/verify should be byte-transparent. The header is
    /// text but the body isn't.
    #[test]
    fn binary_body_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        // All 256 byte values, including NUL.
        let data: Vec<u8> = (0u8..=255).collect();
        let input = dir.path().join("payload");
        fs::write(&input, &data).unwrap();

        let mut signed = Vec::new();
        sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();
        let v = verify_blob(&paths, &Signer::Any, &signed).unwrap();
        assert_eq!(v.body, data);
    }

    /// **Golden vector from upstream's test suite.** `test/integration/
    /// cmd_sign_verify.py` has a blob produced with a fixed key and
    /// fixed time `1653397516`. If `verify_blob` accepts it, the
    /// format is byte-compatible. The artifact IS the test — no
    /// upstream binary needed.
    ///
    /// This proves, simultaneously:
    /// - The trailer format (` foo 1653397516`, leading space) matches
    /// - The header parse accepts what upstream emits
    /// - tinc-b64 encoding matches (sig decodes to 64 bytes)
    /// - The Ed25519 verify matches (`tinc-crypto::sign::verify`)
    /// - `load_host_pubkey` parses the `Ed25519PublicKey =` line
    ///
    /// If any one of those is wrong, this test fails.
    #[test]
    fn golden_upstream_vector() {
        // Transcribed from `test/integration/cmd_sign_verify.py:12-29`.
        // The PEM has leading/trailing newlines in the Python (it's a
        // triple-quoted string starting with `\n`); read_pem skips
        // pre-BEGIN lines so they're harmless. Transcribed exactly to
        // make `diff cmd_sign_verify.py cmd/sign.rs` line up.
        const PRIV_KEY: &str = "\
-----BEGIN ED25519 PRIVATE KEY-----
4Q8bJqfN60s0tOiZdAhAWLgB9+o947cta2WMXmQIz8mCdBdcphzhp23Wt2vUzfQ6
XHt9+5IqidIw/lLXG61Nbc6IZ+4Fy1XOO1uJ6j4hqIKjdSytD2Vb7MPlNJfPdCDu
-----END ED25519 PRIVATE KEY-----
";

        // Host file: pubkey config line + a `Port` line (which we
        // ignore — proves `load_host_pubkey` doesn't choke on extra
        // config).
        const HOST: &str = "\
Ed25519PublicKey = nOSmPehc9ljTtbi+IeoKiyYnkc7gd12OzTZTy3TnwgL
Port = 17879
";

        // The signed blob. The Python's `\n` line-continuation joins
        // adjacent strings; the embedded `\n` are literal. Body is
        // `fake testing data\nhello there\n`. Transcribed byte-exact.
        const SIGNED: &[u8] = b"Signature = foo 1653397516 \
T8Bjg7dc7IjsCrZQC/20qLRsWPlrbthnjyDHQM0BMLoTeAHbLt0fxP5CbTy7Cifgg7P0K179GeahBFsnaIr4MA\n\
fake testing data\n\
hello there\n";

        // Expected body (header stripped).
        const BODY: &[u8] = b"fake testing data\nhello there\n";

        // ─── Set up confbase exactly as the Python does
        let dir = tempfile::tempdir().unwrap();
        let confbase = dir.path().join("foo");
        fs::create_dir_all(confbase.join("hosts")).unwrap();
        fs::write(confbase.join("tinc.conf"), "Name = foo\n").unwrap();
        fs::write(confbase.join("hosts/foo"), HOST).unwrap();
        fs::write(confbase.join("ed25519_key.priv"), PRIV_KEY).unwrap();

        let paths = Paths::for_cli(&PathsInput {
            confbase: Some(confbase),
            ..Default::default()
        });

        // ─── Verify the upstream-signed blob
        // The Python tests `.` and `foo` and `*`. We do all three.
        // If ANY of them fails, format compat is broken.
        for signer in [
            Signer::Named("foo".into()),
            Signer::Any,
            // `.` resolves to `foo` via tinc.conf above.
            Signer::parse(".", &paths).unwrap(),
        ] {
            let v = verify_blob(&paths, &signer, SIGNED)
                .unwrap_or_else(|e| panic!("signer {signer:?}: {e}"));
            assert_eq!(v.signer, "foo");
            assert_eq!(v.body, BODY);
        }

        // ─── Re-sign and confirm round-trip
        // Ed25519 is deterministic given key+message. Same key, same
        // body, same time, same trailer → same sig. Prove it.
        let body_file = dir.path().join("body");
        fs::write(&body_file, BODY).unwrap();
        let mut resigned = Vec::new();
        sign(&paths, Some(&body_file), 1_653_397_516, &mut resigned).unwrap();

        // **Byte-identical to upstream's output.** This is the
        // strongest possible compat statement: not just "our verify
        // accepts upstream's sign", but "our sign IS upstream's sign".
        assert_eq!(resigned, SIGNED, "Rust sign output != upstream sign output");
    }

    /// Empty body. Degenerate but valid — you can sign nothing.
    #[test]
    fn empty_body_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let paths = fake_init(&dir, "alice");

        let input = dir.path().join("payload");
        fs::write(&input, b"").unwrap();

        let mut signed = Vec::new();
        sign(&paths, Some(&input), 1_700_000_000, &mut signed).unwrap();
        // Signed output is exactly the header line + nothing.
        let nl = signed.iter().position(|&b| b == b'\n').unwrap();
        assert_eq!(nl + 1, signed.len()); // \n is the last byte

        let v = verify_blob(&paths, &Signer::Any, &signed).unwrap();
        assert_eq!(v.body, b"");
    }
}
