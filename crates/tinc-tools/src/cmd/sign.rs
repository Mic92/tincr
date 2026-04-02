//! `cmd_sign` + `cmd_verify` — `tincctl.c:2770-2998`.
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
//! Note the **leading space** before name. C: `xasprintf(&trailer,
//! " %s %ld", name, t)` — `tincctl.c:2833`. That space is in the
//! format string, not an artifact. The trailer is `memcpy`'d after
//! the file bytes (`tincctl.c:2837`), then signed. The trailer is
//! **not** in the output — only in the signature input.
//!
//! Why the trailer at all? Without it, you sign `file_contents` and
//! the header carries `name`+`t` as unsigned metadata. Anyone can
//! rewrite the header to say a different signer/time. With the
//! trailer, name+time are *inside* the signed message; rewriting the
//! header without the private key invalidates the sig.
//!
//! Why the leading space? Separator. If the file ends `...alice` and
//! name is `bob`, the trailer-less concatenation is `...alicebob 123`.
//! `verify` parses `name=alicebob`, looks up `hosts/alicebob`, fails
//! confusingly. The space makes it `...alice bob 123`, which parses
//! as `name=bob`. (Except `verify` doesn't *parse* the trailer — it
//! reconstructs it from the header. The space is defense in depth
//! against a hypothetical attack where you find a file that, when
//! concatenated with `<evilname> <t>`, has a known signature. With
//! the space, you'd need `<space><evilname>` and then the header's
//! `name` field doesn't match. Honestly the threat model is murky.
//! The C has the space; we replicate it.)
//!
//! No trailing newline on the trailer. `xasprintf(" %s %ld", ...)`
//! doesn't add one. `tincctl.c:2833` confirmed.
//!
//! ## `verify`'s signer argument
//!
//! `tincctl.c:2872-2889`:
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
//! ## `get_pubkey` — the fourth tokenizer
//!
//! `tincctl.c:1647-1678` is yet another hand-rolled config-line
//! tokenizer (the strcspn/strspn/optional-`=` dance — same shape as
//! `conf.c`'s, copy-pasted). It walks the host file looking for
//! `Ed25519PublicKey = <b64>`. We use `tinc-conf::parse_file` instead,
//! same as `get_my_name` already does. The `get_pubkey` C falls back
//! to `ecdsa_read_pem_public_key` (`tincctl.c:2972`) — host file might
//! have a PEM block instead of a config line (unusual; init writes the
//! config line, but a hand-edited host file might have either). We
//! replicate the fallback.
//!
//! ## Time parameterized for tests
//!
//! C uses `time(NULL)`. Non-deterministic output makes the
//! sign-then-verify roundtrip test fragile (the time in the header
//! must match the time in the trailer; if they're computed in
//! different test runs the roundtrip is fine, but a golden-output
//! test isn't). We take time as a parameter; the binary wrapper
//! supplies `SystemTime::now()`. Tests supply a fixed value.
//!
//! ## Input from file or stdin
//!
//! Both `sign` and `verify` take an optional file argument; absent,
//! they read stdin. C: `if(argc == 2) fopen(argv[1]) else stdin`
//! (`tincctl.c:2805-2813`). Same. The file is slurped whole
//! (`readfile` — `tincctl.c:2743` — `realloc` doubling, no size
//! limit; we use `read_to_end`, also no limit). For a 10 GB file
//! both implementations OOM. Don't sign 10 GB files.
//!
//! ## What we don't replicate
//!
//! - The C `fwrite(data, len, 1, stdout)` writes the file body in one
//!   shot (`tincctl.c:2853`). We do the same. No streaming —
//!   signature is over the whole thing anyway.
//! - C `verify` doesn't write *anything* on failure (no body output).
//!   `tincctl.c:2991` only fwrites on success. Same.
//! - The `MAX_STRING_SIZE - 1 = 2048` cap on the header line length
//!   (`tincctl.c:2918`). We enforce it. It's the C's `sscanf` buffer
//!   size — without the cap a 100 KB header line would overflow
//!   `char signer[MAX_STRING_SIZE]`. Ours is heap so no overflow,
//!   but the cap is a sanity check (a 100 KB header is malformed).
//! - The `!t` check in `sscanf` validation (`tincctl.c:2930`). Time
//!   zero (1970-01-01) is rejected. Probably guarding against
//!   `sscanf` returning 3 but with `t` unparsed-left-at-init (which
//!   can't happen with `%ld` but defensive). We replicate. `sign`
//!   never emits `t=0` (you'd need `time(NULL)==0`, which... no), so
//!   the check is unreachable on the happy path.

use std::io::{Read, Write};
use std::path::Path;

use crate::cmd::exchange::get_my_name;
use crate::cmd::{CmdError, io_err};
use crate::keypair;
use crate::names::{Paths, check_id};

use tinc_crypto::b64;
use tinc_crypto::sign::{PUBLIC_LEN, SIG_LEN, verify};

/// 64-byte raw signature → 86-char tinc-b64. `ceil(64 * 4 / 3) = 86`.
/// C `tincctl.c:2930`: `strlen(sig) != 86` is a hardcoded check.
/// `const _:` is the no-runtime-cost form of asserting our
/// arithmetic matches. If `SIG_LEN` changes (it won't — Ed25519
/// signatures are 64 bytes by definition) this fails at compile time.
const SIG_B64_LEN: usize = 86;
const _: () = assert!((SIG_LEN * 4).div_ceil(3) == SIG_B64_LEN);

/// `MAX_STRING_SIZE - 1 = 2048`. `tincctl.c:2918`. The C check is
/// `newline - data > MAX_STRING_SIZE - 1`, i.e. header (without the
/// `\n`) longer than 2048 bytes is rejected. Our parsed line is
/// already without the `\n` (we slice at it), so direct comparison.
const MAX_HEADER_LEN: usize = 2048;

/// Slurp `path` or stdin. C `readfile` (`tincctl.c:2743`).
///
/// `path = None` → stdin. The error path naming is slightly off in C:
/// `tincctl.c:2826` does `argv[1]` even when `argc < 2` (reads stack
/// garbage). We say `<stdin>`.
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
/// C `tincctl.c:2832-2838`: `xasprintf(&trailer, " %s %ld", name, t)`
/// then `xrealloc(data, len + trailer_len); memcpy(data + len,
/// trailer, trailer_len)`. The xrealloc grows `data` in place; we
/// can't do that (we'd need ownership games), so we build a fresh
/// `Vec`. One extra alloc. The data we're signing is already
/// in-memory whole (slurped); one more copy is noise.
///
/// `t` formatted with `%ld` — i.e., decimal, sign-allowed-but-time-is-
/// positive, no padding. Our `{t}` does the same for `i64`.
///
/// The `name` here can be either *our* name (sign) or the *signer's*
/// name from the header (verify reconstructs the same trailer). In
/// both cases it's already validated (`get_my_name` runs `check_id`;
/// `verify` runs `check_id(signer)` after sscanf). So no spaces in
/// `name`, no ambiguity in the trailer parse — but again, nobody
/// parses the trailer. It's signed-then-discarded.
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
/// `t` is the unix time to embed. Caller supplies `time(NULL)`; tests
/// supply a fixed value. C `tincctl.c:2831`: `long t = time(NULL)`.
/// We use `i64` — `long` is 64-bit on every Unix tinc targets (LP64),
/// 32-bit on Windows (LLP64). `i64` is the safe bet for a unix
/// timestamp (won't overflow until 292 billion years from now).
///
/// # Errors
///
/// `BadInput` if `tinc.conf` missing or no `Name`. `Io` for the
/// private key open or the input file open. **Not** for the signature
/// itself — `ecdsa_sign` (the C) returns false only on alloc failure
/// (`ed25519/sign.c` — the actual crypto can't fail), and our
/// `SigningKey::sign` returns `[u8; 64]` directly.
pub fn sign(paths: &Paths, input: Option<&Path>, t: i64, out: impl Write) -> Result<(), CmdError> {
    // ─── Load name + private key ────────────────────────────────────
    // C `tincctl.c:2776-2801`: `get_my_name(true)` then read PEM. The
    // `true` is `verbose` — it controls whether `get_my_name` prints
    // an error itself. Ours always returns the error (caller prints).
    let name = get_my_name(paths)?;
    let sk = keypair::read_private(&paths.ed25519_private())
        .map_err(|e| CmdError::BadInput(e.to_string()))?;
    // `LoadError` → `BadInput` because there's no `Io` variant that
    // takes a pre-stringified inner error. `LoadError::Display`
    // already includes the path. Slight loss of structure (caller
    // can't `match` on Io-vs-Pem) but this is leaf-level — the caller
    // is the binary, which prints + exits.

    // ─── Slurp input ────────────────────────────────────────────────
    let data = slurp(input)?;

    // ─── Build signed message + sign ────────────────────────────────
    // C `tincctl.c:2831-2847`. The `b64encode_tinc(sig, sig, 64)`
    // (`:2849`) encodes in-place into a `char sig[87]` — the 87 is
    // 86 b64 chars + NUL. Our encode returns a fresh `String`.
    let msg = signed_message(&data, &name, t);
    let sig_raw = sk.sign(&msg);
    let sig_b64 = b64::encode(&sig_raw);
    // Sanity. `SIG_B64_LEN` const check at the top proves the
    // arithmetic; this proves `b64::encode` agrees with the
    // arithmetic. Belt and suspenders. If this ever fires, the
    // problem is in `tinc-crypto::b64`, not here.
    debug_assert_eq!(sig_b64.len(), SIG_B64_LEN);

    // ─── Emit ───────────────────────────────────────────────────────
    // C `tincctl.c:2852-2853`: `fprintf(stdout, "Signature = %s %ld
    // %s\n", name, t, sig)` then `fwrite(data, len, 1, stdout)`.
    //
    // The body is the *original* `data`, NOT `msg` (which has the
    // trailer). `len` not `len + trailer_len`. Load-bearing.
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
        // C `tincctl.c:2872-2889`. The order is `.` then `*` then
        // check_id. So `.` and `*` are NOT validated as names —
        // they're metasyntax. (They'd fail `check_id` anyway: `.`
        // and `*` aren't alnum-or-underscore.)
        match arg {
            "." => Ok(Signer::Named(get_my_name(paths)?)),
            "*" => Ok(Signer::Any),
            name => {
                if check_id(name) {
                    Ok(Signer::Named(name.to_owned()))
                } else {
                    // C `:2888`: `fprintf(stderr, "Invalid node name\n")`.
                    Err(CmdError::BadInput("Invalid node name".into()))
                }
            }
        }
    }
}

/// What `verify` discovers. The body (header-stripped input) and the
/// signer's name (relevant when `Signer::Any` — caller might want to
/// know *who* signed it, not just that *someone* did).
///
/// C doesn't return this — it just `fwrite`s the body to stdout
/// (`tincctl.c:2993`). We return it so tests can assert on the body
/// without capturing stdout. The binary wrapper writes `body` to
/// stdout to match C.
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
/// newline, header too long, sscanf shape mismatch, sig length wrong,
/// `t == 0`, signer fails `check_id`). C bundles all these into one
/// message (`tincctl.c:2918`, `:2930`). We do too.
///
/// `BadInput("Signature is not made by NAME")` if `Signer::Named` and
/// the header's signer doesn't match. C `tincctl.c:2936`.
///
/// `BadInput("Invalid signature")` if the crypto fails. Covers both
/// b64-decode failure and Ed25519 verify failure — C lumps them
/// (`tincctl.c:2984`: `b64decode_tinc(...) != 64 || !ecdsa_verify`).
///
/// `Io` for host-file open failure.
///
/// `BadInput("Could not read public key from PATH")` if the host file
/// exists but has neither `Ed25519PublicKey =` line nor PEM block.
/// (Distinct from `Io` — the file opened fine, the contents are
/// wrong.)
pub fn verify_blob(paths: &Paths, signer: &Signer, blob: &[u8]) -> Result<Verified, CmdError> {
    // ─── Find the header line ───────────────────────────────────────
    // C `tincctl.c:2916-2924`: `memchr(data, '\n', len)`. If no
    // newline, OR header longer than `MAX_STRING_SIZE - 1`, fail. The
    // C then `*newline++ = '\0'` to NUL-terminate for `sscanf`; we
    // slice instead.
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

    // ─── Parse header ───────────────────────────────────────────────
    // C `tincctl.c:2930`: `sscanf(data, "Signature = %s %ld %s",
    // signer, &t, sig) != 3 || strlen(sig) != 86 || !t || !check_id`.
    //
    // `%s` skips leading whitespace, reads non-whitespace. So the
    // sscanf accepts `Signature = alice  123  xyz` (extra spaces).
    // The format string's literal spaces also match any whitespace
    // (sscanf's space matches `[ \t\n]*`). And the literal `=` must
    // match exactly. So:
    //
    //   Signature = alice 123 xyz   → parses
    //   Signature=alice 123 xyz     → FAILS (no space before =? no:
    //                                  the format's "Signature " needs
    //                                  the space-then-= to match. wait.)
    //
    // Actually: sscanf format-string whitespace matches *zero or more*
    // input whitespace. So `"Signature = "` matches `Signature=` (the
    // space-before-= matches zero chars, the `=` matches `=`, the
    // space-after matches zero). Ugh. sscanf is permissive.
    //
    // We could replicate that exactly (zero-or-more whitespace at each
    // format-string-space), but sign always emits the canonical form
    // (`tincctl.c:2852`: `"Signature = %s %ld %s\n"` — single spaces).
    // The only way to get a non-canonical header is hand-editing.
    // We accept the canonical form; deviation noted. If a user reports
    // "verify rejects my hand-edited header" the answer is "don't".
    //
    // Practically: split on single spaces, expect exactly 5 fields:
    // `["Signature", "=", name, t, sig]`. Stricter than sscanf,
    // matches sign's output exactly.
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

    // `strlen(sig) != 86`. Do this before b64-decode — it's cheaper
    // and catches truncation/garbage early.
    if sig_b64.len() != SIG_B64_LEN {
        return Err(CmdError::BadInput("Invalid input".into()));
    }

    // `%ld` → i64. `parse()` rejects trailing garbage (sscanf's `%ld`
    // stops at the first non-digit, leaving garbage for the next `%`;
    // here the next `%s` would consume it. Same outcome: non-digit
    // after time is rejected, just at a different layer.)
    let t: i64 = t_str
        .parse()
        .map_err(|_| CmdError::BadInput("Invalid input".into()))?;
    // `!t` — C rejects time zero. See module doc.
    if t == 0 {
        return Err(CmdError::BadInput("Invalid input".into()));
    }

    // `check_id(signer)`. Node names are alnum-or-underscore. A
    // signer name with `/` or `..` would let `*` mode read
    // `hosts/../../../etc/passwd`. The C check is here for the same
    // reason — and we already trust check_id to reject those.
    if !check_id(signer_name) {
        return Err(CmdError::BadInput("Invalid input".into()));
    }

    // ─── Match signer ───────────────────────────────────────────────
    // C `tincctl.c:2935-2943`: `if(node && strcmp(node, signer))`
    // (where `node = NULL` is the `*` case).
    let resolved_signer = match signer {
        Signer::Any => signer_name,
        Signer::Named(n) => {
            if n != signer_name {
                // C `:2936`: `"Signature is not made by %s\n"`.
                // Use `n` (what the user asked for) not `signer_name`
                // (what the blob claims). C uses `node` = `n`.
                return Err(CmdError::BadInput(format!("Signature is not made by {n}")));
            }
            signer_name
        }
    };

    // ─── Load public key ────────────────────────────────────────────
    // C `tincctl.c:2960-2982`: `fopen(hosts/NAME)`, `get_pubkey`,
    // fall back to `ecdsa_read_pem_public_key` if `get_pubkey`
    // returned NULL.
    let host_path = paths.host_file(resolved_signer);
    let pubkey = load_host_pubkey(&host_path)?;

    // ─── Decode sig + reconstruct trailer + verify ──────────────────
    // C `tincctl.c:2984`: `b64decode_tinc(sig, sig, 86) != 64 ||
    // !ecdsa_verify(...)`. Both failures map to "Invalid signature".
    let sig_raw =
        b64::decode(sig_b64).ok_or_else(|| CmdError::BadInput("Invalid signature".into()))?;
    let sig_raw: [u8; SIG_LEN] = sig_raw
        .try_into()
        .map_err(|_| CmdError::BadInput("Invalid signature".into()))?;

    // Reconstruct the trailer. The C does the same xasprintf+memcpy
    // dance as `sign` (`tincctl.c:2948-2954`), using the *header's*
    // signer name and time — not anything the verifier knows
    // independently. This is correct: the trailer is *inside* the
    // signature, so if the header lies about name/time, the
    // reconstructed trailer differs from what was signed, and verify
    // fails. The signature *binds* the header fields.
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
    // C `tincctl.c:2993`: `fwrite(newline, len - skip, 1, stdout)`.
    // Body, byte-exact. Only on success — error paths return before
    // here.
    let mut out = out;
    out.write_all(&v.body).map_err(io_err("<stdout>"))?;
    Ok(())
}

/// `get_pubkey` (`tincctl.c:1647`) + the PEM fallback (`tincctl.c:
/// 2972`). Read `hosts/NAME`, look for `Ed25519PublicKey = <b64>`,
/// fall back to a `-----BEGIN ED25519 PUBLIC KEY-----` PEM block.
///
/// The C fallback does `fseek(fp, 0, SEEK_SET)` then re-reads the
/// same `FILE*`. We re-read from the path. Same I/O count (one extra
/// open, but the kernel cached the inode), simpler code.
///
/// `tinc-conf::parse_file` replaces the strcspn/strspn tokenizer (the
/// fourth — see module doc).
fn load_host_pubkey(host_path: &Path) -> Result<[u8; PUBLIC_LEN], CmdError> {
    // ─── Try config-line form ───────────────────────────────────────
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
        // `ecdsa_set_base64_public_key` (`ed25519/ecdsa.c:59`) does
        // the b64 decode + 32-byte check. Our `b64::decode` returns
        // `Option<Vec<u8>>`; we check the length here.
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

    // ─── Fall back to PEM block ─────────────────────────────────────
    // `keypair::read_public` does the open + read_pem + length check.
    // It errors `LoadError::Pem(NotFound)` if there's no PEM block.
    // That's our "neither form found" terminal error.
    keypair::read_public(host_path).map_err(|_| {
        // Don't expose `LoadError` details — C just says "Could not
        // read public key from PATH" (`tincctl.c:2978`). The user
        // doesn't need to know whether parse_file or read_pem failed;
        // the actionable info is "this host file has no pubkey".
        CmdError::BadInput(format!(
            "Could not read public key from {}",
            host_path.display()
        ))
    })
}

// ────────────────────────────────────────────────────────────────────
// Tests
// ────────────────────────────────────────────────────────────────────

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

        // ─── Shape check on the output ──────────────────────────────
        // First line is the header, rest is the body byte-exact.
        let nl = signed.iter().position(|&b| b == b'\n').unwrap();
        let header = std::str::from_utf8(&signed[..nl]).unwrap();
        assert!(header.starts_with("Signature = alice 1700000000 "));
        // Sig is the 5th space-separated field.
        let sig_b64 = header.rsplit(' ').next().unwrap();
        assert_eq!(sig_b64.len(), SIG_B64_LEN);
        // Body is the original data, byte-exact.
        assert_eq!(&signed[nl + 1..], data);

        // ─── Verify ─────────────────────────────────────────────────
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
        // runs *before* the pubkey load (`tincctl.c:2935` is before
        // `:2960`). So we hit the mismatch error, not "no host file".
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

    /// **Golden vector from the C test suite.** `test/integration/
    /// cmd_sign_verify.py` has a blob produced by C `cmd_sign` (fixed
    /// key, fixed time `1653397516`). If Rust `verify_blob` accepts
    /// it, the format is byte-compatible. This is the cross-impl test
    /// that doesn't need a C binary — the artifact IS the test.
    ///
    /// This proves, simultaneously:
    /// - The trailer format (` foo 1653397516`, leading space) matches
    /// - The header sscanf parse matches (we accept what C emits)
    /// - tinc-b64 encoding matches (sig decodes to 64 bytes)
    /// - The Ed25519 verify matches (`tinc-crypto::sign::verify`)
    /// - `load_host_pubkey` parses the C-written `Ed25519PublicKey =`
    ///   line (same b64, same alphabet)
    ///
    /// If any one of those is wrong, this test fails.
    #[test]
    fn golden_c_vector() {
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

        // ─── Set up confbase exactly as the Python does ────────────
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

        // ─── Verify the C-signed blob ───────────────────────────────
        // The Python tests `.` and `foo` and `*` (line 78-83). We do
        // all three. If ANY of them fails, format compat is broken.
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

        // ─── Re-sign and confirm round-trip ─────────────────────────
        // We can't compare our signed output to SIGNED directly —
        // Ed25519 is deterministic given the key+message, so actually
        // we CAN. The signature is a pure function of (private key,
        // message). Same key, same body, same time, same trailer →
        // same sig. Prove it.
        let body_file = dir.path().join("body");
        fs::write(&body_file, BODY).unwrap();
        let mut resigned = Vec::new();
        sign(&paths, Some(&body_file), 1_653_397_516, &mut resigned).unwrap();

        // **Byte-identical to the C output.** This is the strongest
        // possible compat statement: not just "our verify accepts C's
        // sign", but "our sign IS C's sign".
        assert_eq!(resigned, SIGNED, "Rust sign output != C sign output");
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
