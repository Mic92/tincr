//! Phase 2+3: keypair coherence and private-key file mode.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use tinc_conf::Config;
use tinc_crypto::b64;
use tinc_crypto::sign::PUBLIC_LEN;

use crate::cmd::genkey::disable_old_keys;
use crate::keypair::{self, TY_PUBLIC};
use crate::names::Paths;

use super::Finding;

/// Full keypair-coherence check. Upstream's four small functions
/// collapsed: under `DISABLE_LEGACY` each was called from exactly one
/// place and the indirection was just `#ifdef` scaffolding.
///
/// Returns the success bool: `false` only for unfixable failures (no
/// private key, or mismatch + `!force`). With `force`, mismatch is
/// fixed and returns `true`.
pub(super) fn check_keypairs(
    paths: &Paths,
    cfg: &Config,
    host_file: &Path,
    force: bool,
    findings: &mut Vec<Finding>,
) -> bool {
    // ─── Load private key
    // Check `Ed25519PrivateKeyFile` config first, fall back to
    // `<confbase>/ed25519_key.priv`. fsck respects this; genkey/sign
    // currently don't (see module doc).
    //
    // `lookup` is case-insensitive; the canonical case is
    // `Ed25519PrivateKeyFile` per the table.
    let priv_path: PathBuf = cfg
        .lookup("Ed25519PrivateKeyFile")
        .next()
        .map_or_else(|| paths.ed25519_private(), |e| PathBuf::from(e.get_str()));

    let Ok(sk) = keypair::read_private(&priv_path) else {
        // We single-print where upstream double-prints (its inner
        // helper also logs). ENOENT vs bad-PEM aren't distinguished
        // at the fsck level — both are "no private key found".
        findings.push(Finding::NoPrivateKey { path: priv_path });
        return false;
    };

    // ─── Check private key file mode (Unix only)
    #[cfg(unix)]
    check_key_mode(&priv_path, force, findings);

    // ─── Host file readability
    // Warn but continue: the pubkey load below might still succeed
    // via `Ed25519PublicKeyFile` (different path) or fail more
    // specifically. The warning is "heads up, your hosts/NAME is
    // weird".
    if fs::File::open(host_file).is_err() {
        findings.push(Finding::HostFileUnreadable {
            host_file: host_file.to_owned(),
        });
        // `load_ec_pubkey` will hit the same wall and produce
        // `NoPublicKey`, which is the *actionable* finding. This is
        // just early-warning noise, kept for parity.
    }

    // ─── Load public key from config tree + host file
    // Three-step lookup:
    //   1. `Ed25519PublicKey = <b64>` config entry
    //   2. `Ed25519PublicKeyFile = <path>` → PEM-read that path
    //   3. PEM-read `hosts/NAME` directly (default for #2)
    let pubkey = load_ec_pubkey(cfg, host_file);

    // ─── Coherence check
    // Four-way matrix on (priv?, pub?). priv=None already returned
    // above. Remaining:
    //
    //   pub=Some, match  → ok
    //   pub=Some, !match → KeyMismatch, fixable
    //   pub=None         → NoPublicKey, fixable
    //
    // We compare bytes directly — no need to round-trip through b64.
    // (Upstream uses b64-strcmp because `ecdsa_t` is opaque and the
    // b64 accessor is the only "give me the pubkey" API. Our
    // `SigningKey` exposes `public_key()` as bytes.)
    let priv_derived: &[u8; PUBLIC_LEN] = sk.public_key();

    match pubkey {
        Some(pk) if pk == *priv_derived => {
            // The happy path. No finding, no message. fsck on a
            // clean `tinc init` lands here.
            true
        }
        Some(_) => {
            findings.push(Finding::KeyMismatch {
                host_file: host_file.to_owned(),
            });
            // Upstream considers "user declined to fix" as success
            // (the fix-helper returns `true` when the prompt is
            // declined). We tighten: a mismatch you didn't fix is a
            // failed fsck. The user said `--force` to fix; they said
            // nothing to fail.
            if force {
                fix_public_key(host_file, priv_derived, findings)
            } else {
                false
            }
        }
        None => {
            findings.push(Finding::NoPublicKey {
                host_file: host_file.to_owned(),
            });
            // Same tightening.
            if force {
                fix_public_key(host_file, priv_derived, findings)
            } else {
                false
            }
        }
    }
}

/// Three-step public key lookup.
///
/// Returns `None` for any failure — file missing, bad b64, wrong
/// length, no PEM block. fsck doesn't distinguish these (all are "no
/// usable public key").
///
/// `cfg` is the *merged* tree (server + host). `Ed25519PublicKey` is
/// `VAR_HOST`-only so it'll only ever come from the host file in
/// practice, but the lookup doesn't care.
pub(super) fn load_ec_pubkey(cfg: &Config, default_host_file: &Path) -> Option<[u8; PUBLIC_LEN]> {
    // ─── Step 1: Ed25519PublicKey = <b64>
    // Bad b64 is `None`, NOT a fall-through to PEM — a malformed
    // `Ed25519PublicKey =` line is a config bug, not a "let me look
    // elsewhere" situation.
    if let Some(entry) = cfg.lookup("Ed25519PublicKey").next() {
        let raw = b64::decode(entry.get_str())?;
        return raw.try_into().ok();
    }

    // ─── Step 2+3: Ed25519PublicKeyFile or default → PEM read
    // The default (when `Ed25519PublicKeyFile` unset) is `hosts/NAME`,
    // which is *also* the file we'd parse for the config-line form.
    // The reason for both: `tinc init` writes config-line, but `fsck
    // --force` writes PEM (see module doc). And legacy configs from
    // pre-1.1 used PEM. Both forms exist in the wild.
    let pem_path: PathBuf = cfg.lookup("Ed25519PublicKeyFile").next().map_or_else(
        || default_host_file.to_owned(),
        |e| PathBuf::from(e.get_str()),
    );

    // `read_public` does open + read_pem + length check. Any failure
    // → None.
    keypair::read_public(&pem_path).ok()
}

/// Rewrite the public key in `host_file`, post-`force` gate.
///
/// `disable_old_keys` to comment out whatever was there, then append
/// a PEM block with the priv-derived public key. Returns `true` iff
/// both succeeded. Records `FixedPublicKey` or `FixFailed`.
fn fix_public_key(
    host_file: &Path,
    pubkey: &[u8; PUBLIC_LEN],
    findings: &mut Vec<Finding>,
) -> bool {
    // ─── disable_old_keys
    // Our `disable_old_keys` is `Result<bool>` — `Err` is "write/
    // rename failed", both `Ok(true)` and `Ok(false)` are "safe to
    // append" (either nothing matched or it was successfully
    // commented). The bool is genkey's "did I touch anything", which
    // fsck doesn't care about.
    if let Err(e) = disable_old_keys(host_file) {
        findings.push(Finding::FixFailed {
            path: host_file.to_owned(),
            err: e.to_string(),
        });
        return false;
    }

    // ─── Append PEM block
    // Append mode, existing perms preserved, no chmod. genkey's
    // `open_append` would set a create-mode but hosts files are
    // 0644-ish from `tinc init` and we're appending to an existing
    // one; the create-mode is moot.
    //
    // The PEM-not-config-line choice: see module doc.
    let result = (|| -> std::io::Result<()> {
        let mut o = fs::OpenOptions::new();
        o.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits());
        }
        let f = o.open(host_file)?;
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::pem::write_pem(&mut w, TY_PUBLIC, pubkey)?;
        w.flush()
    })();

    match result {
        Ok(()) => {
            findings.push(Finding::FixedPublicKey {
                path: host_file.to_owned(),
            });
            true
        }
        Err(e) => {
            findings.push(Finding::FixFailed {
                path: host_file.to_owned(),
                err: e.to_string(),
            });
            false
        }
    }
}

// Phase 3: Key file mode

/// Private key file mode check. Unix-only.
///
/// `& 077` check: any bits in group/other. `0600` passes, `0640`
/// doesn't. Also checks `st_uid != getuid()` to decide whether to
/// offer the fix — you can't `chmod` a file you don't own (without
/// root). We push a `Finding` either way; the `uid_match` field
/// gates the fix.
#[cfg(unix)]
fn check_key_mode(path: &Path, force: bool, findings: &mut Vec<Finding>) {
    use std::os::unix::fs::MetadataExt; // for st_uid

    // We already successfully opened this file (in `read_private`),
    // so metadata failing here would be a TOCTOU race. Just skip —
    // the `read_private` call is the real existence check.
    let Ok(meta) = fs::metadata(path) else {
        return;
    };

    let mode = meta.permissions().mode();
    // clippy suggests `mode.trailing_zeros() >= 6` here, which is
    // technically equivalent but obfuscates the intent: this is a
    // Unix permission-bit mask, not a power-of-2 check.
    #[allow(clippy::verbose_bit_mask)] // perm-bit mask; trailing_zeros() obscures intent
    if mode & 0o077 == 0 {
        return; // clean
    }

    // `MetadataExt::uid()` returns `u32`; compare against
    // `nix::unistd::getuid().as_raw()` — both `u32`.
    let uid_match = meta.uid() == nix::unistd::getuid().as_raw();

    findings.push(Finding::UnsafeKeyMode {
        path: path.to_owned(),
        mode,
        uid_match,
    });

    if !force || !uid_match {
        // uid mismatch skips the fix.
        return;
    }

    // Mask off group/other, preserve owner bits + sticky/suid.
    let fixed = fs::Permissions::from_mode(mode & !0o077);
    match fs::set_permissions(path, fixed) {
        Ok(()) => findings.push(Finding::FixedMode {
            path: path.to_owned(),
        }),
        Err(e) => findings.push(Finding::FixFailed {
            path: path.to_owned(),
            err: e.to_string(),
        }),
    }
}
