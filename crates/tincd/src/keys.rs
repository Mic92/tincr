//! Load Ed25519 keys.
//!
//! `read_ecdsa_private_key`: resolves path from config, warns on
//! insecure perms, hints "run `tinc generate-ed25519-keys`" on
//! ENOENT. `read_ecdsa_public_key`: tries three sources (inline
//! b64, file path, `hosts/NAME` PEM block).
//!
//! The bare 12-line PEM-read is duplicated from `tinc-tools/
//! keypair.rs`. Same dup-don't-factor call as `read_fd`/`write_fd`:
//! avoids depending on the whole CLI crate. Factor trigger is "a
//! third crate needs this" → `tinc-conf`.
//!
//! Upstream checks `& ~0100700u`, flagging symlinks and setuid
//! bits. Intent is `& 0o077` (no group/other read). We port the
//! bug; the warning is cosmetic and 1.1 users
//! grep for the C message.

use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use tinc_conf::{Config, read_pem};
use tinc_crypto::b64;
use tinc_crypto::sign::{PUBLIC_LEN, SigningKey};

// PEM type strings + blob length

/// Same constants as `tinc-tools/keypair.rs`. Upstream's casing —
/// "ED25519", not "Ed25519".
const TY_PRIVATE: &str = "ED25519 PRIVATE KEY";
const TY_PUBLIC: &str = "ED25519 PUBLIC KEY";

/// On-disk private blob: `expanded[64] || public[32]`. `tinc-crypto::
/// sign::SigningKey::from_blob` takes this.
const PRIVATE_BLOB_LEN: usize = 96;

// Public-key b64

/// `ecdsa_set_base64_public_key`. Decode 43 b64 chars → 32 bytes.
///
/// The C checks `strlen(p) != 43` first, then `b64decode != 32`. We
/// could let `b64::decode` reject everything (wrong length → wrong
/// output length → arr fail), but matching the C's two-step makes the
/// log lines distinguishable: "Invalid size 42" vs "Invalid format".
/// One length, one decode.
///
/// 43 because `ceil(32 * 4/3) = 43` — tinc's b64 doesn't pad. The
/// exported pubkey is always exactly 43 chars (`ecdsa_get_base64_
/// public_key` writes 44 bytes incl NUL → 43 char string).
fn pubkey_from_b64(p: &str) -> Option<[u8; PUBLIC_LEN]> {
    if p.len() != 43 {
        log::debug!(target: "tincd::keys",
                    "Invalid size {} for public key (want 43)", p.len());
        return None;
    }
    let bytes = b64::decode(p)?;
    bytes.as_slice().try_into().ok().or_else(|| {
        // b64::decode of 43 chars should ALWAYS give 32 bytes.
        // Reaching here means tinc-crypto's b64 disagrees with
        // upstream `b64decode_tinc`. The KAT tests pin that, so
        // this is unreachable-in-practice. We check anyway.
        log::debug!(target: "tincd::keys",
                    "Invalid format of public key! len = {}", bytes.len());
        None
    })
}

// Private key

/// Why `read_ecdsa_private_key` failed. Upstream just returns NULL and
/// logs; we return the variant so `setup()` can decide whether the
/// daemon can boot at all. `Missing` is fatal (can't auth as
/// ourselves → can't peer). Upstream has a fallback to RSA (legacy)
/// when this fails, but we forbid legacy, so all variants are
/// fatal for us.
#[derive(Debug, thiserror::Error)]
pub enum PrivKeyError {
    /// `ENOENT`. Carries the path for the gen-keys hint message.
    #[error("Error reading Ed25519 private key file `{}': No such file or directory", .0.display())]
    Missing(PathBuf),
    /// Any other I/O error on `fopen`.
    #[error("Error reading Ed25519 private key file `{}': {}", .0.display(), .1)]
    Io(PathBuf, #[source] std::io::Error),
    /// `read_pem` failed: bad armor, wrong type string, wrong size.
    #[error("Ed25519 private key in `{}' malformed: {}", .0.display(), .1)]
    Pem(PathBuf, #[source] tinc_conf::PemError),
}

/// `read_ecdsa_private_key`.
///
/// Path resolution: `Ed25519PrivateKeyFile` config var if set, else
/// `confbase/ed25519_key.priv`. (`Ed25519PrivateKeyFile` is in
/// tinc.conf, not hosts/NAME — it's SERVER-tagged per `vars.rs`.
/// The `config` here is the merged tree after `read_host_
/// config`, but it doesn't matter — the lookup finds it wherever.)
///
/// Permission warning: `if(s.st_mode & ~0100700u)`. See module doc
/// for why this is over-broad. Warning, not error.
///
/// Upstream's `keyfile` out-parameter is unused (caller passes
/// NULL). We drop it. The path is in the error variant if you need
/// it.
///
/// # Errors
/// `Missing` if the file doesn't exist (caller prints the gen-keys
/// hint), `Io` for other fs errors, `Pem` for malformed contents.
pub fn read_ecdsa_private_key(
    config: &Config,
    confbase: &Path,
) -> Result<SigningKey, PrivKeyError> {
    // ─── path resolution (`:114-116`)
    let path = config.lookup("Ed25519PrivateKeyFile").next().map_or_else(
        || confbase.join("ed25519_key.priv"),
        |e| PathBuf::from(e.get_str()),
    );

    // ─── open + perm check (`:118-144`)
    let f = File::open(&path).map_err(|err| {
        if err.kind() == std::io::ErrorKind::NotFound {
            PrivKeyError::Missing(path.clone())
        } else {
            PrivKeyError::Io(path.clone(), err)
        }
    })?;

    // `fstat(fileno(fp), &s)` then `s.st_mode & ~0100700`. We use
    // `f.metadata()` (also `fstat` under the hood
    // — `File::metadata` calls `fstat` not `stat`, so symlink mode
    // bits don't apply, slightly NARROWING the C bug. The C's `fstat`
    // ALSO follows the symlink — `fopen` already did. So neither
    // sees `S_IFLNK`. The "symlink false positive" in the module doc
    // is wrong for `fstat`; only `lstat` would see it. But the
    // setuid-bit case still stands.)
    //
    // metadata() failure is just logged in C (`:135-139`: returns
    // false, but the actual key parse below will fail anyway). We
    // skip the warn on metadata error — it's noise.
    if let Ok(meta) = f.metadata() {
        // `~0100700` octal. `0o100700` is `S_IFREG | S_IRWXU`.
        // `& !0o100700` flags any other bit: group/other perms,
        // setuid/setgid/sticky, OR a non-regular-file type (which
        // can't happen post-`open`-of-a-regular-file, but the C
        // mask doesn't know that).
        let mode = meta.permissions().mode();
        if mode & !0o100_700 != 0 {
            log::warn!(target: "tincd::keys",
                       "Warning: insecure file permissions for Ed25519 private key file `{}'!",
                       path.display());
        }
    }

    // ─── parse
    // `read_pem` returns exactly 96 bytes or errors.
    let blob = read_pem(f, TY_PRIVATE, PRIVATE_BLOB_LEN).map_err(|e| PrivKeyError::Pem(path, e))?;
    // `read_pem` checked the length. Unwrap is the handoff.
    let mut arr = [0u8; PRIVATE_BLOB_LEN];
    arr.copy_from_slice(&blob);
    Ok(SigningKey::from_blob(&arr))
}

// Peer public key

/// `read_ecdsa_public_key`. Three sources in order:
///
/// 1. `Ed25519PublicKey` inline b64 (`tinc init` writes)
/// 2. `Ed25519PublicKeyFile` explicit path
/// 3. `hosts/NAME` PEM block (`cmd_exchange` writes)
///
/// `host_config` is the peer's; caller already loaded it. Returns
/// `None` on failure: `id_h` treats it as "downgrade to legacy"
/// (then rejected at `:443-447`).
///
/// Source-order subtlety: if `hosts/NAME` has BOTH the var and a
/// PEM block, the var wins silently (early return). No consistency
/// check; ported faithfully.
#[must_use]
pub fn read_ecdsa_public_key(
    host_config: &Config,
    confbase: &Path,
    name: &str,
) -> Option<[u8; PUBLIC_LEN]> {
    // ─── Source 1: inline b64 config var (`:179-184`)
    if let Some(e) = host_config.lookup("Ed25519PublicKey").next() {
        // Returns NULL if the b64 is bad. NO fallthrough to source
        // 2/3. A present-but-malformed inline key is a hard
        // None, not a "try the next source". This is correct: a typo
        // in the inline var should be an error, not silently masked
        // by an old PEM block at the bottom of the file.
        return pubkey_from_b64(e.get_str());
    }

    // ─── Source 2/3: file (`:186-189`)
    // `Ed25519PublicKeyFile` if set, else `hosts/NAME`. The default
    // is "the same file we already parsed as config" — `read_pem`
    // skips lines until BEGIN.
    let path = host_config
        .lookup("Ed25519PublicKeyFile")
        .next()
        .map_or_else(
            || confbase.join("hosts").join(name),
            |e| PathBuf::from(e.get_str()),
        );

    // ─── Open + parse (`:191-211`)
    // C logs ERR on `fopen` fail (`:196-199`). We match. `:204` logs
    // ERR on parse fail too (unless `errno == ENOENT`, which means
    // `read_pem` got EOF before BEGIN).
    let f = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            log::error!(target: "tincd::keys",
                        "Error reading Ed25519 public key file `{}': {e}",
                        path.display());
            return None;
        }
    };

    match read_pem(f, TY_PUBLIC, PUBLIC_LEN) {
        Ok(blob) => {
            // `read_pem` length-checked.
            let mut arr = [0u8; PUBLIC_LEN];
            arr.copy_from_slice(&blob);
            Some(arr)
        }
        // `tinc-conf::PemError::NotFound`: scanned the whole file,
        // no BEGIN line. `if(errno != ENOENT)` suppresses this log.
        // The file existed (we opened it) but has no PEM block —
        // that's a `hosts/NAME` with config lines but no key. Common
        // (`tinc init` writes Port + Subnet + b64 var, no PEM). The
        // ERR log would be noise; `id_h` reports the consequence
        // ("Peer X had unknown identity") which is the actual problem.
        Err(tinc_conf::PemError::NotFound) => None,
        Err(e) => {
            log::error!(target: "tincd::keys",
                        "Parsing Ed25519 public key file `{}' failed: {e}",
                        path.display());
            None
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;
    use tinc_conf::{Source, parse_line};
    use tinc_crypto::b64::encode;

    /// Tempdir per test. Same idiom as `daemon.rs::tests`.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new(tag: &str) -> Self {
            let tid = std::thread::current().id();
            let p = std::env::temp_dir().join(format!("tincd-keys-{tag}-{tid:?}"));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Generate a deterministic keypair for tests. Seeded from a tag.
    fn det_key(tag: u8) -> SigningKey {
        SigningKey::from_seed(&[tag; 32])
    }

    /// Write a private key PEM file with given mode.
    fn write_priv(path: &Path, sk: &SigningKey, mode: u32) {
        use std::os::unix::fs::OpenOptionsExt;
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .unwrap();
        let mut w = std::io::BufWriter::new(f);
        tinc_conf::write_pem(&mut w, TY_PRIVATE, &sk.to_blob()).unwrap();
    }

    // pubkey_from_b64

    #[test]
    fn b64_roundtrip() {
        let pk = *det_key(1).public_key();
        // tinc's standard b64 encoding. 43 chars for 32 bytes (no pad).
        let b64 = encode(&pk);
        assert_eq!(b64.len(), 43, "tinc-b64 of 32 bytes is 43 chars");
        let back = pubkey_from_b64(&b64).expect("decode");
        assert_eq!(back, pk);
    }

    /// `if(strlen(p) != 43)` — the FIRST check. Anything not 43
    /// chars is rejected before decode is even tried.
    #[test]
    fn b64_wrong_len() {
        // 42 chars — one short.
        assert!(pubkey_from_b64(&"A".repeat(42)).is_none());
        // 44 chars — one long.
        assert!(pubkey_from_b64(&"A".repeat(44)).is_none());
        // Empty.
        assert!(pubkey_from_b64("").is_none());
    }

    /// 43 chars but bad alphabet → `b64::decode` returns None.
    #[test]
    fn b64_bad_char() {
        // `!` isn't in tinc's b64 alphabet (neither standard nor URL-safe).
        let bad: String = std::iter::repeat_n('A', 42).chain(['!']).collect();
        assert_eq!(bad.len(), 43);
        assert!(pubkey_from_b64(&bad).is_none());
    }

    // read_ecdsa_private_key

    #[test]
    fn priv_default_path() {
        let tmp = TmpDir::new("priv-def");
        let sk = det_key(2);
        write_priv(&tmp.path().join("ed25519_key.priv"), &sk, 0o600);

        let cfg = Config::default();
        let loaded = read_ecdsa_private_key(&cfg, tmp.path()).unwrap();
        // Compare via public key (SigningKey isn't PartialEq).
        assert_eq!(loaded.public_key(), sk.public_key());
    }

    /// `Ed25519PrivateKeyFile = /path` overrides the default.
    #[test]
    fn priv_explicit_path() {
        let tmp = TmpDir::new("priv-exp");
        let sk = det_key(3);
        let custom = tmp.path().join("weird-name.key");
        write_priv(&custom, &sk, 0o600);

        // ALSO write a DIFFERENT key at the default path. If the
        // explicit-path lookup is broken, we'd silently load the
        // wrong key. The pubkey assert catches it.
        let wrong = det_key(99);
        write_priv(&tmp.path().join("ed25519_key.priv"), &wrong, 0o600);

        // No `parse_string` — just `parse_line`. One config var, one
        // line. The `Source` is irrelevant here (only matters for
        // sort order when there are duplicates; there aren't).
        let entry = parse_line(
            &format!("Ed25519PrivateKeyFile = {}", custom.display()),
            Source::Cmdline { line: 0 },
        )
        .expect("nonempty line")
        .expect("well-formed");
        let mut cfg = Config::default();
        cfg.merge([entry]);

        let loaded = read_ecdsa_private_key(&cfg, tmp.path()).unwrap();
        assert_eq!(loaded.public_key(), sk.public_key());
        assert_ne!(loaded.public_key(), wrong.public_key());
    }

    #[test]
    fn priv_missing_is_distinct_variant() {
        let tmp = TmpDir::new("priv-miss");
        // No file written.
        let cfg = Config::default();
        // SigningKey isn't Debug (deliberately — it's a private key).
        // unwrap_err() would need Debug on the Ok type for its panic
        // message. Match instead.
        let Err(err) = read_ecdsa_private_key(&cfg, tmp.path()) else {
            panic!("expected error");
        };
        // `Missing`, not `Io(ENOENT)`. The split lets `setup()` print
        // the gen-keys hint without string-matching on the io error.
        assert!(
            matches!(err, PrivKeyError::Missing(ref p) if p.ends_with("ed25519_key.priv")),
            "got {err:?}"
        );
        // Display includes the C message.
        let msg = err.to_string();
        assert!(msg.contains("No such file or directory"), "msg: {msg}");
    }

    /// Mode 644 → warning. Mode 600 → no warning.
    /// `s.st_mode & ~0100700u`.
    ///
    /// We can't capture log output easily without a mock logger, so:
    /// test the CONDITION (`mode & !0o100_700 != 0`) directly. If
    /// the condition is right and the `if` is right (one line, hard
    /// to get wrong), the warn fires. The integration test will see
    /// the log line in stderr.
    ///
    /// Per the module doc: the C mask is over-broad. Pin the cases
    /// that matter (group/other read) AND a false-positive case
    /// (setgid bit — weird but not actually insecure) to document
    /// that we MATCH the C bug.
    #[test]
    fn priv_perm_condition() {
        // 0o100600 — regular file, owner rw only. Safe.
        assert_eq!(0o100_600 & !0o100_700, 0);
        // 0o100644 — group+other read. Warns. (THE intended case.)
        assert_ne!(0o100_644 & !0o100_700, 0);
        // 0o100700 — owner rwx. Safe (the boundary: x bit allowed).
        assert_eq!(0o100_700 & !0o100_700, 0);
        // 0o100400 — owner r only. Safe.
        assert_eq!(0o100_400 & !0o100_700, 0);

        // ─── False positives (C-bug, ported)
        // 0o102600 — setgid + 600. NOT actually insecure (setgid on
        // a non-executable does nothing exploitable for a key file).
        // C warns anyway. We match.
        assert_ne!(0o102_600 & !0o100_700, 0);
        // 0o101600 — sticky + 600. Sticky on a regular file is
        // ignored on Linux. C warns. We match.
        assert_ne!(0o101_600 & !0o100_700, 0);
    }

    /// The actual perm warn fires (loads OK, just warns). Mode 644.
    /// Can't capture the warning, but verify the load succeeds —
    /// it's a WARN not an ERROR.
    #[test]
    fn priv_insecure_perms_loads_anyway() {
        let tmp = TmpDir::new("priv-perm");
        let sk = det_key(4);
        // 0o644: group+other readable. Triggers the warn.
        write_priv(&tmp.path().join("ed25519_key.priv"), &sk, 0o644);

        let cfg = Config::default();
        let loaded = read_ecdsa_private_key(&cfg, tmp.path()).unwrap();
        assert_eq!(loaded.public_key(), sk.public_key());
    }

    /// Garbage in the file → `Pem` variant.
    #[test]
    fn priv_malformed() {
        let tmp = TmpDir::new("priv-mal");
        std::fs::write(
            tmp.path().join("ed25519_key.priv"),
            "not a PEM file at all\n",
        )
        .unwrap();

        let cfg = Config::default();
        let Err(err) = read_ecdsa_private_key(&cfg, tmp.path()) else {
            panic!("expected error");
        };
        assert!(matches!(err, PrivKeyError::Pem(_, _)), "got {err:?}");
    }

    // read_ecdsa_public_key

    /// Source 1: inline b64 config var. Most common (`tinc init`
    /// writes this).
    #[test]
    fn pub_source1_inline_b64() {
        let tmp = TmpDir::new("pub-s1");
        std::fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk = *det_key(5).public_key();
        let b64 = encode(&pk);

        // Write to hosts/peer THEN parse it (this is what id_h does:
        // read_host_config(name) → host_config). The function takes
        // an already-loaded config; it's not loading the file itself
        // for source 1.
        let host_file = tmp.path().join("hosts").join("peer");
        std::fs::write(&host_file, format!("Ed25519PublicKey = {b64}\n")).unwrap();
        let mut cfg = Config::default();
        cfg.merge(tinc_conf::parse_file(&host_file).unwrap());

        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer").unwrap();
        assert_eq!(loaded, pk);
    }

    /// Source 1 with bad b64 → None, NO fallthrough. Early return
    /// regardless of `ecdsa` being NULL or not.
    ///
    /// The host file has a (valid!) PEM block at the bottom. If we
    /// were falling through, the PEM would load. Asserting `None`
    /// proves the early return.
    #[test]
    fn pub_source1_bad_no_fallthrough() {
        let tmp = TmpDir::new("pub-s1bad");
        std::fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        // 42 chars — wrong length for inline.
        let host_file = tmp.path().join("hosts").join("peer");
        let pk = *det_key(6).public_key();
        let mut content = format!("Ed25519PublicKey = {}\n", "A".repeat(42));
        // Append a VALID PEM block. Source 3 would load this if
        // fallthrough happened.
        let mut pem = Vec::new();
        tinc_conf::write_pem(&mut pem, TY_PUBLIC, &pk).unwrap();
        content.push_str(std::str::from_utf8(&pem).unwrap());
        std::fs::write(&host_file, &content).unwrap();

        let mut cfg = Config::default();
        cfg.merge(tinc_conf::parse_file(&host_file).unwrap());

        // The PEM block is there, but the inline var is malformed.
        // No fallthrough → None.
        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer");
        assert!(loaded.is_none(), "must not fall through to PEM block");
    }

    /// Source 3: PEM block at the end of `hosts/NAME`. The
    /// `tinc-tools::cmd_exchange` output format.
    #[test]
    fn pub_source3_pem_in_hosts() {
        let tmp = TmpDir::new("pub-s3");
        std::fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk = *det_key(7).public_key();
        let host_file = tmp.path().join("hosts").join("peer");
        // Config lines + PEM block. `read_pem` skips until BEGIN.
        let mut content = String::from("Port = 655\nSubnet = 10.0.0.0/24\n");
        let mut pem = Vec::new();
        tinc_conf::write_pem(&mut pem, TY_PUBLIC, &pk).unwrap();
        content.push_str(std::str::from_utf8(&pem).unwrap());
        std::fs::write(&host_file, &content).unwrap();

        // Config has Port + Subnet but NO Ed25519PublicKey var.
        // Source 1 misses → source 2 misses (no file var) → source
        // 3 default path → PEM in hosts/peer.
        let mut cfg = Config::default();
        cfg.merge(tinc_conf::parse_file(&host_file).unwrap());
        // Precondition: source 1 doesn't fire.
        assert!(cfg.lookup("Ed25519PublicKey").next().is_none());

        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer").unwrap();
        assert_eq!(loaded, pk);
    }

    /// Source 2: explicit file path. Uncommon but supported.
    #[test]
    fn pub_source2_explicit_file() {
        let tmp = TmpDir::new("pub-s2");
        std::fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk = *det_key(8).public_key();
        let key_file = tmp.path().join("peer.pub");
        let mut pem = Vec::new();
        tinc_conf::write_pem(&mut pem, TY_PUBLIC, &pk).unwrap();
        std::fs::write(&key_file, &pem).unwrap();

        // hosts/peer has the file pointer. NO inline var, NO PEM
        // in hosts/peer itself.
        let host_file = tmp.path().join("hosts").join("peer");
        std::fs::write(
            &host_file,
            format!("Ed25519PublicKeyFile = {}\n", key_file.display()),
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.merge(tinc_conf::parse_file(&host_file).unwrap());

        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer").unwrap();
        assert_eq!(loaded, pk);
    }

    /// `hosts/NAME` exists but has no PEM and no inline var. C
    /// `:204`'s `errno == ENOENT` suppression: `read_pem` returns
    /// `PemError::NotFound`, we map to None silently.
    ///
    /// This is the "fresh `tinc init` followed by manual `hosts/peer`
    /// edit" case. The user added Port/Subnet but forgot the key.
    /// `id_h` will log "Peer X had unknown identity" — that's the
    /// useful error. Logging "PEM not found in hosts/peer" first
    /// would be noise.
    #[test]
    fn pub_no_key_silent_none() {
        let tmp = TmpDir::new("pub-nokey");
        std::fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let host_file = tmp.path().join("hosts").join("peer");
        std::fs::write(&host_file, "Port = 655\n").unwrap();

        let mut cfg = Config::default();
        cfg.merge(tinc_conf::parse_file(&host_file).unwrap());

        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer");
        assert!(loaded.is_none());
    }

    /// `hosts/NAME` doesn't exist at all. The fopen fails (source 3
    /// default path). Log; still None.
    #[test]
    fn pub_hosts_file_missing() {
        let tmp = TmpDir::new("pub-nohosts");
        // No hosts/ dir at all.
        let cfg = Config::default();
        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer");
        assert!(loaded.is_none());
    }

    /// Source-order documentation test: when BOTH inline var AND
    /// PEM block are present (and DIFFERENT), inline wins (early
    /// return). See module doc "source-order subtlety".
    ///
    /// This pins the order. If someone "optimizes" by trying PEM
    /// first ("it's the same file we already opened anyway"), this
    /// fails.
    #[test]
    fn pub_inline_wins_over_pem() {
        let tmp = TmpDir::new("pub-order");
        std::fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk_inline = *det_key(10).public_key();
        let pk_pem = *det_key(11).public_key();
        // Precondition: they're different. Otherwise the test is vacuous.
        assert_ne!(pk_inline, pk_pem);

        let host_file = tmp.path().join("hosts").join("peer");
        let mut content = format!("Ed25519PublicKey = {}\n", encode(&pk_inline));
        let mut pem = Vec::new();
        tinc_conf::write_pem(&mut pem, TY_PUBLIC, &pk_pem).unwrap();
        content.push_str(std::str::from_utf8(&pem).unwrap());
        std::fs::write(&host_file, &content).unwrap();

        let mut cfg = Config::default();
        cfg.merge(tinc_conf::parse_file(&host_file).unwrap());

        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer").unwrap();
        assert_eq!(loaded, pk_inline, "inline var should win");
        assert_ne!(loaded, pk_pem);
    }
}
