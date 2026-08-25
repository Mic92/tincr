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

use std::collections::HashMap;
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use std::env;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::sync::Once;
use tinc_conf::{Config, read_pem};
use tinc_crypto::aead::{SptpsAead, hw_aes_available};
use tinc_crypto::b64;
use tinc_crypto::sign::{PUBLIC_LEN, SigningKey};

type Stamp = (Option<SystemTime>, u64);
type HostCache = Mutex<HashMap<PathBuf, (Stamp, Arc<Config>)>>;
static HOST_CACHE: OnceLock<HostCache> = OnceLock::new();

/// Read `hosts/{name}` into a [`Config`], empty on ENOENT/parse-fail.
/// Cached per path, revalidated by mtime+size so on-disk updates are seen.
#[must_use]
pub(crate) fn read_host_config(confbase: &Path, name: &str) -> Arc<Config> {
    let path = confbase.join("hosts").join(name);
    let mut cache = HOST_CACHE.get_or_init(Default::default).lock().unwrap();
    let Ok(meta) = fs::metadata(&path) else {
        cache.remove(&path);
        return Arc::default();
    };
    let stamp = (meta.modified().ok(), meta.len());
    if let Some((cached, cfg)) = cache.get(&path)
        && *cached == stamp
    {
        return Arc::clone(cfg);
    }
    let mut cfg = Config::default();
    if let Ok(entries) = tinc_conf::parse_file(&path) {
        cfg.merge(entries);
    }
    let cfg = Arc::new(cfg);
    cache.insert(path, (stamp, Arc::clone(&cfg)));
    cfg
}

/// `SPTPSCipher` from a host config; `None` if absent (global default applies).
/// An unknown value logs and yields `None` rather than an error: host files get
/// synced from peers on newer versions, and refusing to start is worse than the
/// documented `BadSig` mismatch. The no-hardware-AES warning fires once per
/// process, the first time AES-256-GCM is selected.
#[must_use]
pub(crate) fn read_sptps_cipher(host_config: &Config, name: &str) -> Option<SptpsAead> {
    let e = host_config.lookup("SPTPSCipher").next()?;
    let Some(aead) = SptpsAead::from_config_str(e.get_str()) else {
        log::warn!(target: "tincd::keys",
                   "hosts/{name}: unknown SPTPSCipher `{}' \u{2014} ignoring",
                   e.get_str());
        return None;
    };
    if aead == SptpsAead::Aes256Gcm {
        warn_aes_no_hw_once();
    }
    Some(aead)
}

/// One-shot CPU-feature warning. `Once` so the per-handshake host-file
/// read in [`read_sptps_cipher`] doesn't spam the log.
pub(crate) fn warn_aes_no_hw_once() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        if !hw_aes_available() {
            log::warn!(target: "tincd::keys",
                "SPTPSCipher = aes-256-gcm but this CPU lacks AES/PMULL \
                 acceleration; ring will fall back to bitsliced AES \
                 (slow, and table-based AES on other implementations is \
                 a cache-timing side-channel risk). Prefer \
                 chacha20-poly1305 here.");
        }
    });
}

// PEM type strings + blob length

/// Same constants as `tinc-tools/keypair.rs`. Upstream's casing —
/// "ED25519", not "Ed25519".
const TY_PRIVATE: &str = "ED25519 PRIVATE KEY";
const TY_PUBLIC: &str = "ED25519 PUBLIC KEY";

/// On-disk private blob: `expanded[64] || public[32]`. `tinc-crypto::
/// sign::SigningKey::from_blob` takes this.
const PRIVATE_BLOB_LEN: usize = 96;

/// Decode a 43-char unpadded b64 public key to 32 bytes. Length is checked
/// before decoding, as in C, so the log distinguishes "Invalid size 42" from
/// "Invalid format".
fn pubkey_from_b64(p: &str) -> Option<[u8; PUBLIC_LEN]> {
    if p.len() != 43 {
        log::debug!(target: "tincd::keys",
                    "Invalid size {} for public key (want 43)", p.len());
        return None;
    }
    let bytes = b64::decode(p)?;
    bytes.as_slice().try_into().ok().or_else(|| {
        // b64::decode of 43 chars should always give 32 bytes.
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
pub(crate) enum PrivKeyError {
    /// `ENOENT`. Carries the path for the gen-keys hint message.
    #[error("Error reading Ed25519 private key file `{}': No such file or directory", .0.display())]
    Missing(PathBuf),
    /// Any other I/O error on `fopen`.
    #[error("Error reading Ed25519 private key file `{}': {}", .0.display(), .1)]
    Io(PathBuf, #[source] io::Error),
    /// `read_pem` failed: bad armor, wrong type string, wrong size.
    #[error("Ed25519 private key in `{}' malformed: {}", .0.display(), .1)]
    Pem(PathBuf, #[source] tinc_conf::PemError),
}

fn private_key_permissions_insecure(
    path: &Path,
    mode: u32,
    credentials_directory: Option<&Path>,
) -> bool {
    let allowed = if credentials_directory.is_some_and(|dir| path.starts_with(dir)) {
        // systemd exposes service credentials as root-owned 0440 files inside
        // a per-unit directory that only the service can traverse.
        0o100_740
    } else {
        0o100_700
    };
    mode & !allowed != 0
}

/// Load the node's Ed25519 private key. Path resolution:
/// `TINCR_ED25519_PRIVATE_KEY_FILE` env var, else the
/// `Ed25519PrivateKeyFile` config var, else `confbase/ed25519_key.priv`.
///
/// # Errors
/// `Missing` if the file doesn't exist (caller prints the gen-keys
/// hint), `Io` for other fs errors, `Pem` for malformed contents.
pub(crate) fn read_ecdsa_private_key(
    config: &Config,
    confbase: &Path,
) -> Result<SigningKey, PrivKeyError> {
    // env override so service managers can inject the key without touching tinc.conf
    // (e.g. systemd LoadCredential=).
    let path = env::var_os("TINCR_ED25519_PRIVATE_KEY_FILE").map_or_else(
        || {
            config.lookup("Ed25519PrivateKeyFile").next().map_or_else(
                || confbase.join("ed25519_key.priv"),
                |e| PathBuf::from(e.get_str()),
            )
        },
        PathBuf::from,
    );

    let f = File::open(&path).map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            PrivKeyError::Missing(path.clone())
        } else {
            PrivKeyError::Io(path.clone(), err)
        }
    })?;

    if let Ok(meta) = f.metadata() {
        let mode = meta.permissions().mode();
        let credentials_directory = env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
        if private_key_permissions_insecure(&path, mode, credentials_directory.as_deref()) {
            log::warn!(target: "tincd::keys",
                       "Warning: insecure file permissions for Ed25519 private key file `{}'!",
                       path.display());
        }
    }

    let blob = read_pem(f, TY_PRIVATE, PRIVATE_BLOB_LEN).map_err(|e| PrivKeyError::Pem(path, e))?;
    let mut arr = [0u8; PRIVATE_BLOB_LEN];
    arr.copy_from_slice(&blob);
    Ok(SigningKey::from_blob(&arr))
}

/// The peer's Ed25519 public key from its already-loaded host config: inline
/// `Ed25519PublicKey` (as `tinc init` writes), else `Ed25519PublicKeyFile`,
/// else the PEM block in `hosts/NAME` (as export writes). The first source
/// found wins with no cross-check, as in C. `None` makes the caller reject the
/// peer; legacy RSA is unsupported.
#[must_use]
pub(crate) fn read_ecdsa_public_key(
    host_config: &Config,
    confbase: &Path,
    name: &str,
) -> Option<[u8; PUBLIC_LEN]> {
    // Source 1: inline b64 config var.
    if let Some(e) = host_config.lookup("Ed25519PublicKey").next() {
        // Returns NULL if the b64 is bad. NO fallthrough to source
        // 2/3. A present-but-malformed inline key is a hard
        // None, not a "try the next source". This is correct: a typo
        // in the inline var should be an error, not silently masked
        // by an old PEM block at the bottom of the file.
        return pubkey_from_b64(e.get_str());
    }

    // Source 2/3: file.
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

    // Open + parse. Errors are logged; a missing PEM block is
    // silently treated as "no key".
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

    use crate::testutil::TmpDir;
    use std::fs;
    use std::fs::OpenOptions;
    use std::io::BufWriter;
    use std::iter;
    use std::os::unix::fs::OpenOptionsExt;
    use std::str;

    /// Generate a deterministic keypair for tests. Seeded from a tag.
    fn det_key(tag: u8) -> SigningKey {
        SigningKey::from_seed(&[tag; 32])
    }

    /// Write a private key PEM file with given mode.
    fn write_priv(path: &Path, sk: &SigningKey, mode: u32) {
        let f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(path)
            .unwrap();
        let mut w = BufWriter::new(f);
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

    /// `if(strlen(p) != 43)` — the first check. Anything not 43
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
        let bad: String = iter::repeat_n('A', 42).chain(['!']).collect();
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

    /// Mode 644 warns, 600 doesn't; test the condition `mode & !0o100_700 != 0`
    /// directly since log capture needs a mock logger. The C mask is over-broad
    /// (setgid trips it); pin that we match it.
    #[test]
    fn priv_perm_condition() {
        let path = Path::new("/run/key");
        // 0o100600 — regular file, owner rw only. Safe.
        assert!(!private_key_permissions_insecure(path, 0o100_600, None));
        // 0o100644 — group+other read. Warns. (THE intended case.)
        assert!(private_key_permissions_insecure(path, 0o100_644, None));
        // 0o100700 — owner rwx. Safe (the boundary: x bit allowed).
        assert!(!private_key_permissions_insecure(path, 0o100_700, None));
        // 0o100400 — owner r only. Safe.
        assert!(!private_key_permissions_insecure(path, 0o100_400, None));

        // False positives (C-bug, ported).
        // 0o102600 — setgid + 600. not actually insecure (setgid on
        // a non-executable does nothing exploitable for a key file).
        // C warns anyway. We match.
        assert!(private_key_permissions_insecure(path, 0o102_600, None));
        // 0o101600 — sticky + 600. Sticky on a regular file is
        // ignored on Linux. C warns. We match.
        assert!(private_key_permissions_insecure(path, 0o101_600, None));
    }

    #[test]
    fn systemd_credential_permissions_are_confined() {
        let credentials = Path::new("/run/credentials/tincr-naru.service");
        let key = credentials.join("ed25519_key");

        assert!(!private_key_permissions_insecure(
            &key,
            0o100_440,
            Some(credentials),
        ));
        assert!(private_key_permissions_insecure(
            &key,
            0o100_444,
            Some(credentials),
        ));
        assert!(private_key_permissions_insecure(
            Path::new("/run/secrets/key"),
            0o100_440,
            Some(credentials),
        ));
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
        fs::write(
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
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk = *det_key(5).public_key();
        let b64 = encode(&pk);

        // Write to hosts/peer then parse it (this is what id_h does:
        // read_host_config(name) → host_config). The function takes
        // an already-loaded config; it's not loading the file itself
        // for source 1.
        let host_file = tmp.path().join("hosts").join("peer");
        fs::write(&host_file, format!("Ed25519PublicKey = {b64}\n")).unwrap();
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
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        // 42 chars — wrong length for inline.
        let host_file = tmp.path().join("hosts").join("peer");
        let pk = *det_key(6).public_key();
        let mut content = format!("Ed25519PublicKey = {}\n", "A".repeat(42));
        // Append a VALID PEM block. Source 3 would load this if
        // fallthrough happened.
        let mut pem = Vec::new();
        tinc_conf::write_pem(&mut pem, TY_PUBLIC, &pk).unwrap();
        content.push_str(str::from_utf8(&pem).unwrap());
        fs::write(&host_file, &content).unwrap();

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
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk = *det_key(7).public_key();
        let host_file = tmp.path().join("hosts").join("peer");
        // Config lines + PEM block. `read_pem` skips until BEGIN.
        let mut content = String::from("Port = 655\nSubnet = 10.0.0.0/24\n");
        let mut pem = Vec::new();
        tinc_conf::write_pem(&mut pem, TY_PUBLIC, &pk).unwrap();
        content.push_str(str::from_utf8(&pem).unwrap());
        fs::write(&host_file, &content).unwrap();

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
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk = *det_key(8).public_key();
        let key_file = tmp.path().join("peer.pub");
        let mut pem = Vec::new();
        tinc_conf::write_pem(&mut pem, TY_PUBLIC, &pk).unwrap();
        fs::write(&key_file, &pem).unwrap();

        // hosts/peer has the file pointer. NO inline var, NO PEM
        // in hosts/peer itself.
        let host_file = tmp.path().join("hosts").join("peer");
        fs::write(
            &host_file,
            format!("Ed25519PublicKeyFile = {}\n", key_file.display()),
        )
        .unwrap();

        let mut cfg = Config::default();
        cfg.merge(tinc_conf::parse_file(&host_file).unwrap());

        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer").unwrap();
        assert_eq!(loaded, pk);
    }

    /// `hosts/NAME` with no PEM and no inline key: `NotFound` maps to `None`
    /// silently. That's the "edited hosts/peer but forgot the key" case; `id_h`'s
    /// "unknown identity" is the useful error, a PEM-not-found line first would be
    /// noise.
    #[test]
    fn pub_no_key_silent_none() {
        let tmp = TmpDir::new("pub-nokey");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let host_file = tmp.path().join("hosts").join("peer");
        fs::write(&host_file, "Port = 655\n").unwrap();

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

    /// Source-order documentation test: when both inline var and
    /// PEM block are present (and DIFFERENT), inline wins (early
    /// return). See module doc "source-order subtlety".
    ///
    /// This pins the order. If someone "optimizes" by trying PEM
    /// first ("it's the same file we already opened anyway"), this
    /// fails.
    #[test]
    fn pub_inline_wins_over_pem() {
        let tmp = TmpDir::new("pub-order");
        fs::create_dir_all(tmp.path().join("hosts")).unwrap();

        let pk_inline = *det_key(10).public_key();
        let pk_pem = *det_key(11).public_key();
        // Precondition: they're different. Otherwise the test is vacuous.
        assert_ne!(pk_inline, pk_pem);

        let host_file = tmp.path().join("hosts").join("peer");
        let mut content = format!("Ed25519PublicKey = {}\n", encode(&pk_inline));
        let mut pem = Vec::new();
        tinc_conf::write_pem(&mut pem, TY_PUBLIC, &pk_pem).unwrap();
        content.push_str(str::from_utf8(&pem).unwrap());
        fs::write(&host_file, &content).unwrap();

        let mut cfg = Config::default();
        cfg.merge(tinc_conf::parse_file(&host_file).unwrap());

        let loaded = read_ecdsa_public_key(&cfg, tmp.path(), "peer").unwrap();
        assert_eq!(loaded, pk_inline, "inline var should win");
        assert_ne!(loaded, pk_pem);
    }
}
