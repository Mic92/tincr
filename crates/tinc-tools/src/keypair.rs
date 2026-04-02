//! Key generation and PEM I/O. The thin glue between `tinc-crypto::sign`
//! and `tinc-conf::pem` that both binaries share.
//!
//! ## On-disk layout
//!
//! Private key file: `private[64] || public[32]` = 96 bytes, wrapped in
//! `-----BEGIN ED25519 PRIVATE KEY-----`. The C `read_pem` writes those
//! 96 bytes straight into `struct { uint8_t private[64]; uint8_t
//! public[32]; }` via the struct-overlap trick — see `tinc-conf::pem`
//! module doc. `SigningKey::from_blob` expects the same layout.
//!
//! Public key file: `public[32]`, wrapped in `-----BEGIN ED25519 PUBLIC
//! KEY-----`. One body line (32 bytes → 43 b64 chars).

use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use tinc_conf::pem::{PemError, read_pem, write_pem};
use tinc_crypto::sign::{PUBLIC_LEN, SigningKey};

/// PEM type strings. Not configurable — `ecdsagen.c:71` and `ecdsa.c:132`
/// hardcode these. (Yes, "ED25519", not "Ed25519". Upstream's casing.)
const TY_PRIVATE: &str = "ED25519 PRIVATE KEY";
const TY_PUBLIC: &str = "ED25519 PUBLIC KEY";

/// `sizeof(struct ecdsa)`. The private blob length.
const PRIVATE_BLOB_LEN: usize = 96;

/// `ecdsa_generate`: 32 bytes of OS entropy → expanded keypair.
///
/// The C `randomize(seed, 32)` reads `/dev/urandom` (or `getrandom(2)`).
/// `OsRng` does the same. The seed is zeroized before return —
/// `ecdsagen.c:43` `memzero(seed, sizeof(seed))`.
///
/// # Panics
/// Only if the OS RNG fails (`OsRng::fill_bytes` panics). At that point
/// you have bigger problems than key generation.
#[must_use]
pub fn generate() -> SigningKey {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    SigningKey::from_seed(&seed)
}

/// `ecdsa_write_pem_private_key` + `ecdsa_write_pem_public_key`.
/// Creates both files; overwrites if they exist (matches C `fopen("w")`).
///
/// # Errors
/// I/O on either file. The C version closes the private file before
/// opening the public one and bails if the second `fopen` fails — same
/// here, you can end up with a private file written and no public file.
/// Not transactional; nothing in tinc is.
pub fn write_pair(sk: &SigningKey, private: &Path, public: &Path) -> std::io::Result<()> {
    // Private: full 96-byte blob.
    {
        let f = File::create(private)?;
        let mut w = BufWriter::new(f);
        // `to_blob` returns `[u8; 96]` by value — stack-allocated, drops
        // after this block. No explicit zeroize needed for stack arrays
        // in Rust (they're not heap-spilled), but the data did flow
        // through `write_pem`'s internals, which already zeroize.
        write_pem(&mut w, TY_PRIVATE, &sk.to_blob())?;
    }
    // Public: just the 32-byte half.
    {
        let f = File::create(public)?;
        let mut w = BufWriter::new(f);
        write_pem(&mut w, TY_PUBLIC, sk.public_key())?;
    }
    Ok(())
}

/// `ecdsa_read_pem_private_key`. Loads the full keypair from a private
/// key file (the file holds both halves).
///
/// # Errors
/// `LoadError::Pem` for missing/malformed armor or wrong size,
/// `LoadError::Io` for `fopen` failure.
pub fn read_private(path: &Path) -> Result<SigningKey, LoadError> {
    let f = File::open(path).map_err(|err| LoadError::Io {
        path: path.to_owned(),
        err,
    })?;
    let blob = read_pem(f, TY_PRIVATE, PRIVATE_BLOB_LEN).map_err(|err| LoadError::Pem {
        path: path.to_owned(),
        err,
    })?;
    // `read_pem` returned exactly 96 bytes (it checked). Unwrap is the
    // length-guarantee handoff.
    let mut arr = [0u8; PRIVATE_BLOB_LEN];
    arr.copy_from_slice(&blob);
    Ok(SigningKey::from_blob(&arr))
}

/// `ecdsa_read_pem_public_key`. Just the 32 bytes.
///
/// # Errors
/// Same as [`read_private`].
pub fn read_public(path: &Path) -> Result<[u8; PUBLIC_LEN], LoadError> {
    let f = File::open(path).map_err(|err| LoadError::Io {
        path: path.to_owned(),
        err,
    })?;
    let blob = read_pem(f, TY_PUBLIC, PUBLIC_LEN).map_err(|err| LoadError::Pem {
        path: path.to_owned(),
        err,
    })?;
    let mut arr = [0u8; PUBLIC_LEN];
    arr.copy_from_slice(&blob);
    Ok(arr)
}

/// Key file load failure. Wraps the inner errors with the path because
/// the C `logger()` calls all include `argv[n]` and we want the same
/// quality of diagnostic.
#[derive(Debug)]
pub enum LoadError {
    Io {
        path: std::path::PathBuf,
        err: std::io::Error,
    },
    Pem {
        path: std::path::PathBuf,
        err: PemError,
    },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io { path, err } => {
                write!(f, "Could not open {}: {err}", path.display())
            }
            LoadError::Pem { path, err } => {
                write!(f, "Could not read key from {}: {err}", path.display())
            }
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadError::Io { err, .. } => Some(err),
            LoadError::Pem { err, .. } => Some(err),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full round-trip through the filesystem. The unit tests in
    /// `tinc-conf::pem` cover the PEM framing; this covers the *layout*
    /// (96 bytes, private||public order) and the type strings.
    #[test]
    fn roundtrip_via_disk() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("test.priv");
        let pub_path = dir.path().join("test.pub");

        let sk = generate();
        write_pair(&sk, &priv_path, &pub_path).unwrap();

        let sk2 = read_private(&priv_path).unwrap();
        let pk2 = read_public(&pub_path).unwrap();

        // Same key signs same message to same signature.
        let msg = b"roundtrip";
        assert_eq!(sk.sign(msg), sk2.sign(msg));
        // Public file matches the public half of the private file.
        assert_eq!(&pk2, sk.public_key());
        assert_eq!(&pk2, sk2.public_key());
    }

    /// The type strings are part of the on-disk format. Pin them.
    #[test]
    fn type_strings() {
        // If these change, every existing key file in the wild breaks.
        assert_eq!(TY_PRIVATE, "ED25519 PRIVATE KEY");
        assert_eq!(TY_PUBLIC, "ED25519 PUBLIC KEY");
    }

    /// Reading a public file as private fails on size mismatch.
    #[test]
    fn wrong_type_fails() {
        let dir = tempfile::tempdir().unwrap();
        let priv_path = dir.path().join("k.priv");
        let pub_path = dir.path().join("k.pub");

        let sk = generate();
        write_pair(&sk, &priv_path, &pub_path).unwrap();

        // Reading the public file as private: BEGIN type doesn't match
        // ("PUBLIC" vs "PRIVATE") → NotFound.
        assert!(matches!(
            read_private(&pub_path),
            Err(LoadError::Pem {
                err: PemError::NotFound,
                ..
            })
        ));
    }
}
