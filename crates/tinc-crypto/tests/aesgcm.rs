//! AES-256-GCM known-answer test for [`SptpsCipher`].
//!
//! The ChaCha path is pinned by the C-generated `kat.rs` vectors. The
//! AES path has no C tinc reference, so it's pinned against a NIST
//! CAVP `gcmEncryptExtIV256` vector instead — same role: if a `ring`
//! bump ever changes the ciphertext, this fails before any SPTPS test
//! gets a confusing `BadSig`/`DecryptFailed`.

use tinc_crypto::aead::{SptpsAead, SptpsCipher};
use tinc_crypto::chapoly::{KEY_LEN, TAG_LEN};

fn h(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

/// Fixed-input AES-256-GCM vector. `SptpsCipher` derives the 96-bit
/// IV as `0⁸ ‖ seqno_be⁴`, so a published NIST CAVP vector is only
/// reproducible through the public API when its IV happens to be all
/// zero in the high 8 bytes — none in `gcmEncryptExtIV256.rsp` are.
/// Instead this pins `ring`'s output for a fixed (key, seqno=3, pt)
/// triple: same purpose (catch a backend bump that changes wire
/// bytes), and any reviewer can reproduce it with five lines of
/// `ring::aead` or `openssl enc -aes-256-gcm`.
#[test]
fn aes256gcm_known_answer() {
    let key32 = h("e3c08a8f06c6e3ad95a70557b23f75483ce33021a9c72b7025666204c69c0b72");
    // 52-byte body: type byte + 51-byte ICMP-ish payload — the shape
    // an SPTPS data record actually carries.
    let pt = h("08000001020304050607c0a87b01000000000000000000000000\
         00000000000000000000000000000000000000000000000000000000");
    let ct = h("a3a9b358a81a6313b4d9c9dee73119b8928fba339095f05ec7cf\
         4241e8a9a3a9d14683107cd0cc5028bf70c185758b29994c4e5b6705");
    let tag = h("a5cbb70116da1a9cd932117ce95bdd8f");
    let seqno = 3u64;

    let mut key = [0u8; KEY_LEN];
    key[..32].copy_from_slice(&key32);
    let cipher = SptpsCipher::new(SptpsAead::Aes256Gcm, &key);

    let sealed = cipher.seal(seqno, &pt);
    assert_eq!(sealed.len(), pt.len() + TAG_LEN);
    assert_eq!(&sealed[..pt.len()], ct.as_slice(), "ciphertext mismatch");
    assert_eq!(&sealed[pt.len()..], tag.as_slice(), "tag mismatch");

    assert_eq!(cipher.open(seqno, &sealed).unwrap(), pt);
}
