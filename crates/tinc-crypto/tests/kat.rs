//! Known-answer tests against `kat/vectors.json`, generated from the C
//! sources by `kat/gen_kat.c` (`make -f kat/Makefile`). A failure after
//! a dependency bump means the dependency changed, not the test.

use serde::Deserialize;
use tinc_crypto::aead::{SptpsAead, SptpsCipher};
use tinc_crypto::chapoly::{KEY_LEN, TAG_LEN};
use tinc_crypto::{b64, chapoly, ecdh, invite, prf, sign};

const VECTORS_JSON: &str = include_str!("kat/vectors.json");

// Hex strings; seqno is decimal because JSON numbers cannot hold u64.

#[derive(Deserialize)]
struct Vectors {
    chapoly: Vec<ChaPolyVec>,
    ecdh: Vec<EcdhVec>,
    prf: Vec<PrfVec>,
    sign: Vec<SignVec>,
    b64: Vec<B64Vec>,
    invitation: Vec<InvitationVec>,
}

#[derive(Deserialize)]
struct ChaPolyVec {
    key: String,
    seqno: String,
    plaintext: String,
    ciphertext: String,
}

#[derive(Deserialize)]
struct EcdhVec {
    seed_a: String,
    priv_a: String,
    pub_a: String,
    seed_b: String,
    #[expect(dead_code)]
    #[serde(skip)]
    priv_b: (),
    pub_b: String,
    shared: String,
}

#[derive(Deserialize)]
struct PrfVec {
    secret: String,
    seed: String,
    out: String,
}

#[derive(Deserialize)]
struct SignVec {
    seed: String,
    expanded_private: String,
    public: String,
    message: String,
    signature: String,
}

#[derive(Deserialize)]
struct B64Vec {
    raw: String,
    encoded_std: String,
    encoded_urlsafe: String,
}

#[derive(Deserialize)]
struct InvitationVec {
    key_seed: String,
    cookie: String,
    pubkey: String,
    fingerprint: String,
    key_hash_b64: String,
    cookie_b64: String,
    cookie_hash_b64: String,
}

fn vectors() -> Vectors {
    serde_json::from_str(VECTORS_JSON).expect("vectors.json is well-formed")
}

fn hex_arr<const N: usize>(s: &str, what: &str) -> [u8; N] {
    let v = hex::decode(s).unwrap_or_else(|e| panic!("{what}: bad hex: {e}"));
    v.try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("{what}: want {N} bytes, got {}", v.len()))
}

#[test]
fn chapoly_seal_matches_c() {
    for (i, v) in vectors().chapoly.iter().enumerate() {
        let key: [u8; 64] = hex_arr(&v.key, "key");
        let seqno: u64 = v.seqno.parse().unwrap();
        let pt = hex::decode(&v.plaintext).unwrap();
        let want = hex::decode(&v.ciphertext).unwrap();

        let cp = chapoly::ChaPoly::new(&key);
        let got = cp.seal(seqno, &pt);

        assert_eq!(
            hex::encode(&got),
            hex::encode(&want),
            "chapoly[{i}] seqno={seqno} ptlen={}",
            pt.len()
        );

        let reopened = cp.open(seqno, &got).expect("round-trip open");
        assert_eq!(reopened, pt, "chapoly[{i}] round-trip");

        // The `_into` variants with prefix/headroom, as the daemon uses them.
        let mut sealed = vec![0u8; 4]; // pretend seqno header
        if !pt.is_empty() {
            cp.seal_into(seqno, pt[0], &pt[1..], &mut sealed, 4);
            assert_eq!(&sealed[4..], &got[..], "chapoly[{i}] seal_into");
        }
        let mut opened = vec![0u8; 7]; // arbitrary headroom
        cp.open_into(seqno, &got, &mut opened, 7)
            .expect("round-trip open_into");
        assert_eq!(&opened[..7], &[0u8; 7], "chapoly[{i}] headroom untouched");
        assert_eq!(&opened[7..], &pt[..], "chapoly[{i}] open_into round-trip");
    }
}

#[test]
fn chapoly_open_rejects_tampered() {
    let v = vectors()
        .chapoly
        .into_iter()
        .find(|v| !v.plaintext.is_empty())
        .expect("at least one non-empty chapoly vector");
    let key: [u8; 64] = hex_arr(&v.key, "key");
    let seqno: u64 = v.seqno.parse().unwrap();
    let mut sealed = hex::decode(&v.ciphertext).unwrap();

    let cp = chapoly::ChaPoly::new(&key);
    sealed[0] ^= 1;
    assert!(cp.open(seqno, &sealed).is_err(), "flipped CT byte accepted");
    sealed[0] ^= 1;

    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    assert!(
        cp.open(seqno, &sealed).is_err(),
        "flipped tag byte accepted"
    );
}

#[test]
fn ecdh_from_seed_matches_c() {
    for (i, v) in vectors().ecdh.iter().enumerate() {
        let seed_a: [u8; 32] = hex_arr(&v.seed_a, "seed_a");
        let seed_b: [u8; 32] = hex_arr(&v.seed_b, "seed_b");
        let want_pub_a: [u8; 32] = hex_arr(&v.pub_a, "pub_a");
        let want_pub_b: [u8; 32] = hex_arr(&v.pub_b, "pub_b");
        let want_priv_a: [u8; 64] = hex_arr(&v.priv_a, "priv_a");
        let want_shared: [u8; 32] = hex_arr(&v.shared, "shared");

        let (priv_a, pub_a) = ecdh::EcdhPrivate::from_seed(&seed_a);
        let (priv_b, pub_b) = ecdh::EcdhPrivate::from_seed(&seed_b);
        assert_eq!(pub_a, want_pub_a, "ecdh[{i}] pub_a");
        assert_eq!(pub_b, want_pub_b, "ecdh[{i}] pub_b");

        let shared_ab = priv_a.compute_shared(&pub_b).unwrap();
        let shared_ba = priv_b.compute_shared(&pub_a).unwrap();
        assert_eq!(
            hex::encode(shared_ab),
            hex::encode(want_shared),
            "ecdh[{i}] shared a→b"
        );
        assert_eq!(shared_ab, shared_ba, "ecdh[{i}] commutativity");

        // On-disk keys load via from_expanded.
        let priv_a_expanded = ecdh::EcdhPrivate::from_expanded(&want_priv_a);
        let shared_expanded = priv_a_expanded.compute_shared(&want_pub_b).unwrap();
        assert_eq!(shared_expanded, want_shared, "ecdh[{i}] from_expanded");
    }
}

#[test]
fn prf_matches_c() {
    for (i, v) in vectors().prf.iter().enumerate() {
        let secret = hex::decode(&v.secret).unwrap();
        let seed = hex::decode(&v.seed).unwrap();
        let want = hex::decode(&v.out).unwrap();

        let mut got = vec![0u8; want.len()];
        prf::prf(&secret, &seed, &mut got);

        assert_eq!(
            hex::encode(&got),
            hex::encode(&want),
            "prf[{i}] secretlen={} seedlen={} outlen={}",
            secret.len(),
            seed.len(),
            want.len()
        );
    }
}

#[test]
fn sign_matches_c() {
    for (i, v) in vectors().sign.iter().enumerate() {
        let seed: [u8; 32] = hex_arr(&v.seed, "seed");
        let want_expanded: [u8; 64] = hex_arr(&v.expanded_private, "expanded");
        let want_public: [u8; 32] = hex_arr(&v.public, "public");
        let msg = hex::decode(&v.message).unwrap();
        let want_sig: [u8; 64] = hex_arr(&v.signature, "signature");

        let sk = sign::SigningKey::from_seed(&seed);
        assert_eq!(sk.expanded_private(), &want_expanded, "sign[{i}] expanded");
        assert_eq!(sk.public(), &want_public, "sign[{i}] public");

        let got_sig = sk.sign(&msg);
        assert_eq!(
            hex::encode(got_sig),
            hex::encode(want_sig),
            "sign[{i}] msglen={}",
            msg.len()
        );

        sign::verify(&want_public, &msg, &got_sig).expect("sign[{i}] verify");
    }
}

#[test]
fn b64_encode_matches_c() {
    for (i, v) in vectors().b64.iter().enumerate() {
        let raw = hex::decode(&v.raw).unwrap();

        assert_eq!(b64::encode(&raw), v.encoded_std, "b64[{i}] std encode");
        assert_eq!(
            b64::encode_urlsafe(&raw),
            v.encoded_urlsafe,
            "b64[{i}] urlsafe encode"
        );

        assert_eq!(
            b64::decode(&v.encoded_std).as_deref(),
            Some(&raw[..]),
            "b64[{i}] std decode"
        );
        assert_eq!(
            b64::decode(&v.encoded_urlsafe).as_deref(),
            Some(&raw[..]),
            "b64[{i}] urlsafe decode"
        );
    }
}

#[test]
fn b64_decode_accepts_mixed_alphabet() {
    // C's decoder table accepts both alphabets mixed in one string.
    //
    let v = vectors()
        .b64
        .into_iter()
        .find(|v| v.encoded_urlsafe.contains('-') || v.encoded_urlsafe.contains('_'))
        .expect("at least one vector with special chars");
    let raw = hex::decode(&v.raw).unwrap();

    let mut mixed = String::new();
    let mut flip = false;
    for c in v.encoded_urlsafe.chars() {
        mixed.push(match c {
            '-' if flip => '+',
            '_' if flip => '/',
            other => other,
        });
        if matches!(c, '-' | '_') {
            flip = !flip;
        }
    }
    assert_ne!(mixed, v.encoded_std);
    assert_ne!(mixed, v.encoded_urlsafe);

    assert_eq!(
        b64::decode(&mixed).as_deref(),
        Some(&raw[..]),
        "mixed-alphabet decode"
    );
}

/// Each stage of the invitation slug asserted separately so a failure
/// names the stage.
#[test]
fn invitation_crypto_kernel_matches_c() {
    for (i, v) in vectors().invitation.iter().enumerate() {
        let seed: [u8; 32] = hex_arr(&v.key_seed, "key_seed");
        let cookie: [u8; invite::COOKIE_LEN] = hex_arr(&v.cookie, "cookie");
        let want_pubkey: [u8; 32] = hex_arr(&v.pubkey, "pubkey");

        let sk = sign::SigningKey::from_seed(&seed);
        let pubkey = *sk.public_key();
        assert_eq!(
            pubkey, want_pubkey,
            "case {i}: pubkey mismatch (sign::from_seed disagrees with C)"
        );

        // Standard alphabet, and it is this string that gets hashed.
        let fp = invite::fingerprint(&pubkey);
        assert_eq!(fp, v.fingerprint, "case {i}: fingerprint (b64 alphabet?)");
        assert_eq!(fp.len(), 43, "case {i}: fingerprint length");

        let kh = invite::key_hash(&pubkey);
        assert_eq!(
            b64::encode_urlsafe(&kh),
            v.key_hash_b64,
            "case {i}: key_hash (hashed raw pubkey instead of b64 string?)"
        );

        assert_eq!(
            b64::encode_urlsafe(&cookie),
            v.cookie_b64,
            "case {i}: cookie b64 (alphabet?)"
        );

        // cookie ‖ fingerprint, in that order.
        assert_eq!(
            invite::cookie_filename(&cookie, &pubkey),
            v.cookie_hash_b64,
            "case {i}: cookie_hash (cookie/fingerprint order?)"
        );
        assert_eq!(v.cookie_hash_b64.len(), invite::SLUG_PART_LEN);

        let slug = invite::build_slug(&pubkey, &cookie);
        assert_eq!(slug.len(), invite::SLUG_LEN);
        assert_eq!(
            slug,
            format!("{}{}", v.key_hash_b64, v.cookie_b64),
            "case {i}: full slug"
        );

        let (parsed_hash, parsed_cookie) = invite::parse_slug(&slug).unwrap();
        assert_eq!(parsed_cookie, cookie, "case {i}: parsed cookie");
        assert_eq!(parsed_hash, kh, "case {i}: parsed key_hash");
    }
}

/// No C reference and no NIST vector fits `SptpsCipher`'s IV layout, so
/// this pins the backend's output; a dependency bump that changes wire
/// bytes fails here.
#[test]
fn aes256gcm_known_answer() {
    let h = |s: &str| hex::decode(s).unwrap();
    let key32 = h("e3c08a8f06c6e3ad95a70557b23f75483ce33021a9c72b7025666204c69c0b72");
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
