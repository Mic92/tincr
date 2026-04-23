//! Supply-chain pin for `asm/`: recompute SHA-256 and fail on drift,
//! so edits to vendored assembly must update `asm/PROVENANCE.md`.
//! Runs on all hosts, not just aarch64.

use sha2::{Digest, Sha256};

const PINS: &[(&str, &str)] = &[
    (
        "poly1305-armv8-apple.S",
        "ac96e8f720d97a020ea6d02dc6b5e5b04cf42967b1295ce362b52a5cabbd8e86",
    ),
    (
        "poly1305-armv8-elf.S",
        "8e2671f54298f4698e305fa1fc4c894f434f996c55128cef53aef54698a9ad2a",
    ),
    (
        "arm_arch.h",
        "b9c61ed09e70affe17ead6c456217d3fed09ca093c9d609d94e8abc9f321432d",
    ),
    (
        "poly1305_glue.c",
        "9623e96906cd4fe6f93d9ef6c75fc32b80294b45ae691d78b3eaf479181891b4",
    ),
];

#[test]
fn vendored_asm_checksums() {
    let asm = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("asm");
    for (name, want) in PINS {
        let bytes =
            std::fs::read(asm.join(name)).unwrap_or_else(|e| panic!("read asm/{name}: {e}"));
        let got = hex::encode(Sha256::digest(&bytes));
        assert_eq!(
            &got, want,
            "asm/{name} drifted from PROVENANCE.md — update the pin if this edit is intentional",
        );
    }

    // PROVENANCE.md must carry the same hashes — keep doc and pin in lockstep.
    let prov = std::fs::read_to_string(asm.join("PROVENANCE.md")).expect("read PROVENANCE.md");
    for (name, want) in PINS {
        assert!(
            prov.contains(want),
            "PROVENANCE.md missing checksum for {name}",
        );
    }
}
