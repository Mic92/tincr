//! Compile sptps.c + crypto deps into a static library, link it into the crate.
//!
//! Same header-guard suppression trick as `kat/Makefile`: predefine the
//! include guards for tinc's real headers so they become no-ops, then
//! force-include `csrc/shim.h` to provide the dozen symbols sptps.c
//! actually needs.
//!
//! No bindgen. The FFI surface is five `ffi_*` functions plus two key
//! constructors — hand-declared in `lib.rs`. Bindgen would buy us
//! nothing here except a build-dep on libclang and a fight with the
//! same header tangle we just side-stepped.

use std::path::PathBuf;

fn main() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root resolves");

    let csrc = root.join("crates/tinc-ffi/csrc");
    let src = root.join("tinc-c/src");

    // The crypto sources are pure computation — no per-OS code. The same
    // file set as the KAT generator, plus sptps.c, plus ecdh.c
    // (KAT called ed25519_key_exchange directly; sptps wraps it in an
    // alloc-then-compute API we have to honor).
    let c_sources = [
        // shim
        csrc.join("shim.c"),
        csrc.join("sizeof.c"),
        // sptps state machine — brought in via #include in replay_shim.c
        // so we can wrap its statics (sptps_check_seqno). Compiling
        // sptps.c directly as well would duplicate-define every
        // non-static (sptps_start, sptps_stop, ...).
        csrc.join("replay_shim.c"),
        // chacha-poly1305
        src.join("chacha-poly1305/chacha.c"),
        src.join("chacha-poly1305/chacha-poly1305.c"),
        src.join("chacha-poly1305/poly1305.c"),
        // ed25519 (incl. ecdh.c this time — sptps needs the ecdh_t* API)
        src.join("ed25519/fe.c"),
        src.join("ed25519/ge.c"),
        src.join("ed25519/sc.c"),
        src.join("ed25519/sha512.c"),
        src.join("ed25519/keypair.c"),
        src.join("ed25519/key_exchange.c"),
        src.join("ed25519/sign.c"),
        src.join("ed25519/verify.c"),
        src.join("ed25519/ecdh.c"),
        // PRF (key derivation)
        src.join("nolegacy/prf.c"),
    ];

    let mut build = cc::Build::new();
    build
        .files(&c_sources)
        // Guard defines: make the real headers turn into no-ops.
        // Same set as kat/Makefile, plus the new headers sptps.c reaches.
        .define("TINC_SYSTEM_H", None)
        .define("TINC_UTILS_H", None)
        .define("TINC_XALLOC_H", None)
        .define("TINC_PRF_H", None)
        .define("TINC_RANDOM_H", None)
        .define("TINC_ECDSA_H", None) // we ship our own ecdsa_t in shim.c
        .define("TINC_LOGGER_H", None) // ecdh.c doesn't log, but ecdsa.c would
        // ecdh.h is left UNSUPPRESSED: sptps.h needs ECDH_SIZE for the
        // packed kex struct, and ecdh.c needs the prototype attrs to
        // line up. The header itself is benign — just two #defines and
        // three extern decls once system.h is no-opped.
        //
        // sptps.h is also unsuppressed: sizeof.c needs the struct body,
        // and sptps.c needs SPTPS_* constants.
        // Force-include the shim. Every TU gets it, including ones that
        // don't need it — harmless, the guard prevents double-include.
        .flag("-include")
        .flag(csrc.join("shim.h").to_str().unwrap())
        // sptps.h does `#include "chacha-poly1305/chacha-poly1305.h"`;
        // make that resolve.
        .include(&src)
        // Upstream's crypto code is decade-old C; suppress its warnings
        // rather than patch it. Our shim is `-Wall`-clean by hand.
        .warnings(false)
        .flag_if_supported("-Wno-unused-result")
        // subnet_compare_ipv4's `a->weight - b->weight` is signed-overflow
        // UB in stock C. The fuzzer feeds arbitrary i32 weights; without
        // -fwrapv the optimizer can assume the subtraction never wraps
        // and the divergence we're hunting becomes a heisenbug.
        .flag_if_supported("-fwrapv");

    // Honour cross-compile.
    println!("cargo:rerun-if-changed={}", csrc.display());
    for s in &c_sources {
        println!("cargo:rerun-if-changed={}", s.display());
    }
    println!("cargo:rerun-if-changed={}", src.join("sptps.h").display());

    build.compile("tinc_sptps_ffi");
}
