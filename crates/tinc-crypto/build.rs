fn main() {
    // Only the aarch64 NEON Poly1305 kernel is vendored; everything
    // else uses the pure-Rust backend. The cfg this emits is what
    // `chapoly.rs` keys on, so the source has a single `#[cfg]`
    // instead of `all(feature, target_arch, unix)` everywhere.
    println!("cargo::rustc-check-cfg=cfg(tinc_poly1305_asm)");

    let asm = std::env::var("CARGO_FEATURE_VENDORED_POLY1305_ASM").is_ok();
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if !(asm && arch == "aarch64") {
        return;
    }

    let src = match os.as_str() {
        "macos" | "ios" => "asm/poly1305-armv8-apple.S",
        // ELF flavours: Linux, *BSD, Android.
        _ => "asm/poly1305-armv8-elf.S",
    };

    cc::Build::new()
        .file(src)
        .file("asm/poly1305_glue.c")
        .include("asm")
        .flag("-fvisibility=hidden")
        .compile("tinc_poly1305_armv8");

    println!("cargo::rustc-cfg=tinc_poly1305_asm");
    println!("cargo::rerun-if-changed=asm");
}
