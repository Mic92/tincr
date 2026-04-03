// Vendor minilzo (GPL-2.0+, same license as tinc). The C side links
// system liblzo2 via meson; we compile the compact subset directly.
// minilzo is C89 — very portable, no flags needed.
fn main() {
    println!("cargo:rerun-if-changed=minilzo/minilzo.c");
    println!("cargo:rerun-if-changed=minilzo/minilzo.h");
    println!("cargo:rerun-if-changed=minilzo/lzoconf.h");
    println!("cargo:rerun-if-changed=minilzo/lzodefs.h");
    cc::Build::new()
        .file("minilzo/minilzo.c")
        .warnings(false) // upstream code, not ours to lint
        .compile("minilzo");
}
