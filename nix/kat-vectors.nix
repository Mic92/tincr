# KAT vectors as a derivation: content-addressed, so any change to
# the C crypto sources produces a different store hash. Diffing this
# output across commits is the cheapest possible "did the wire
# format change?" check — no Rust toolchain needed.
{
  runCommandCC,
  lib,
  gnumake,
}:
runCommandCC "tinc-kat-vectors"
  {
    # Only the files the generator actually reads. The src/*.h
    # entries are needed even though their *content* is suppressed
    # by -D guard defines: the preprocessor still has to open the
    # file to discover the guard. Keeping this set minimal means
    # unrelated src/ churn doesn't invalidate the cache.
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        (lib.fileset.fileFilter (f: f.hasExt "c" || f.hasExt "h") ../kat)
        ../kat/Makefile
        ../tinc-c/src/chacha-poly1305
        ../tinc-c/src/ed25519
        ../tinc-c/src/nolegacy/prf.c
        ../tinc-c/src/system.h
        ../tinc-c/src/utils.h
        ../tinc-c/src/xalloc.h
        ../tinc-c/src/prf.h
      ];
    };
    # Nix's hardening wrapper sets -D_FORTIFY_SOURCE which warns
    # at -O0. We don't care about hardening a test-vector generator.
    hardeningDisable = [ "fortify" ];
    nativeBuildInputs = [ gnumake ];
  }
  ''
    # Makefile writes the binary next to the sources, so we need
    # a mutable copy. cp -r preserves the layout the Makefile's
    # relative paths expect.
    cp -r $src build
    chmod -R u+w build
    make -C build -f kat/Makefile OUT_JSON=$out
  ''
