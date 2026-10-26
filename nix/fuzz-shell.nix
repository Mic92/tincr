# Dev shell for cargo-fuzz (see fuzz/README.md). Uses the nixpkgs rustc
# with RUSTC_BOOTSTRAP=1 instead of a separate nightly toolchain.
# nixpkgs rustc lacks the sanitizer runtimes, so run with `-s none`.
{
  lib,
  stdenv,
  mkShell,
  cargo,
  rustc,
  cargo-fuzz,
  pkg-config,
  openssl,
  libiconv,
}:
mkShell {
  packages = [
    cargo
    rustc
    cargo-fuzz
    pkg-config
    openssl # tinc-crypto ChaPoly backend
    # llvm-profdata / llvm-cov matching rustc's LLVM, for coverage runs.
    rustc.llvmPackages.llvm
  ]
  ++ lib.optionals stdenv.hostPlatform.isDarwin [ libiconv ];

  RUSTC_BOOTSTRAP = "1";

  shellHook = lib.optionalString stdenv.hostPlatform.isDarwin ''
    # libfuzzer-sys' build.rs needs -liconv on macOS.
    export LIBRARY_PATH="${libiconv}/lib''${LIBRARY_PATH:+:$LIBRARY_PATH}"
  '';
}
