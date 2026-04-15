# The C sptps_test/sptps_keypair binaries, built with meson in
# nolegacy mode (no openssl/gcrypt — same crypto subset as
# tinc-crypto). nixpkgs#tinc_pre doesn't ship these; they're
# build_by_default=false in src/meson.build.
#
# `TINC_C_SPTPS_TEST` / `TINC_C_SPTPS_KEYPAIR` point here for
# the cross-impl tests in tinc-tools/tests/self_roundtrip.rs.
# The devshell sets both — see the comment there about why
# the src/-only fileset makes that free for Rust-side edits.
{
  stdenv,
  meson,
  ninja,
  pkg-config,
}:
stdenv.mkDerivation {
  pname = "tinc-sptps-test-c";
  version = "1.1pre18";
  # Fileset: meson needs the whole src/ tree (the meson.build
  # files reference each other), plus the top-level meson
  # config. No point being clever about minimizing this —
  # it's ~500 small files, derivation rebuild is cheap, and
  # any src/ change SHOULD invalidate it (that's the point of
  # cross-impl: test against the C-that-is, not the C-that-was).
  # The whole upstream tree. We used to fileset-minimize this,
  # but now that it lives in tinc-c/ the boundary is the
  # directory itself — any change in there is by definition a
  # C-side change that should invalidate the cross-impl binaries.
  src = ../tinc-c;
  nativeBuildInputs = [
    meson
    ninja
    pkg-config
  ];
  mesonFlags = [
    # No openssl, no gcrypt. Disables the legacy protocol
    # entirely. SPTPS doesn't need it.
    "-Dcrypto=nolegacy"
    # Silence everything optional. We only want two binaries.
    "-Dminiupnpc=disabled"
    "-Dcurses=disabled"
    "-Dreadline=disabled"
    "-Dzlib=disabled"
    "-Dlzo=disabled"
    "-Dlz4=disabled"
    "-Dvde=disabled"
    "-Ddocs=disabled"
    "-Dtests=disabled"
    "-Dsystemd=disabled"
  ];
  # build_by_default=false — ask for them explicitly.
  ninjaFlags = [
    "src/sptps_test"
    "src/sptps_keypair"
  ];
  # mesonInstallPhase wants to install everything; we only
  # built two targets. Override.
  installPhase = ''
    mkdir -p $out/bin
    install -m755 src/sptps_test src/sptps_keypair $out/bin/
  '';
}
