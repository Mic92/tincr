# The C sptps_test/sptps_keypair binaries, built with meson in
# nolegacy mode (no openssl/gcrypt — same crypto subset as
# tinc-crypto). nixpkgs#tinc_pre doesn't ship these; they're
# build_by_default=false in src/meson.build. Consumed by
# crates/tinc-tools/tests/self_roundtrip.rs via the
# TINC_C_SPTPS_TEST / TINC_C_SPTPS_KEYPAIR env vars.
{
  stdenv,
  meson,
  ninja,
  pkg-config,
}:
stdenv.mkDerivation {
  pname = "tinc-sptps-test-c";
  version = "1.1pre18";
  # The whole upstream tree: any change in tinc-c/ is by
  # definition a C-side change that should invalidate the
  # cross-impl binaries.
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
    "-Dtunemu=disabled"
    "-Dvmnet=disabled"
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
