# The C tincd daemon. Target for crates/tincd/tests/
# crossimpl.rs (TINC_C_TINCD=$out/bin/tincd) and the
# nixos-tinc-crossimpl VM test. OpenSSL not nolegacy: the
# NixOS module's preStart calls `tinc generate-rsa-keys`,
# which nolegacy tincctl rejects at the dispatch table.
# Legacy C still negotiates SPTPS-only against us (no RSA
# pubkey in hosts/ → no legacy offered).
{
  stdenv,
  meson,
  ninja,
  pkg-config,
  openssl,
}:
stdenv.mkDerivation {
  pname = "tinc-tincd-c";
  version = "1.1pre18";
  src = ../tinc-c;
  nativeBuildInputs = [
    meson
    ninja
    pkg-config
  ];
  buildInputs = [ openssl ];
  # Meson defaults sysconfdir to $out/etc; the NixOS module
  # calls `tinc -n NET ...` without -c and expects /etc.
  mesonFlags = [
    "--sysconfdir=/etc"
    "--localstatedir=/var"
    "-Dcrypto=openssl" # default; explicit vs. sptps-test-c
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
  # Default mesonInstallPhase. tincd lands in $out/sbin
  # (meson.build sets install_dir: dir_sbin); also installs
  # tinc(ctl) and the bash completion. We only care about
  # tincd but the extras are harmless and overriding is
  # more lines than not.
}
