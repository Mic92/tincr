# Android cross build of tincd. CI builds this instead of a cargo job.
{
  craneLib,
  lib,
  fenix,
  androidenv,
  perl,
  target ? "aarch64-linux-android",
}:
let
  android = import ./android-env.nix { inherit lib androidenv; };
  toolchain = fenix.combine [
    fenix.stable.cargo
    fenix.stable.rustc
    fenix.targets.${target}.stable.rust-std
  ];
  craneLib' = craneLib.overrideToolchain toolchain;
  common = {
    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../Cargo.toml
        ../Cargo.lock
        ../crates
      ];
    };
    pname = "tincd-android";
    version = "0.1.0";
    strictDeps = true;
    cargoExtraArgs = "-p tincd";
    nativeBuildInputs = [ perl ]; # openssl-src
    doCheck = false;
    CARGO_BUILD_TARGET = target;
  }
  // android.envFor target;
  cargoArtifacts = craneLib'.buildDepsOnly common;
in
craneLib'.buildPackage (common // { inherit cargoArtifacts; })
