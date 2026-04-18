# The Rust daemon + CLI. The NixOS module points `package =` here; its
# ExecStart hard-codes ${pkg}/bin/tincd, which is where crane puts it.
#
# crane splits the build: `buildDepsOnly` compiles every crates.io dep
# into one derivation keyed on Cargo.lock, then `buildPackage` reuses
# that and only rebuilds workspace crates. The hot redeploy loop
# (./scripts/deploy-agent-fix.sh) was paying ~55s × 2 arches per
# commit under buildRustPackage; now src-only changes touch ~10s of
# workspace recompile.
{
  craneLib,
  lib,
  installShellFiles,
}:
let
  rustSrc = lib.fileset.unions [
    ../Cargo.toml
    ../Cargo.lock
    ../.cargo # x86-64-v3 + AVX2 flags; see config.toml
    ../crates
  ];
  mkSrc =
    fs:
    lib.fileset.toSource {
      root = ../.;
      fileset = fs;
    };
  common = {
    src = mkSrc rustSrc;
    pname = "tincd";
    version = "0.1.0";
    strictDeps = true;
    # Just the bin crates; --workspace would pull tinc-ffi's cc.
    cargoExtraArgs = "-p tincd -p tinc-tools";
    # netns tests need bwrap+userns the sandbox lacks. The dev shell
    # runs the full suite; this is the deployment artifact.
    doCheck = false;
  };
  # Dummy src/{lib,main}.rs from every workspace Cargo.toml; compiles
  # all crates.io deps. Rebuilds only when Cargo.{toml,lock} change.
  cargoArtifacts = craneLib.buildDepsOnly common;
in
craneLib.buildPackage (
  common
  // {
    inherit cargoArtifacts;
    # man/ only here so editing a page doesn't rebuild cargoArtifacts.
    src = mkSrc (lib.fileset.union rustSrc ../man);
    nativeBuildInputs = [ installShellFiles ];
    # Hand-written mdoc; committed so the build stays hermetic and
    # diffs are reviewable. Regenerate by editing man/*.? directly.
    postInstall = ''
      installManPage man/*.[0-9]
    '';
    meta.mainProgram = "tincd";
  }
)
