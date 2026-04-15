# The Rust daemon + CLI. The NixOS module points `package =`
# here; its ExecStart hard-codes ${pkg}/bin/tincd, which is
# where buildRustPackage puts it. doCheck=false: netns tests
# need bwrap+userns the sandbox lacks. The dev shell runs the
# full suite; this is the deployment artifact.
{ rustPlatform, lib }:
rustPlatform.buildRustPackage {
  pname = "tincd";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../.cargo # x86-64-v3 + AVX2 flags; see config.toml
      ../crates
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;
  # Just the bin crates; --workspace would pull tinc-ffi's cc.
  cargoBuildFlags = [
    "-p"
    "tincd"
    "-p"
    "tinc-tools"
  ];
  doCheck = false;
  meta.mainProgram = "tincd";
}
