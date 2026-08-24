# The Rust daemon + CLI. The NixOS module points `package =` here; its
# ExecStart hard-codes ${pkg}/bin/tincd, which is where crane puts it.
#
# crane splits the build: `buildDepsOnly` compiles every crates.io dep
# keyed on Cargo.lock, then `buildPackage` reuses that and only
# rebuilds workspace crates on src-only changes.
{
  craneLib,
  lib,
  stdenv,
  installShellFiles,
  pkg-config,
  openssl,
  # test-only inputs, see passthru.tests
  bubblewrap ? null,
  iproute2 ? null,
  iputils ? null,
  util-linux ? null,
  miniupnpd-nftables ? null,
  nftables ? null,
  iperf3 ? null,
  tincd-c ? null,
  sptps-test-c ? null,
  # true → drop the x86-64-v3/AVX2 floor from .cargo/config.toml so
  # the binary runs on pre-Haswell x86_64. No SIGILL; the OpenSSL
  # AEAD kernels dispatch at runtime either way.
  baselineCpu ? false,
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
    # openssl-sys (tinc-crypto's ChaPoly backend)
    nativeBuildInputs = [ pkg-config ];
    buildInputs = [ openssl ];
    # netns tests need bwrap+userns the sandbox lacks. The dev shell
    # runs the full suite; this is the deployment artifact.
    doCheck = false;
    # Loopback-socket tests need this under the darwin sandbox.
    __darwinAllowLocalNetworking = true;
  }
  // lib.optionalAttrs baselineCpu {
    # Env RUSTFLAGS replaces .cargo/config.toml's target.* rustflags
    # (cargo does not merge them); restate frame-pointers, omit
    # target-cpu=x86-64-v3.
    RUSTFLAGS = "-C force-frame-pointers=yes";
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
    nativeBuildInputs = [
      installShellFiles
      pkg-config
    ];
    # Hand-written mdoc; committed so the build stays hermetic and
    # diffs are reviewable. Regenerate by editing man/*.? directly.
    postInstall = ''
      installManPage man/*.[0-9]
    '';
    # `--workspace` needs tinc-c (tinc-ffi's build.rs compiles it).
    passthru.clippy = craneLib.cargoClippy (
      common
      // {
        inherit cargoArtifacts;
        src = mkSrc (
          lib.fileset.unions [
            rustSrc
            ../clippy.toml
            ../tinc-c
          ]
        );
        cargoExtraArgs = "--workspace";
        cargoClippyExtraArgs = "--all-targets -- -D warnings";
      }
    );
    passthru.tests = craneLib.cargoTest (
      common
      // {
        inherit cargoArtifacts;
        doCheck = true;
        cargoExtraArgs = "--workspace";
        # tinc-ffi vendors the C implementation for differential tests.
        # .cargo/config.toml points at scripts/macos-test-runner.sh.
        src = mkSrc (
          lib.fileset.unions [
            rustSrc
            ../tinc-c
            ../scripts/macos-test-runner.sh
          ]
        );
        nativeCheckInputs = [
          iperf3
        ]
        ++ lib.optionals stdenv.hostPlatform.isLinux [
          bubblewrap
          iproute2
          iputils
          util-linux
          miniupnpd-nftables
          nftables
        ];
      }
      # Cross-impl wire-compat tests gate on these; unset → SKIP.
      // lib.optionalAttrs (tincd-c != null) {
        TINC_C_TINCD = "${tincd-c}/sbin/tincd";
      }
      // lib.optionalAttrs (sptps-test-c != null) {
        TINC_C_SPTPS_TEST = "${sptps-test-c}/bin/sptps_test";
        TINC_C_SPTPS_KEYPAIR = "${sptps-test-c}/bin/sptps_keypair";
      }
    );
    meta.mainProgram = "tincd";
  }
)
