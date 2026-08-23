# Android cross-compile shell.
{
  mkShell,
  lib,
  androidenv,
  fenix,
  cargo-ndk,
  perl,
  gnumake,
}:
let
  android = import ./android-env.nix { inherit lib androidenv; };
  targets = [
    "aarch64-linux-android"
    "x86_64-linux-android"
  ];
  toolchain = fenix.combine (
    [
      fenix.stable.cargo
      fenix.stable.rustc
      fenix.stable.clippy
      fenix.stable.rustfmt
    ]
    ++ map (t: fenix.targets.${t}.stable.rust-std) targets
  );
in
mkShell (
  {
    packages = [
      toolchain
      cargo-ndk
      perl # for openssl-src
      gnumake
    ];
    ANDROID_NDK_ROOT = android.ndkRoot;
    ANDROID_NDK_HOME = android.ndkRoot;
    meta.platforms = lib.platforms.linux;
  }
  // lib.mergeAttrsList (map android.envFor targets)
)
