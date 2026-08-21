# Android cross-compile shell.
{
  mkShell,
  lib,
  androidenv,
  fenix,
  cargo-ndk,
  perl,
  gnumake,
  gradle,
  jdk17,
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
      gradle
      jdk17
    ];
    ANDROID_NDK_ROOT = android.ndkRoot;
    ANDROID_NDK_HOME = android.ndkRoot;
    ANDROID_HOME = android.sdkRoot;
    JAVA_HOME = jdk17.home;
    # AGP's Maven aapt2 doesn't run on NixOS.
    GRADLE_OPTS = "-Dandroid.aapt2FromMavenOverride=${android.aapt2}";
    meta.platforms = lib.platforms.linux;
  }
  // lib.mergeAttrsList (map android.envFor targets)
)
