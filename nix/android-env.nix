# Pinned NDK and per-target cargo/cc env, shared by the android
# devshell and the tincd-android package.
{ lib, androidenv }:
let
  composition = androidenv.composeAndroidPackages {
    includeNDK = true;
    # r27 LTS, pinned so the toolchain doesn't move on nixpkgs bumps.
    ndkVersion = "27.2.12479018";
    platformVersions = [ "35" ];
  };
  # Separate so cross-compile env doesn't rebuild when this changes.
  fullComposition = androidenv.composeAndroidPackages {
    platformVersions = [ "35" ];
    buildToolsVersions = [ "35.0.0" ];
    includeEmulator = true;
    includeSystemImages = true;
    systemImageTypes = [ "google_apis" ];
    abiVersions = [ "x86_64" ];
  };
  fullSdkRoot = "${fullComposition.androidsdk}/libexec/android-sdk";
  ndkRoot = "${composition.androidsdk}/libexec/android-sdk/ndk-bundle";
  ndkBin = "${ndkRoot}/toolchains/llvm/prebuilt/linux-x86_64/bin";
  api = "24"; # min API
in
{
  inherit ndkRoot fullSdkRoot;
  fullSdk = fullComposition.androidsdk;
  aapt2 = "${fullSdkRoot}/build-tools/35.0.0/aapt2";
  envFor =
    target:
    let
      u = lib.replaceStrings [ "-" ] [ "_" ] target;
      cc = "${ndkBin}/${target}${api}-clang";
    in
    {
      "CARGO_TARGET_${lib.toUpper u}_LINKER" = cc;
      # Google Play requires 16 KB page support for targetSdk 35.
      "CARGO_TARGET_${lib.toUpper u}_RUSTFLAGS" = "-C link-arg=-Wl,-z,max-page-size=16384";
      "CC_${u}" = cc;
      "AR_${u}" = "${ndkBin}/llvm-ar";
      "RANLIB_${u}" = "${ndkBin}/llvm-ranlib";
    };
}
