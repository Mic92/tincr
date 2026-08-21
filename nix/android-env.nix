# Pinned NDK and per-target cargo/cc env, shared by the android
# devshell and the tincd-android package.
{ lib, androidenv }:
let
  composition = androidenv.composeAndroidPackages {
    includeNDK = true;
    # r27 LTS, pinned so the toolchain doesn't move on nixpkgs bumps.
    ndkVersion = "27.2.12479018";
    platformVersions = [ "35" ];
    buildToolsVersions = [ "35.0.0" ];
  };
  sdkRoot = "${composition.androidsdk}/libexec/android-sdk";
  ndkRoot = "${composition.androidsdk}/libexec/android-sdk/ndk-bundle";
  # NDK ships linux-x86_64 host prebuilts only.
  ndkBin = "${ndkRoot}/toolchains/llvm/prebuilt/linux-x86_64/bin";
  api = "24"; # min API, encoded in the clang wrapper name
in
{
  inherit ndkRoot sdkRoot;
  aapt2 = "${sdkRoot}/build-tools/35.0.0/aapt2";
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
