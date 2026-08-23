{
  lib,
  stdenv,
  gradle,
  jdk17,
  androidenv,
  tincd-android,
  # Emulator runs x86_64 while devices want aarch64.
  abi ? "arm64-v8a",
}:
let
  android = import ./android-env.nix { inherit lib androidenv; };
  abiTarget = {
    "arm64-v8a" = "aarch64-linux-android";
    "x86_64" = "x86_64-linux-android";
  };
  tincd = tincd-android.override { target = abiTarget.${abi}; };
in
stdenv.mkDerivation (finalAttrs: {
  pname = "tincr-app";
  version = "0.1.0";

  src = lib.fileset.toSource {
    root = ../android;
    fileset = lib.fileset.unions [
      ../android/app/src
      ../android/app/build.gradle.kts
      ../android/build.gradle.kts
      ../android/settings.gradle.kts
      ../android/gradle.properties
    ];
  };

  nativeBuildInputs = [
    gradle
    jdk17
  ];

  mitmCache = gradle.fetchDeps {
    pkg = finalAttrs.finalPackage;
    data = ./android-app-deps.json;
  };

  postPatch = ''
    mkdir -p app/src/main/jniLibs/${abi}
    cp ${tincd}/bin/tincd app/src/main/jniLibs/${abi}/libtincd.so
    echo "android.aapt2FromMavenOverride=${android.aapt2}" >> gradle.properties
  '';

  preBuild = ''
    export ANDROID_USER_HOME=$TMPDIR/android-user
  '';

  gradleBuildTask = [
    "assembleDebug"
    "assembleDebugAndroidTest"
  ];
  doCheck = false;
  # AGP variant matching breaks the generic nixDownloadDeps task.
  gradleUpdateTask = "assembleDebug assembleDebugAndroidTest";

  env.ANDROID_HOME = android.fullSdkRoot;

  installPhase = ''
    runHook preInstall
    install -Dm644 app/build/outputs/apk/debug/app-debug.apk \
      $out/tincr.apk
    install -Dm644 app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk \
      $out/tincr-test.apk
    runHook postInstall
  '';
})
