{
  lib,
  runCommand,
  androidenv,
  jdk17,
  tincr-app,
}:
let
  android = import ./android-env.nix { inherit lib androidenv; };
  app = tincr-app.override { abi = "x86_64"; };
in
runCommand "android-mesh-check"
  {
    nativeBuildInputs = [
      android.fullSdk
      jdk17
    ];
    requiredSystemFeatures = [ "kvm" ];
  }
  ''
    export HOME=$TMPDIR ANDROID_USER_HOME=$TMPDIR/android-user
    export ANDROID_HOME=${android.fullSdkRoot} ANDROID_SDK_ROOT=${android.fullSdkRoot}
    export ANDROID_AVD_HOME=$TMPDIR/avd
    mkdir -p "$ANDROID_AVD_HOME"

    printf 'no\n' | avdmanager create avd -n test \
      -k "system-images;android-35;google_apis;x86_64"

    adb start-server
    emulator -avd test -no-window -no-audio -no-boot-anim \
      -gpu swiftshader_indirect -no-snapshot &
    adb wait-for-device
    for _ in $(seq 150); do
      [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
      sleep 2
    done
    [ "$(adb shell getprop sys.boot_completed | tr -d '\r')" = 1 ]

    adb install ${app}/tincr.apk
    adb install ${app}/tincr-test.apk
    adb shell am instrument -w \
      io.thalheim.tincr.test/androidx.test.runner.AndroidJUnitRunner \
      | tee instrument.log
    grep -q "OK (1 test" instrument.log

    adb emu kill || true
    touch $out
  ''
