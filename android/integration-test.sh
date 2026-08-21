#!/usr/bin/env bash
# Run instrumentation tests on a headless AVD (nix develop .#android).
set -euo pipefail
cd "$(dirname "$0")"

export ANDROID_AVD_HOME="${XDG_CACHE_HOME:-$HOME/.cache}/tincr/avd"
mkdir -p "$ANDROID_AVD_HOME"
avd=tincr-test
if ! avdmanager list avd -c | grep -qx "$avd"; then
  printf 'no\n' | avdmanager create avd -n "$avd" \
    -k "system-images;android-35;google_apis;x86_64"
fi

adb start-server
emulator -avd "$avd" -no-window -no-audio -no-boot-anim \
  -gpu swiftshader_indirect -no-snapshot &
trap 'kill %1 2>/dev/null || true' EXIT
adb wait-for-device
for _ in $(seq 120); do
  [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = 1 ] && break
  sleep 2
done

gradle --no-daemon connectedDebugAndroidTest
