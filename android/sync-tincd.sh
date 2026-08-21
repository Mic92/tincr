#!/usr/bin/env bash
# Build tincd for both ABIs and place it as jniLibs/<abi>/libtincd.so.
set -euo pipefail
cd "$(dirname "$0")/.."

declare -A abis=(
  [arm64-v8a]=tincd-android
  [x86_64]=tincd-android-x86_64
)
for abi in "${!abis[@]}"; do
  out=$(nix build --no-link --print-out-paths ".#${abis[$abi]}")
  install -Dm755 "$out/bin/tincd" "android/app/src/main/jniLibs/$abi/libtincd.so"
done
