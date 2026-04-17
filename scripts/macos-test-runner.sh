#!/bin/sh
# Cargo test runner for macOS. Re-execs test binaries under sudo
# when not already root, so tests requiring privileges (utun, etc.)
# work transparently.
#
# Set in .cargo/config.toml:
#   [target.aarch64-apple-darwin]
#   runner = "scripts/macos-test-runner.sh"
#
# First invocation prompts for the password interactively.
# Subsequent test binaries reuse the cached credential (sudo
# caches for ~5 min by default). Uses a lock file to ensure
# only one prompt even when cargo runs binaries in parallel.
#
# Set TINC_NO_SUDO=1 to skip escalation entirely.

if [ "${TINC_NO_SUDO:-0}" = 1 ]; then
    exec "$@"
fi

if [ "$(id -u)" -ne 0 ]; then
    # Fast path: credential already cached.
    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH,HOME,TMPDIR "$@"
    fi

    # Slow path: need to prompt. Use a lock so parallel test
    # binaries don't race multiple prompts.
    lockfile="${TMPDIR:-/tmp}/tincr-sudo-lock"

    # Spin-wait for lock (mkdir is atomic).
    while ! mkdir "$lockfile" 2>/dev/null; do
        sleep 0.1
        # Another runner may have cached the credential while we waited.
        if sudo -n true 2>/dev/null; then
            exec sudo -n --preserve-env=PATH,HOME,TMPDIR "$@"
        fi
    done

    # We hold the lock. Prompt once (only if a tty exists).
    if [ -e /dev/tty ] && sh -c ': </dev/tty' 2>/dev/null; then
        # shellcheck disable=SC2024 # redirect is FOR sudo's password prompt
        sudo -v </dev/tty
    fi
    rm -rf "$lockfile"

    if sudo -n true 2>/dev/null; then
        exec sudo -n --preserve-env=PATH,HOME,TMPDIR "$@"
    fi

    # sudo failed (no tty, user cancelled). Run unprivileged.
    exec "$@"
fi

exec "$@"
