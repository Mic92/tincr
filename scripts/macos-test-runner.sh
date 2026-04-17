#!/bin/sh
# Cargo test runner for macOS. Re-execs test binaries under sudo
# when not already root, so tests requiring privileges (utun, etc.)
# work transparently.
#
# Set in .cargo/config.toml:
#   [target.aarch64-apple-darwin]
#   runner = "scripts/macos-test-runner.sh"
#
# First invocation prompts for the password (sudo -v caches it).
# Subsequent test binaries in the same cargo test run reuse the
# cached credential. Set TINC_NO_SUDO=1 to skip escalation.

if [ "${TINC_NO_SUDO:-0}" = 1 ]; then
    exec "$@"
fi

if [ "$(id -u)" -ne 0 ]; then
    # Validate/cache credential. Interactive — may prompt once.
    # If stdin isn't a tty (CI without sudo), this fails and we
    # fall through to run unprivileged (tests SKIP themselves).
    if ! sudo -v 2>/dev/null; then
        exec "$@"
    fi
    exec sudo --preserve-env=PATH,HOME,TMPDIR "$@"
fi

exec "$@"
