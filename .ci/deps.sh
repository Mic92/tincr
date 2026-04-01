#!/bin/sh

set -eu

SKIP_OPENSSL3="${SKIP_OPENSSL3:-}"
SKIP_MESON="${SKIP_MESON:-}"

deps_linux_alpine() {
  apk upgrade

  apk add \
    git binutils ninja pkgconf gcc linux-headers shadow sudo libgcrypt-dev texinfo gzip \
    openssl-dev zlib-dev lzo-dev ncurses-dev readline-dev musl-dev lz4-dev vde2-dev cmocka-dev

  if [ -z "$SKIP_MESON" ]; then
    apk add meson
  fi
}

deps_linux_debian_mingw() {
  apt-get install -y \
    mingw-w64 mingw-w64-tools \
    wine wine-binfmt \
    libgcrypt-mingw-w64-dev \
    "$@"
}

deps_linux_debian_linux() {
  if [ -n "$HOST" ]; then
    dpkg --add-architecture "$HOST"
  fi

  apt-get update

  apt-get install -y \
    binfmt-support binutils gcc make pkgconf \
    zlib1g-dev:"$HOST" \
    libssl-dev:"$HOST" \
    liblzo2-dev:"$HOST" \
    liblz4-dev:"$HOST" \
    libncurses-dev:"$HOST" \
    libreadline-dev:"$HOST" \
    libgcrypt-dev:"$HOST" \
    libminiupnpc-dev:"$HOST" \
    libvdeplug-dev:"$HOST" \
    libcmocka-dev:"$HOST" \
    libsystemd-dev:"$HOST" \
    "$@"

  if [ -n "$HOST" ]; then
    apt-get install -y crossbuild-essential-"$HOST" qemu-user
  else
    linux_openssl3
  fi
}

deps_linux_debian() {
  export DEBIAN_FRONTEND=noninteractive

  apt-get update
  apt-get upgrade -y
  apt-get install -y git pkgconf sudo texinfo meson

  HOST=${HOST:-}
  if [ "$HOST" = mingw ]; then
    deps_linux_debian_mingw "$@"
  else
    deps_linux_debian_linux "$@"
  fi

  if [ -n "$SKIP_MESON" ]; then
    return
  fi

  . /etc/os-release
}

deps_linux_rhel() {
  yum upgrade -y

  if [ "$ID" != fedora ]; then
    yum install -y epel-release

    if type dnf; then
      dnf install -y 'dnf-command(config-manager)'
      dnf config-manager --enable powertools || true
      dnf config-manager --enable crb || true
    fi
  fi

  yum install -y \
    git binutils make ninja-build pkgconf gcc sudo texinfo-tex systemd perl-IPC-Cmd \
    lzo-devel zlib-devel lz4-devel ncurses-devel readline-devel libgcrypt-devel systemd-devel \
    openssl-devel "$@"

  if [ -z "$SKIP_MESON" ]; then
    yum install -y meson
  fi

  if yum info miniupnpc-devel; then
    yum install -y miniupnpc-devel
  fi
}

deps_linux() {
  . /etc/os-release

  case "$ID" in
  alpine)
    deps_linux_alpine "$@"
    ;;

  debian | ubuntu)
    deps_linux_debian "$@"
    ;;

  fedora | centos | almalinux)
    deps_linux_rhel "$@"
    ;;

  *) exit 1 ;;
  esac
}

deps_macos() {
  brew install lzo lz4 miniupnpc libgcrypt openssl "$@"

  if [ -z "$SKIP_MESON" ]; then
    brew install meson
  fi
}

case "$(uname -s)" in
Linux) deps_linux "$@" ;;
Darwin) deps_macos "$@" ;;
*) exit 1 ;;
esac
