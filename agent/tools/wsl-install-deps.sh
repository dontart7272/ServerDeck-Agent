#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run only as root in the explicitly selected Ubuntu-22.04 WSL distribution.
set -euo pipefail
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
test "$(id -u)" = 0
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install --no-install-recommends -y \
    gcc-11=11.4.0-1ubuntu1~22.04.3 \
    gcc-11-aarch64-linux-gnu=11.4.0-1ubuntu1~22.04.3cross1 \
    libc6-dev=2.35-0ubuntu3.15 libc6-dev-arm64-cross=2.35-0ubuntu1cross3 \
    binutils=2.38-4ubuntu2.12 binutils-aarch64-linux-gnu=2.38-4ubuntu2.12 \
    qemu-user=1:6.2+dfsg-2ubuntu6.31 make ca-certificates curl python3 rsync
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' gcc-11 gcc-11-aarch64-linux-gnu libc6 libc6-dev libc6-dev-arm64-cross binutils binutils-aarch64-linux-gnu qemu-user
apt-cache policy gcc-11 gcc-11-aarch64-linux-gnu libc6 libc6-dev-arm64-cross
