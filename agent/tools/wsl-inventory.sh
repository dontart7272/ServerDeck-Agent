#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cat /etc/os-release
uname -a
id
findmnt -T "$HOME"
df -h "$HOME"
for tool in go gcc gcc-11 aarch64-linux-gnu-gcc aarch64-linux-gnu-gcc-11 readelf curl python3 rsync qemu-aarch64; do
    command -v "$tool" || true
done
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' libc6 binutils ca-certificates curl 2>/dev/null
grep -hE '^[[:space:]]*deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null || true
