#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
base="$HOME/serverdeck-e07-final-2026-10-15"
{
 set -x
 date -u --iso-8601=seconds
 dpkg-query -W iputils-ping libcap2 libidn2-0 libunistring2 libc6 util-linux
 dpkg -V iputils-ping libcap2 libidn2-0 libunistring2
 sha256sum "$base/processcontrol.test" "$base/diagnostics.test"
 for package in iputils-ping libcap2 libidn2-0 libunistring2; do sha256sum "/usr/share/doc/$package/copyright"; done
} > "$base/evidence/runtime-dependencies.txt" 2>&1
