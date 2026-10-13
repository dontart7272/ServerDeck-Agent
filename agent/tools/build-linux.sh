#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
arch="${1:?usage: bash tools/build-linux.sh amd64|arm64}"
case "$arch" in amd64|arm64) ;; *) echo 'unsupported architecture' >&2; exit 2;; esac
: "${CC:?set CC to the target Linux GCC 11.4.0 with glibc 2.35 sysroot}"
export GOTOOLCHAIN=local CGO_ENABLED=1 GOOS=linux GOARCH="$arch"
test "$(go env GOVERSION)" = go1.27.2
test "$("$CC" -dumpfullversion)" = 11.4.0
triple="$("$CC" -dumpmachine)"
case "$arch:$triple" in amd64:x86_64*linux*|arm64:aarch64*linux*) ;; *) echo 'CC target mismatch' >&2; exit 1;; esac
# No system SQLite or NVML library is linked in E01. The bundled amalgamation
# is used; no libsqlite3 tag, no static portability claim.
mkdir -p "dist/linux-$arch"
go mod verify
for command in serverdeck-agent serverdeckctl; do
    go build -mod=readonly -trimpath -buildvcs=false -o "dist/linux-$arch/$command" "./cmd/$command"
done
{
    go version
    "$CC" --version
    go list -m all
    for command in serverdeck-agent serverdeckctl; do
        sha256sum "dist/linux-$arch/$command"
        go version -m "dist/linux-$arch/$command"
        readelf -h -l -d -V "dist/linux-$arch/$command"
    done
} > "dist/linux-$arch/build-evidence.txt"
python3 tools/inspect-linux.py "$arch" > "dist/linux-$arch/elf-summary.json"
echo "Built linux/$arch with cgo; ELF/GLIBC<=2.35 checked. Run smoke on the matching Linux host."
