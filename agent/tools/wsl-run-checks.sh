#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
task_root="$HOME/serverdeck-e01-2026-10-13"
source "$task_root/env.sh"
copy_root=$(cat "$task_root/copy-path.txt")
cd "$copy_root/agent"
export CC=/usr/bin/gcc-11
run() { printf '\nCOMMAND:'; printf ' %q' "$@"; printf '\n'; "$@"; }
exec > >(tee "$task_root/evidence/linux-checks.txt") 2>&1
trap 'status=$?; printf "\nEXIT=%s LINE=%s\n" "$status" "$LINENO"' EXIT
run date -u +%Y-%m-%dT%H:%M:%SZ
run uname -a
run id
run go version
run go env CGO_ENABLED CC GOOS GOARCH GOTOOLCHAIN GOPATH GOCACHE GOTMPDIR TMPDIR
run gcc-11 -dumpfullversion
run aarch64-linux-gnu-gcc-11 -dumpfullversion
run getconf GNU_LIBC_VERSION
unformatted=$(gofmt -l cmd internal)
test -z "$unformatted"
echo 'PASS: gofmt clean'
run go mod verify
run bash tools/build-linux.sh amd64
run bash tools/smoke-linux.sh
run env CC=/usr/bin/aarch64-linux-gnu-gcc-11 bash tools/build-linux.sh arm64
for arch in amd64 arm64; do
    cp "dist/linux-$arch/build-evidence.txt" "$task_root/evidence/build-$arch.txt"
done
echo 'ARM64 USER-MODE EMULATION ONLY; not native ARM testing'
for command in serverdeck-agent serverdeckctl; do
    run timeout 60s qemu-aarch64 -L /usr/aarch64-linux-gnu "dist/linux-arm64/$command" version
    run timeout 60s qemu-aarch64 -L /usr/aarch64-linux-gnu "dist/linux-arm64/$command" sqlite-info
done
run timeout 60s qemu-aarch64 -L /usr/aarch64-linux-gnu dist/linux-arm64/serverdeckctl validate-config '../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json'
echo 'PASS: WSL amd64 build/smoke/vet/tests/race and arm64 cgo cross-build/emulated commands. Native ARM NOT RUN.'
