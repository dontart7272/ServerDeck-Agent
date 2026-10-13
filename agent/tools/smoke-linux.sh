#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(uname -s)" = Linux
export GOTOOLCHAIN=local CGO_ENABLED=1
test "$(go env GOVERSION)" = go1.27.2
case "$(uname -m)" in x86_64) arch=amd64;; aarch64) arch=arm64;; *) exit 2;; esac
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
for command in serverdeck-agent serverdeckctl; do
    "dist/linux-$arch/$command" version
    info="$("dist/linux-$arch/$command" sqlite-info)"
    case "$info" in 'sqlite_version=3.53.4 sqlite_source_id='*) ;; *) echo 'SQLite mismatch' >&2; exit 1;; esac
    printf '%s\n' "$info"
    ldd "dist/linux-$arch/$command"
done
dist/linux-"$arch"/serverdeckctl validate-config '../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json'
set +e
dist/linux-"$arch"/serverdeck-agent
status=$?
set -e
test "$status" = 2
echo 'PASS: offline E01 Linux smoke; no systemd install, privileged operation or network service tested.'
