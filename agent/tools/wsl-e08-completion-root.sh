#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
test "$(id -u)" = 0
base=${1:-/home/dontart7272/serverdeck-e08-completion-2026-10-15}
test -x "$base/app.test"
export SD_E08_OUTER_MNT=$(readlink /proc/self/ns/mnt)
# All mounts and propagation changes below are confined to the child namespace.
unshare --mount --pid --fork --mount-proc bash -s -- "$base" <<'INNER'
set -euo pipefail
base=$1
cd "$(cat "$base/copy-path.txt")/agent/internal/app"
test "$(readlink /proc/self/ns/mnt)" != "$SD_E08_OUTER_MNT"
mount --make-rprivate /
work=$(mktemp -d /tmp/serverdeck-e08.XXXXXX)
case "$work" in /tmp/serverdeck-e08.*) ;; *) exit 2;; esac
mkdir "$work/data" "$work/data2" "$work/tmp"
mount -t tmpfs -o size=16000000,mode=0700 tmpfs "$work/data"
mount -t tmpfs -o size=16000000,mode=0700 tmpfs "$work/data2"
trap 'umount "$work/data2" && umount "$work/data" && rm -rf -- "$work"' EXIT
SD_E08_ROOT="$work/data" SD_E08_ROOT2="$work/data2" TMPDIR="$work/tmp" "$base/app.test" -test.v -test.run '^TestE08(NativeSeparateFilesystem|UnregisteredRestoredStateNeverExposesKey)$' 2>&1 | tee "$base/evidence/separate-filesystem.txt"
INNER
