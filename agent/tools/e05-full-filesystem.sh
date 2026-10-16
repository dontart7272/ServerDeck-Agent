#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
test "$(id -u)" = 0
test "$(readlink /proc/self/ns/mnt)" != "$(readlink /proc/1/ns/mnt)"
mount --make-rprivate /
base=/home/dontart7272/serverdeck-e05-complete-2026-10-14
work=$(mktemp -d "$base/enospc.XXXXXX")
trap 'mountpoint -q "$work/mount" && umount "$work/mount" || true' EXIT
truncate -s 16000000 "$work/image.ext4"
mkfs.ext4 -q -F -m 0 "$work/image.ext4"
mkdir "$work/mount"
mount -o loop,nosuid,nodev,noexec "$work/image.ext4" "$work/mount"
chown 1000:1000 "$work/mount"
chmod 0700 "$work/mount"
chmod 0755 "$work"
cd "$(cat "$base/copy-path.txt")/agent/internal/storage"
runuser -u dontart7272 -- env SERVERDECK_TEST_FULL_FS="$work/mount" "$base/storage.test" -test.run '^TestTelemetryPhysicalFullFilesystem$' -test.v
