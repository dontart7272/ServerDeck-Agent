#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
test "$(id -u)" = 0
base=/home/dontart7272/serverdeck-e03-2026-10-13
copy=$(cat "$base/copy-path.txt")
work=$(mktemp -d /tmp/serverdeck-e03-root.XXXXXX)
trap 'rm -rf -- "$work"' EXIT
export TMPDIR="$work"
cd "$copy/agent/internal/app"
exec > >(tee "$base/evidence/root-checks.txt") 2>&1
set -x
id; uname -a
"$base/app.test" -test.v -test.count=1 -test.run='^(TestNativeServeCLIShutdownAndPortConflict|TestUnixPeerCLIAndPathProtection|TestForeignUIDAdminPeerIsRejected)$'
echo 'PASS: root-owned temporary state, local admin and actual UID65534 rejection; no host configuration changed'
