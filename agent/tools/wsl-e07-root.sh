#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
test "$(id -u)" = 0
base=/home/dontart7272/serverdeck-e07-final-2026-10-15
test -x "$base/processcontrol.test"
work=$(mktemp -d /tmp/serverdeck-e07.XXXXXX)
test "$(findmnt -n -o FSTYPE -T "$work")" = ext4
chmod 0755 "$work"
trap 'rm -f -- "$work/processcontrol.test"; rmdir -- "$work"' EXIT
cp "$base/processcontrol.test" "$work/processcontrol.test"
chmod 0755 "$work/processcontrol.test"
export SD_E07_OUTER_PIDNS=$(readlink /proc/self/ns/pid)
# Temporary binary permits traversal by the test-only foreign UID; no home chmod.
{
 id; uname -a
 sha256sum "$base/processcontrol.test" "$work/processcontrol.test"
 unshare --pid --fork --mount-proc "$work/processcontrol.test" -test.v -test.run '^(TestPidfdSignalsIdentityProtectionAndNoFallback|TestPinnedDeadProcessCannotSignalNewChild|TestTERMDoesNotEscalateKILLIsSeparate|TestPID1AgentStillProtectsItsChildren)$'
 SD_E07_ISOLATED_ROOT=1 unshare --pid --fork --mount-proc "$work/processcontrol.test" -test.v -test.run '^TestIsolatedForeignUID$'
 # Drop a capability only in a child namespace. Never grant or modify file caps.
 SD_E07_PING_DENIED=1 unshare --net --pid --fork --mount-proc setpriv --bounding-set=-net_raw "$base/diagnostics.test" -test.v -test.run '^TestIsolatedPingPermissionDenied$'
} 2>&1 | tee "$base/evidence/foreign-uid.txt"
