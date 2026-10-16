#!/bin/bash
set -euo pipefail
base=/home/dontart7272/serverdeck-e08-final-2026-10-16
cd "$(cat "$base/copy-path.txt")/agent/internal/app"
"$base/app-race.test" -test.v -test.run '^TestForeignUIDAdminPeerIsRejected$' 2>&1 | tee "$base/evidence/foreign-peer.txt"
