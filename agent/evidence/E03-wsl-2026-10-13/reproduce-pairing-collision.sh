#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Regression only: modify a new private Linux copy, never the main project.
set -euo pipefail
base="$HOME/serverdeck-e03-2026-10-13"
copy=$(cat "$base/copy-path.txt")
source "$HOME/serverdeck-e01-2026-10-13/env.sh"
export CC=/usr/bin/gcc-11 GOCACHE="$base/cache" GOTMPDIR="$base/tmp" TMPDIR="$base/tmp"
repro=$(mktemp -d "$base/collision.XXXXXX")
test "$(findmnt -n -o FSTYPE -T "$repro")" = ext4
rsync -a --exclude=dist/ "$copy/" "$repro/"
python3 - "$repro/agent/internal/app/gateway.go" <<'PY'
import pathlib,sys
p=pathlib.Path(sys.argv[1]);s=p.read_text()
assert '\t_, requestReserved := g.pairs[string(r.RequestId)]\n' in s
assert ' || requestReserved || ' in s
s=s.replace('\t_, requestReserved := g.pairs[string(r.RequestId)]\n','',1)
s=s.replace(' || requestReserved || ',' || ',1)
p.write_text(s)
PY
exec > >(tee "$base/evidence/pairing-collision.txt") 2>&1
echo 'BEFORE: original pending-map behavior in a new private copy; expected test failure'
cd "$repro/agent"
set +e
go test -count=1 -run '^TestDifferentPairingCodesCannotOverwriteSamePendingRequest$' ./internal/app > "$base/evidence/pairing-before.txt" 2>&1
status=$?
set -e
cat "$base/evidence/pairing-before.txt"
test "$status" = 1
grep -q 'reserved request overwritten' "$base/evidence/pairing-before.txt"
echo 'AFTER: authoritative fixed Linux copy; expected PASS'
cd "$copy/agent"
go test -count=3 -run '^TestDifferentPairingCodesCannotOverwriteSamePendingRequest$' ./internal/app
cmp internal/app/gateway.go /mnt/d/Projects/ServerDeck/agent/internal/app/gateway.go
echo 'PASS: reproduced before failure, fixed regression passed three times, authoritative source unchanged'
