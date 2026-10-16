#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
test "$(id -u)" != 0
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
origin=/mnt/d/Projects/ServerDeck
base="$HOME/serverdeck-e08-final-2026-10-15"
mkdir -p "$base"/{tmp,cache,evidence}
test "$(findmnt -n -o FSTYPE -T "$base")" = ext4
source "$HOME/serverdeck-e01-2026-10-13/env.sh"
export GOCACHE="$base/cache" GOTMPDIR="$base/tmp" TMPDIR="$base/tmp" CC=/usr/bin/gcc-11
copy=$(mktemp -d "$base/source.XXXXXX")
mkdir -p "$copy/agent" "$copy/Документация ServerDeck/Документация ServerDeck Agent"
rsync -a --exclude=/dist/ --exclude=/evidence/ --exclude=/.cache/ "$origin/agent/" "$copy/agent/"
rsync -a "$origin/Документация ServerDeck/Документация ServerDeck Agent/contracts/" "$copy/Документация ServerDeck/Документация ServerDeck Agent/contracts/"
printf '%s\n' "$copy" > "$base/copy-path.txt"
python3 - "$origin" "$copy" "$base/evidence/source-copy.json" <<'PY'
import hashlib,json,pathlib,sys
origin,copy,out=map(pathlib.Path,sys.argv[1:]); records=[]
for p in sorted(copy.rglob('*')):
 if not p.is_file(): continue
 rel=p.relative_to(copy); digest=hashlib.sha256(p.read_bytes()).hexdigest()
 if hashlib.sha256((origin/rel).read_bytes()).hexdigest()!=digest: raise SystemExit('copy mismatch')
 records.append({'path':str(rel),'sha256':digest})
out.write_text(json.dumps({'origin':str(origin),'copy':str(copy),'files':records},ensure_ascii=False,indent=2)+'\n')
print('Byte-identical inputs:',len(records))
PY
cd "$copy/agent"
exec > >(tee "$base/evidence/linux-checks.txt") 2>&1
set -x
date -u --iso-8601=seconds; uname -a; id; cat /etc/os-release
go version; "$CC" --version; ldd --version
go env GOOS GOARCH CGO_ENABLED CC GOTOOLCHAIN GOPATH GOCACHE GOTMPDIR
python3 tools/verify-linux-toolchain.py "$origin/agent/evidence/E01-wsl-2026-10-13/linux-toolchain.lock.json"
test -z "$(gofmt -l internal cmd)"
go mod verify
go vet ./...
go test -v -count=1 ./...
go test -race -count=1 ./...
go test ./internal/history -run '^$' -fuzz '^FuzzWeightedRollup$' -fuzztime=10s -parallel=2
go test ./internal/fileaccess -run '^$' -fuzz '^FuzzE08Location$' -fuzztime=10s -parallel=2
bash tools/build-linux.sh amd64
for command in serverdeck-agent serverdeckctl; do
 "dist/linux-amd64/$command" version
 "dist/linux-amd64/$command" sqlite-info
 ldd "dist/linux-amd64/$command"
done
SERVERDECK_E03_AGENT_BINARY="$PWD/dist/linux-amd64/serverdeck-agent" SERVERDECK_E03_CTL_BINARY="$PWD/dist/linux-amd64/serverdeckctl" go test -v -count=1 -run '^TestNativeServeCLIShutdownAndPortConflict$' ./internal/app
bash tools/state-smoke-linux.sh
CC=/usr/bin/aarch64-linux-gnu-gcc-11 bash tools/build-linux.sh arm64
sha256sum dist/linux-{amd64,arm64}/{serverdeck-agent,serverdeckctl} > "$base/evidence/binaries.sha256"
python3 - "$origin" "$base/evidence/source-copy.json" <<'PY'
import hashlib,json,pathlib,sys
origin=pathlib.Path(sys.argv[1]); manifest=json.loads(pathlib.Path(sys.argv[2]).read_text())
for row in manifest['files']:
 if pathlib.Path(row['path']).suffix != '.md' and hashlib.sha256((origin/row['path']).read_bytes()).hexdigest()!=row['sha256']: raise SystemExit('origin changed during checks: '+row['path'])
print('PASS final source identity',len(manifest['files']))
PY
go test -c -o "$base/app.test" ./internal/app
go test -c -o "$base/processcontrol.test" ./internal/processcontrol
go test -c -o "$base/diagnostics.test" ./internal/diagnostics
export SD_E07_ISOLATED_PIDNS=1 SD_E07_OUTER_PIDNS=$(readlink /proc/self/ns/pid)
unshare --user --map-root-user --pid --fork --mount-proc "$base/processcontrol.test" -test.v -test.run '^TestIsolatedFastPIDReuse$'
{ ping -V; dpkg-query -W iputils-ping; apt-cache policy iputils-ping; getcap /usr/bin/ping; sha256sum /usr/bin/ping; ldd /usr/bin/ping; } > "$base/evidence/ping-provenance.txt"
cp /usr/share/doc/iputils-ping/copyright "$base/evidence/iputils-copyright.txt"
cp dist/linux-amd64/elf-summary.json "$base/evidence/elf-amd64.json"
cp dist/linux-arm64/elf-summary.json "$base/evidence/elf-arm64.json"
cp dist/linux-amd64/build-evidence.txt "$base/evidence/build-amd64.txt"
cp dist/linux-arm64/build-evidence.txt "$base/evidence/build-arm64.txt"
echo 'PASS E08 read-only Linux checks; E08 remains open: BLOCK-FS and protected ancestry gate'
