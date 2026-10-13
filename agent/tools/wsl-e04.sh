#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
test "$(id -u)" != 0
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
base="$HOME/serverdeck-e04-2026-10-13"
origin=/mnt/d/Projects/ServerDeck
mkdir -p "$base"/{tmp,cache,evidence}
test "$(findmnt -n -o FSTYPE -T "$base")" = ext4
source "$HOME/serverdeck-e01-2026-10-13/env.sh"
export GOCACHE="$base/cache" GOTMPDIR="$base/tmp" TMPDIR="$base/tmp" CC=/usr/bin/gcc-11
if test "${1:-}" = sync; then
 copy=$(mktemp -d "$base/source.XXXXXX")
 mkdir -p "$copy/agent" "$copy/Документация ServerDeck/Документация ServerDeck Agent"
 rsync -a --exclude=/dist/ --exclude=/evidence/ "$origin/agent/" "$copy/agent/"
 rsync -a "$origin/Документация ServerDeck/Документация ServerDeck Agent/contracts/" "$copy/Документация ServerDeck/Документация ServerDeck Agent/contracts/"
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
 printf '%s\n' "$copy" > "$base/copy-path.txt"
fi
copy=$(cat "$base/copy-path.txt")
cd "$copy/agent"
case "${1:-}" in
 sync) go mod download; go test -count=1 ./... ;;
 deps) go mod download -json github.com/coder/websocket@v1.8.15 ;;
 provenance)
  go mod download -json > "$base/evidence/modules.json"
  go mod graph > "$base/evidence/module-graph.txt"
  module=$(go env GOPATH)/pkg/mod/github.com/coder/websocket@v1.8.15
  if test -f "$origin/agent/licenses/websocket-ISC.txt";then cmp "$module/LICENSE.txt" "$origin/agent/licenses/websocket-ISC.txt";else cp "$module/LICENSE.txt" "$origin/agent/licenses/websocket-ISC.txt";fi
  sha256sum "$module/LICENSE.txt" "$(go env GOPATH)/pkg/mod/cache/download/github.com/coder/websocket/@v/v1.8.15.zip" > "$base/evidence/websocket-files.sha256"
 ;;
 fault-binary) go test -c ./internal/operations -o "$base/operations.test" ;;
 check)
  exec > >(tee "$base/evidence/linux-checks.txt") 2>&1
  set -x
  date -u --iso-8601=seconds; uname -a; id; cat /etc/os-release
  go version; "$CC" --version; ldd --version
  go env GOOS GOARCH CGO_ENABLED CC GOTOOLCHAIN GOPATH GOCACHE GOTMPDIR
  command -v go gcc-11 aarch64-linux-gnu-gcc-11 readelf python3 rsync
  command -v govulncheck || true
  python3 tools/verify-linux-toolchain.py "$origin/agent/evidence/E01-wsl-2026-10-13/linux-toolchain.lock.json"
  test -z "$(gofmt -l internal cmd)"
  go mod verify
  go vet ./...
  go test -v -count=1 ./...
  go test -race -count=1 ./...
  bash tools/build-linux.sh amd64
  for command in serverdeck-agent serverdeckctl;do
   "dist/linux-amd64/$command" version
   "dist/linux-amd64/$command" sqlite-info
   ldd "dist/linux-amd64/$command"
  done
  SERVERDECK_E03_AGENT_BINARY="$PWD/dist/linux-amd64/serverdeck-agent" SERVERDECK_E03_CTL_BINARY="$PWD/dist/linux-amd64/serverdeckctl" go test -v -count=1 -run '^TestNativeServeCLIShutdownAndPortConflict$' ./internal/app
  bash tools/state-smoke-linux.sh
  CC=/usr/bin/aarch64-linux-gnu-gcc-11 bash tools/build-linux.sh arm64
  python3 tools/inspect-linux.py amd64
  python3 tools/inspect-linux.py arm64
  sha256sum dist/linux-{amd64,arm64}/{serverdeck-agent,serverdeckctl} > "$base/evidence/binaries.sha256"
  go test -c ./internal/app -o "$base/app.test"
  go test -c ./internal/metrics -o "$base/metrics.test"
  for file in tools/*.sh;do bash -n "$file";done
  echo 'PASS E04 Linux WSL checks; native ARM and host matrix not tested'
 ;;
esac
