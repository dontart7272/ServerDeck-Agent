#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
test "$(id -u)" != 0
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
base="$HOME/serverdeck-e02-2026-10-13"
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
 sync) gofmt -w internal/storage internal/operations; go test -count=1 ./internal/storage ./internal/operations ;;
 fault-binary) go test -c ./internal/operations -o "$base/operations.test" ;;
 check)
  exec > >(tee "$base/evidence/linux-checks.txt") 2>&1
  set -x
  date -u --iso-8601=seconds; uname -a; id; cat /etc/os-release
  go version; "$CC" --version; ldd --version
  python3 tools/verify-linux-toolchain.py "$origin/agent/evidence/E01-wsl-2026-10-13/linux-toolchain.lock.json"
  test -z "$(gofmt -l internal cmd)"
  go mod verify
  go vet ./...
  go test -v -count=1 ./...
  go test -race -count=1 ./...
  bash tools/build-linux.sh amd64
  bash tools/smoke-linux.sh
  bash tools/state-smoke-linux.sh
  CC=/usr/bin/aarch64-linux-gnu-gcc-11 bash tools/build-linux.sh arm64
  python3 tools/inspect-linux.py amd64
  python3 tools/inspect-linux.py arm64
  sha256sum dist/linux-{amd64,arm64}/{serverdeck-agent,serverdeckctl} > "$base/evidence/binaries.sha256"
  echo 'PASS E02 Linux WSL checks; native ARM and host matrix not tested'
 ;;
esac
