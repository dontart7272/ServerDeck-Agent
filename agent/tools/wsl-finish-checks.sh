#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
task_root="$HOME/serverdeck-e01-2026-10-13"
source "$task_root/env.sh"
copy_root=$(cat "$task_root/copy-path.txt")
exec > >(tee "$task_root/evidence/linux-extra-checks.txt") 2>&1
trap 'status=$?; printf "\nEXIT=%s LINE=%s\n" "$status" "$LINENO"' EXIT
cd "$copy_root/agent"
for arch in amd64 arm64; do
    python3 /mnt/d/Projects/ServerDeck/agent/tools/inspect-linux.py "$arch" | tee "$task_root/evidence/elf-$arch.json"
done
dist/linux-amd64/serverdeckctl check-contract api QueryRequest '../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/query.json'
python3 - "$copy_root" "$task_root/evidence/build-inputs.json" <<'PY'
import hashlib,json,pathlib,sys
copy,out=map(pathlib.Path,sys.argv[1:]);original=pathlib.Path('/mnt/d/Projects/ServerDeck');records=[]
paths=[p for p in (copy/'agent').rglob('*') if p.is_file() and (p.suffix=='.go' or p.name in ('go.mod','go.sum') or '/contracts/schemas/' in str(p))]
paths+=list((copy/'Документация ServerDeck/Документация ServerDeck Agent/contracts').rglob('*.json'))
for p in sorted(paths):
 rel=p.relative_to(copy);a=hashlib.sha256(p.read_bytes()).hexdigest();b=hashlib.sha256((original/rel).read_bytes()).hexdigest()
 if a!=b:raise SystemExit('Original changed or copy drift: '+str(rel))
 records.append({'path':str(rel),'sha256':a})
out.write_text(json.dumps(records,ensure_ascii=False,indent=2)+'\n')
print('PASS: current original and compiled/tested Linux inputs match:',len(records),'files')
PY
rebuild=$(mktemp -d "$task_root/rebuild.XXXXXX")
mkdir -p "$rebuild/agent"
rsync -a --exclude=/dist/ "$copy_root/agent/" "$rebuild/agent/"
cd "$rebuild/agent"
export GOCACHE="$rebuild/cache"
mkdir -p "$GOCACHE"
echo "Reproducibility: new source path=$rebuild empty build cache=$GOCACHE"
for arch in amd64 arm64; do
    case "$arch" in amd64) compiler=/usr/bin/gcc-11;; arm64) compiler=/usr/bin/aarch64-linux-gnu-gcc-11;; esac
    for command in serverdeck-agent serverdeckctl; do
        echo "COMMAND: CGO_ENABLED=1 GOOS=linux GOARCH=$arch CC=$compiler go build -mod=readonly -trimpath -buildvcs=false -o dist/linux-$arch/$command ./cmd/$command"
        CGO_ENABLED=1 GOOS=linux GOARCH="$arch" CC="$compiler" go build -mod=readonly -trimpath -buildvcs=false -o "dist/linux-$arch/$command" "./cmd/$command"
        cmp "$copy_root/agent/dist/linux-$arch/$command" "dist/linux-$arch/$command"
        sha256sum "dist/linux-$arch/$command"
    done
done
echo 'PASS: all four cgo binaries byte-identical after rebuild from another Linux source path with fresh cache'
cd "$copy_root/agent"
find dist -maxdepth 2 -type f \( -name serverdeck-agent -o -name serverdeckctl \) -print0 | sort -z | xargs -0 sha256sum > "$task_root/evidence/binaries.sha256"
printf 'BUILD_PATH=%s\nREBUILD_PATH=%s\nTMPDIR=%s\nGOTMPDIR=%s\n' "$copy_root" "$rebuild" "$TMPDIR" "$GOTMPDIR"
