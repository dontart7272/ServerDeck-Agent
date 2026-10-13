#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Run as the existing ordinary Ubuntu user; all build data stays on Linux ext4.
set -euo pipefail
. /etc/os-release
test "$ID:$VERSION_ID" = ubuntu:22.04
test "$(id -u)" != 0
source_root=/mnt/d/Projects/ServerDeck
task_root="$HOME/serverdeck-e01-2026-10-13"
mkdir -p "$task_root"/{toolchains,cache/gopath,cache/gobuild,tmp,evidence}
case "$(findmnt -n -o FSTYPE -T "$task_root")" in ext4) ;; *) echo 'Linux ext4 required' >&2; exit 1;; esac
archive="$task_root/toolchains/go1.27.2.linux-amd64.tar.gz"
if test ! -f "$archive"; then
    curl --fail --location --retry 2 --connect-timeout 15 --max-time 300 https://go.dev/dl/go1.27.2.linux-amd64.tar.gz -o "$archive"
fi
printf '%s  %s\n' ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5 "$archive" | sha256sum -c -
if test ! -e "$task_root/toolchains/go"; then
    tar -xzf "$archive" -C "$task_root/toolchains"
fi
"$task_root/toolchains/go/bin/go" version
test "$(GOTOOLCHAIN=local "$task_root/toolchains/go/bin/go" env GOVERSION)" = go1.27.2
copy_root=$(mktemp -d "$task_root/source.XXXXXX")
mkdir -p "$copy_root/agent" "$copy_root/Документация ServerDeck/Документация ServerDeck Agent"
rsync -a --exclude=/dist/ --exclude=/evidence/ --exclude=/.cache/ "$source_root/agent/" "$copy_root/agent/"
rsync -a "$source_root/Документация ServerDeck/Документация ServerDeck Agent/contracts/" "$copy_root/Документация ServerDeck/Документация ServerDeck Agent/contracts/"
printf '%s\n' "$copy_root" > "$task_root/copy-path.txt"
python3 - "$source_root" "$copy_root" "$task_root/evidence/source-copy.json" <<'PY'
import hashlib,json,pathlib,sys
origin,copy,out=map(pathlib.Path,sys.argv[1:])
records=[]
for base in (copy/'agent',copy/'Документация ServerDeck/Документация ServerDeck Agent/contracts'):
 for p in sorted(base.rglob('*')):
  if not p.is_file(): continue
  rel=p.relative_to(copy); a=hashlib.sha256((origin/rel).read_bytes()).hexdigest(); b=hashlib.sha256(p.read_bytes()).hexdigest()
  if a!=b: raise SystemExit('copy mismatch: '+str(rel))
  records.append({'path':str(rel),'sha256':a})
out.write_text(json.dumps({'source':str(origin),'copy':str(copy),'files':records},ensure_ascii=False,indent=2)+'\n')
print('Byte-identical Linux copy:',copy,'files=',len(records))
PY
printf 'export PATH=%q:$PATH\nexport GOTOOLCHAIN=local CGO_ENABLED=1\nexport GOPATH=%q GOCACHE=%q GOTMPDIR=%q TMPDIR=%q\n' "$task_root/toolchains/go/bin" "$task_root/cache/gopath" "$task_root/cache/gobuild" "$task_root/tmp" "$task_root/tmp" > "$task_root/env.sh"
source "$task_root/env.sh"
cd "$copy_root/agent"
go mod download
go mod verify
go list -m -json all > "$task_root/evidence/go-modules.json"
sha256sum go.mod go.sum > "$task_root/evidence/go-module-files.sha256"
find "$GOPATH/pkg/mod/cache/download" -name '*.zip' -print0 | sort -z | xargs -0 sha256sum > "$task_root/evidence/go-module-archives.sha256"
echo "Prepared $copy_root"
