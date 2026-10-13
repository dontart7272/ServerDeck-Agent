#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
base="$HOME/serverdeck-e03-2026-10-13"
copy=$(cat "$base/copy-path.txt")
origin=/mnt/d/Projects/ServerDeck
python3 - "$origin" "$copy" "$base/evidence/build-inputs.json" <<'PY'
import hashlib,json,pathlib,sys
origin,copy,out=map(pathlib.Path,sys.argv[1:]);records=[]
for p in sorted(copy.rglob('*')):
 if not p.is_file() or 'dist' in p.parts:continue
 rel=p.relative_to(copy)
 if p.suffix not in ('.go','.sql','.json','.sum','.mod','.sh','.py','.txt'):continue
 a=hashlib.sha256(p.read_bytes()).hexdigest();b=hashlib.sha256((origin/rel).read_bytes()).hexdigest()
 if a!=b:raise SystemExit('original changed during checks: '+str(rel))
 records.append({'path':str(rel),'sha256':a})
out.write_text(json.dumps({'origin':str(origin),'copy':str(copy),'files':records},ensure_ascii=False,indent=2)+'\n')
print('PASS: compiled/tested/tooling inputs still match main project:',len(records))
PY
mkdir -p "$origin/agent/evidence/E03-wsl-2026-10-13"
rsync -a "$base/evidence/" "$origin/agent/evidence/E03-wsl-2026-10-13/"
for arch in amd64 arm64;do
 mkdir -p "$origin/agent/dist/linux-$arch"
 for command in serverdeck-agent serverdeckctl;do
  cp "$copy/agent/dist/linux-$arch/$command" "$origin/agent/dist/linux-$arch/$command"
  cmp "$copy/agent/dist/linux-$arch/$command" "$origin/agent/dist/linux-$arch/$command"
 done
done
echo 'PASS: evidence and binaries exported; application sources not copied back'
