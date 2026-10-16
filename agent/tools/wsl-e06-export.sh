#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
base="$HOME/serverdeck-e06-final-2026-10-15"
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
expected={row['path'] for row in records}
actual=set()
for directory in (origin/'agent', origin/'Документация ServerDeck/Документация ServerDeck Agent/contracts'):
 for p in directory.rglob('*'):
  if not p.is_file():continue
  rel=p.relative_to(origin)
  if rel.parts[:2] in (('agent','dist'),('agent','evidence')):continue
  if p.suffix in ('.go','.sql','.json','.sum','.mod','.sh','.py','.txt'):actual.add(str(rel))
if actual!=expected:raise SystemExit('input file inventory changed; synchronize and rerun checks')
print('PASS: compiled/tested/tooling inputs still match main project:',len(records))
PY
mkdir -p "$origin/agent/evidence/E06-wsl-2026-10-15"
rsync -a "$base/evidence/" "$origin/agent/evidence/E06-wsl-2026-10-15/"
echo 'PASS: evidence exported; application sources and Windows dist not overwritten'
