#!/bin/bash
set -euo pipefail
base="$HOME/serverdeck-e08-completion-2026-10-15"
copy=$(cat "$base/copy-path.txt")
export TMPDIR="$base/tmp"
cd "$copy/agent"
work=$(mktemp -d "$TMPDIR/inventory-confirm.XXXXXX")
python3 - "$work" <<'PY'
import json,pathlib,pwd,os,sys
base=pathlib.Path(sys.argv[1]);c=json.loads(pathlib.Path('../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json').read_text());c['runtime_user']=pwd.getpwuid(os.getuid()).pw_name;c['paths']['state']=str(base/'state')
for name,value in [('config.json',c),('confirm.json',{'known_regions':[],'absent_operation_ids':[]})]:
 p=base/name;p.write_text(json.dumps(value));p.chmod(0o600)
PY
ctl=dist/linux-amd64/serverdeckctl
exec > >(tee "$base/evidence/inventory-confirm-cli.txt") 2>&1
set -x
"$ctl" state-init "$work/state" "$work/config.json"
"$ctl" state-inventory-confirm "$work/state" "$work/confirm.json" aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa --confirm
"$ctl" state-inventory-confirm "$work/state" "$work/confirm.json" aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa --confirm
"$ctl" state-inventory "$work/state" > "$work/inventory.json"
python3 - "$work/inventory.json" <<'PY'
import json,pathlib,sys
v=json.loads(pathlib.Path(sys.argv[1]).read_text());assert v['attestation']['generation']==v['generation'];assert v['attestation']['regions']==[]
print('PASS: compiled CLI confirmation persisted current attestation and replay did not repeat it')
PY
"$ctl" state-backup "$work/state" "$work/backup" bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb --confirm
"$ctl" state-inventory "$work/state" > "$work/inventory.json"
python3 - "$work/inventory.json" <<'PY'
import json,pathlib,sys
v=json.loads(pathlib.Path(sys.argv[1]).read_text());assert v['attestation']['generation']!=v['generation'];assert len(v['artifacts'])==1
print('PASS: a new owned backup invalidates the previous attestation')
PY
