#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
cd "$(dirname "$0")/.."
test "$(uname -s)" = Linux
work=$(mktemp -d "${TMPDIR:?}/cli-e02.XXXXXX")
# The script never removes/moves host state. All paths refer to this private
# test directory; evidence records only safe command outputs.
python3 - "$work" <<'PY'
import json,pathlib,pwd,os,sys
base=pathlib.Path(sys.argv[1]); source=pathlib.Path('../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json')
c=json.loads(source.read_text());c['runtime_user']=pwd.getpwuid(os.getuid()).pw_name;c['paths']['state']=str(base/'state')
p=base/'config.json';p.write_text(json.dumps(c));p.chmod(0o600)
PY
ctl=dist/linux-amd64/serverdeckctl
"$ctl" state-init "$work/state" "$work/config.json"
"$ctl" state-status "$work/state"
"$ctl" state-backup "$work/state" "$work/backup" 22222222-2222-4222-8222-222222222222 --confirm
"$ctl" state-backup "$work/state" "$work/backup" 22222222-2222-4222-8222-222222222222 --confirm
"$ctl" state-operation "$work/state" 22222222-2222-4222-8222-222222222222
"$ctl" state-restore "$work/state" "$work/backup" "$work/restored" 44444444-4444-4444-8444-444444444444 --confirm
"$ctl" state-status "$work/restored"
"$ctl" state-inventory "$work/restored" > "$work/inventory.json"
python3 - "$work/inventory.json" <<'PY'
import json,pathlib,sys
i=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert i["baseline"]=="unknown" and i["generation"]==3 and len(i["artifacts"])==2
assert {a["kind"] for a in i["artifacts"]}=={"backup","restore"}
print("PASS: E08 CLI inventory preserves both unknown receipts after restore")
PY
# Current operation state overlays the old snapshot. The in-flight restore
# itself is now unknown in the target; observe its completed marker explicitly.
test -f "$work/restored/restore-complete.json"
"$ctl" state-resolve "$work/restored" 44444444-4444-4444-8444-444444444444 applied --confirm
echo 'PASS: E02 offline CLI init/status/backup/replay/restore/admin-resolution in private Linux temp storage'
