#!/bin/bash
set -euo pipefail
base="$HOME/serverdeck-e08-final-2026-10-16"
source "$HOME/serverdeck-e01-2026-10-13/env.sh"
export GOCACHE="$base/cache" GOTMPDIR="$base/tmp" TMPDIR="$base/tmp" CC=/usr/bin/gcc-11
cd "$(cat "$base/copy-path.txt")/agent"
exec > >(tee "$base/evidence/extra-linux.txt") 2>&1
set -x
go test -race -c -o "$base/app-race.test" ./internal/app
go test -race -c -o "$base/fileaccess-race.test" ./internal/fileaccess
python3 - "$base" <<'PY'
import json,pathlib,sys,subprocess,copy
base=pathlib.Path(sys.argv[1]);work=base/'tmp'/'contract-checks';work.mkdir(exist_ok=True)
ctl=str(pathlib.Path.cwd()/'dist/linux-amd64/serverdeckctl')
examples=pathlib.Path('../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples')
internal={'storage.inventory.confirm':{'inventory_attested':True},'files.reconcile':{'reconciled':True},'system.files.cleanup':{'cleaned':True},'system.files.rotate':{'rotated':True},'system.trash.expire':{'trash_id':'11111111-1111-4111-8111-111111111111','purged':True}}
for action,result in internal.items():
 op=json.loads((examples/'operation-state.json').read_text());op['action']=action;op['result']=result
 f=work/'input.json';f.write_text(json.dumps(op));subprocess.run([ctl,'check-contract','api','Operation',str(f)],check=True)
 for definition in ['PrepareRequest','OperationRequest']:
  req={'schema_version':'1.0','request_id':op['operation_id'],'operation_id':op['operation_id'],'action':action,'params':{}}
  if definition=='OperationRequest':req.update(plan_id=op['operation_id'],confirmed=True)
  f.write_text(json.dumps(req));r=subprocess.run([ctl,'check-contract','api',definition,str(f)],stdout=subprocess.PIPE,stderr=subprocess.PIPE);assert r.returncode!=0,action
print('PASS: internal read-view contracts accepted; internal actions rejected by both public request codecs')
receipt=json.loads((examples/'transfer-receipt.json').read_text());f.write_text(json.dumps(receipt));subprocess.run([ctl,'check-contract','api','TransferReceipt',str(f)],check=True)
for key,value in [('received_bytes',-1),('received_bytes',1.5),('ready',False),('sha256','wrong'),('schema_version','2.0')]:
 bad=copy.deepcopy(receipt);bad[key]=value;f.write_text(json.dumps(bad));assert subprocess.run([ctl,'check-contract','api','TransferReceipt',str(f)],stdout=subprocess.PIPE,stderr=subprocess.PIPE).returncode!=0
print('PASS: receipt version/byte/hash/readiness negative bounds')
PY
