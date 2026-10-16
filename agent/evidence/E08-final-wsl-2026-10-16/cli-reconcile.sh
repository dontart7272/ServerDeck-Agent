#!/bin/bash
set -euo pipefail
base="$HOME/serverdeck-e08-final-2026-10-16"
copy=$(cat "$base/copy-path.txt")
export TMPDIR="$base/tmp"
cd "$copy/agent"
python3 - "$base" <<'PY' 2>&1 | tee "$base/evidence/cli-reconcile.txt"
import pathlib,tempfile,json,pwd,os,sqlite3,subprocess,sys,time,uuid
base=pathlib.Path(sys.argv[1]);work=pathlib.Path(tempfile.mkdtemp(prefix='reconcile-cli.',dir=base/'tmp'));ctl=str(pathlib.Path.cwd()/'dist/linux-amd64/serverdeckctl')
cfg=json.loads(pathlib.Path('../Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/config.json').read_text());cfg['runtime_user']=pwd.getpwuid(os.getuid()).pw_name
for k in cfg['paths']:
 cfg['paths'][k]=str(work/k)
 if k!='state':(work/k).mkdir(mode=0o700)
for k in cfg['tls']:
 cfg['tls'][k]=str(work/k);(work/k).write_text('offline pin-only fixture; no service started');(work/k).chmod(0o600)
cfg['runtime_initial']['files']['roots'][0]['path']=str(work/'data');(work/'data').mkdir(mode=0o700)
def private(name,value):
 p=work/name;p.write_text(json.dumps(value));p.chmod(0o600);return str(p)
config=private('config.json',cfg);state=cfg['paths']['state']
def run(*args,good=True):
 r=subprocess.run([ctl,*args],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 assert (r.returncode==0)==good, (args[0],r.returncode,r.stderr.decode())
 return json.loads(r.stdout) if r.stdout.startswith(b'{') else None
run('state-init',state,config)
confirm=private('confirm.json',{'known_regions':[],'absent_operation_ids':[]})
run('state-inventory-confirm',state,confirm,str(uuid.uuid4()),'--confirm')
record=str(uuid.uuid4());original=str(uuid.uuid4());now=time.time_ns()//1000
db=sqlite3.connect(str(pathlib.Path(state)/'critical.db'));db.execute('INSERT INTO file_journal VALUES(?,?,?,?,?,?,?,?,?)',(record,'transfer','local:'+str(os.getuid()),original,'unknown',0,now,now+3600000000,json.dumps({'RootPath':str(work/'data')}).encode()));db.commit();db.close()
rows=run('state-files',state)['items'];row=next(r for r in rows if r['record']['ID']==record)
input=private('reconcile.json',{'record_id':record,'expected_version':row['version'],'state':'purged'})
operation=str(uuid.uuid4());out=run('state-file-reconcile',state,config,input,operation,'--confirm');assert out['state']=='succeeded' and out['audit_status']=='durable'
assert run('state-file-reconcile',state,config,input,operation,'--confirm')==out
rows=run('state-files',state)['items'];assert next(r for r in rows if r['record']['ID']==record)['record']['State']=='purged'
# No original operation is invented or automatically resolved by reconciliation.
run('state-operation',state,original,good=False)
print('PASS: compiled CLI state-files -> CONFIG-bound audited reconciliation -> replay; missing original operation is not invented')
PY
