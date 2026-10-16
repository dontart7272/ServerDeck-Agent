# SPDX-License-Identifier: Apache-2.0
"""Seal or verify E08 evidence and its current code/document inputs."""
import hashlib,json,pathlib,sys
folder=pathlib.Path(__file__).resolve().parent
root=folder.parents[2]
def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def check(manifest,base):
 for row in manifest["files"]:
  p=base/row["path"]
  if not p.is_file() or digest(p)!=row["sha256"]: raise SystemExit("MISMATCH: "+row["path"])
inputs=json.loads((folder/"build-inputs.json").read_text(encoding="utf8"))
check(inputs,root)
expected={row["path"] for row in inputs["files"]}
actual=set()
for directory in [root/"agent",root/"Документация ServerDeck/Документация ServerDeck Agent/contracts"]:
 for p in directory.rglob("*"):
  if not p.is_file():continue
  rel=p.relative_to(root)
  if rel.parts[:2] in [("agent","dist"),("agent","evidence")]:continue
  if p.suffix in [".go",".sql",".json",".sum",".mod",".sh",".py",".txt"]:actual.add(rel.as_posix())
if actual!=expected:raise SystemExit("MISMATCH: build input inventory")
if "--verify" in sys.argv:
 check(json.loads((folder/"docs-snapshot.json").read_text(encoding="utf8")),root)
 check(json.loads((folder/"artifacts.json").read_text(encoding="utf8")),folder)
 print("PASS: code, documents and evidence checksums",len(expected))
else:
 log=(folder/"linux-checks.txt").read_text(encoding="utf8")
 if "PASS E08 current Linux checks" not in log or "PASS final source identity" not in log:raise SystemExit("Linux checks incomplete")
 if not (folder/"docs-check.txt").read_text(encoding="utf-8-sig").startswith("PASS:"):raise SystemExit("Docs checks incomplete")
 rootlog=(folder/"separate-filesystem.txt").read_text(encoding="utf8")
 for name in ["TestE08NativeSeparateFilesystem","TestE08UnregisteredRestoredStateNeverExposesKey","TestE08NativeFullAndReadOnlyPreserveOriginal"]:
  if "--- PASS: "+name not in rootlog:raise SystemExit("Private namespace checks incomplete")
 docs={root/"AGENTS.md",*list((root/"agent").glob("*.md")),*list((root/"agent/licenses").glob("*.md")),*list((root/"Документация ServerDeck").rglob("*.md"))}
 rows=[{"path":p.relative_to(root).as_posix(),"sha256":digest(p)} for p in sorted(docs)]
 (folder/"docs-snapshot.json").write_text(json.dumps({"files":rows},ensure_ascii=False,indent=2)+"\n",encoding="utf8")
 rows=[{"path":p.relative_to(folder).as_posix(),"sha256":digest(p)} for p in sorted(folder.rglob("*")) if p.is_file() and p.name!="artifacts.json"]
 (folder/"artifacts.json").write_text(json.dumps({"files":rows},ensure_ascii=False,indent=2)+"\n",encoding="utf8")
 print("PASS: sealed",len(expected),"build inputs and",len(rows),"evidence files")
