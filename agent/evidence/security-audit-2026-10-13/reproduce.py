"""Harmless offline reproductions; run from the project root with Python.

Builds the current CLI, uses synthetic manifests, never registers/runs modules.
"""
import copy
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
env = dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="1",
           GOPATH=str(ROOT / ".tools/gopath"), GOCACHE=str(ROOT / ".tools/gocache"))
go = ROOT / ".tools/go/bin/go.exe"
exe = ROOT / "agent/dist/windows-amd64/serverdeckctl-audit.exe"
subprocess.run([str(go), "build", "-mod=readonly", "-trimpath", "-buildvcs=false",
                "-o", str(exe), "./cmd/serverdeckctl"], cwd=ROOT / "agent", env=env, check=True)
fixture = ROOT / "Документация ServerDeck/Документация ServerDeck Agent/contracts/examples/module.json"
base = json.loads(fixture.read_text(encoding="utf-8"))
closed = {"type": "object", "properties": {}, "additionalProperties": False}
variants = [{"type": "object", "properties": {"kind": {"const": tag}},
             "required": ["kind"], "additionalProperties": False} for tag in ("a", "b")]
cases = {
    "control-forbidden-pattern": {"type": "object", "properties": {
        "x": {"type": "string", "maxLength": 80, "pattern": "a+"}}, "additionalProperties": False},
    "const-skips-properties": {"const": {}, "type": "object", "properties": {
        "x": {"type": "string", "pattern": "a+"}}, "additionalProperties": False},
    "oneof-skips-properties": {"oneOf": variants, "properties": {
        "kind": {"type": "string", "pattern": "a|b"}}},
    "const-skips-recursive-reference": {"const": {}, "type": "object", "properties": {
        "x": {"$ref": "#"}}, "additionalProperties": False},
    "enum-skips-properties": {"enum": [{}], "properties": {
        "x": {"type": "string", "pattern": "a+"}}},
}
lines = []
for name, schema in cases.items():
    manifest = copy.deepcopy(base)
    manifest["reads"] = [{"id": "audit.probe", "schema_version": "1.0.0", "timeout_ms": 1000,
                          "params_schema": schema, "result_schema": closed}]
    target = HERE / (name + ".json")
    target.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result = subprocess.run([str(exe), "check-contract", "module", "-", str(target)],
                            capture_output=True, text=True, timeout=15)
    lines.append(f"{name}: exit={result.returncode}; {(result.stdout + result.stderr).strip()}")
(HERE / "results-fixed.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
if any("exit=1; SCHEMA_MISMATCH" not in line for line in lines):
    raise SystemExit("FAIL: an unsafe schema was accepted or failed unexpectedly")
