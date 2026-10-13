"""Offline API-contract audit probes; no HTTP requests or server changes."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
DOCS = ROOT / "Документация ServerDeck/Документация ServerDeck Agent"
env = dict(os.environ, GOTOOLCHAIN="local", CGO_ENABLED="1",
           GOPATH=str(ROOT / ".tools/gopath"), GOCACHE=str(ROOT / ".tools/gocache"))
exe = ROOT / "agent/dist/windows-amd64/serverdeckctl-api-audit.exe"
subprocess.run([str(ROOT / ".tools/go/bin/go.exe"), "build", "-mod=readonly", "-trimpath",
                "-buildvcs=false", "-o", str(exe), "./cmd/serverdeckctl"],
               cwd=ROOT / "agent", env=env, check=True)
uid = "11111111-1111-4111-8111-111111111111"
api = json.loads((DOCS / "contracts/api.schema.json").read_text(encoding="utf-8"))["definitions"]
ipc = json.loads((DOCS / "contracts/ipc.schema.json").read_text(encoding="utf-8"))["definitions"]
def message_types(schema):
    if "$ref" in schema:
        return message_types(api[schema["$ref"].split("/")[-1]])
    if "oneOf" in schema:
        return [kind for branch in schema["oneOf"] for kind in message_types(branch)]
    return [schema["properties"]["type"]["const"]]

inventory = {
    "routes": re.findall(r"^\| (POST|GET|PUT) `([^`]+)`", (DOCS / "3. API и форматы данных.md.md").read_text(encoding="utf-8"), re.M),
    "queries": [b["properties"]["query"]["const"] for b in api["QueryRequest"]["oneOf"]],
    "actions": [b["properties"]["action"]["const"] for b in api["OperationRequest"]["oneOf"]],
    "ipc_methods": [b["properties"]["method"]["const"] for b in ipc["Request"]["oneOf"]],
    "wss_types": list(dict.fromkeys(message_types(api["WssMessage"]))),
}
(HERE / "inventory-fixed.json").write_text(json.dumps(inventory, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
subscribe = {"schema_version": "1.0", "request_id": uid, "type": "subscribe",
             "subscriptions": [{"id": "s", "topic": "snapshot", "params": True}]}
duplicate = copy.deepcopy(subscribe)
duplicate["subscriptions"] = [{"id": "s", "topic": "snapshot", "params": {"view": "summary"}}] * 2
prepare = {"schema_version": "1.0", "request_id": uid, "operation_id": uid,
           "action": "config.set", "expected_version": "audit-version",
           "params": {"changes": {"icmp": {"target": "-c", "background_enabled": True}}}}
execute = dict(prepare, plan_id="a" * 22)
config = json.loads((DOCS / "contracts/examples/config.json").read_text(encoding="utf-8"))
config["runtime_initial"]["icmp"] = prepare["params"]["changes"]["icmp"]
unknown = copy.deepcopy(prepare)
unknown["params"]["changes"]["runtime_user"] = "audit-synthetic"
storage = {"kind": "audit", "status": "ok", "used_bytes": "0", "budget_bytes": "1",
           "wal_bytes": "0", "reserve_bytes": "0", "reason": None}
cases = [
    ("wss-nonobject-params", "WssClientMessage", subscribe, 1),
    ("wss-duplicate-subscription-id", "WssClientMessage", duplicate, 1),
    ("wss-server-message", "WssClientMessage", {"schema_version": "1.0", "type": "heartbeat", "server_time": "2026-10-13T00:00:00Z"}, 1),
    ("wss-topic-data-mismatch", "WssServerMessage", {"schema_version": "1.0", "type": "changes", "subscription_id": "s", "server_time": "2026-10-13T00:00:00Z", "topic": "events", "data": [storage], "cursor": "synthetic"}, 1),
    ("prepare-icmp-flag", "PrepareRequest", prepare, 1),
    ("execute-icmp-flag", "OperationRequest", execute, 1),
    ("control-valid-client", "WssClientMessage", {"schema_version":"1.0", "request_id":uid, "type":"subscribe", "subscriptions":[{"id":"s","topic":"snapshot","params":{"view":"summary"}}]}, 0),
    ("control-valid-server", "WssServerMessage", {"schema_version":"1.0", "type":"heartbeat", "server_time":"2026-10-13T00:00:00Z"}, 0),
    ("control-bootstrap-icmp-flag", None, config, 1),
    ("control-unknown-bootstrap-field", "PrepareRequest", unknown, 1),
]
lines = []
for name, definition, payload, expected in cases:
    file = HERE / (name + ".json")
    file.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    args = ["validate-config", str(file)] if definition is None else ["check-contract", "api", definition, str(file)]
    result = subprocess.run([str(exe), *args], capture_output=True, text=True, timeout=15)
    lines.append(f"{name}: exit={result.returncode}; {(result.stdout + result.stderr).strip()}")
    if result.returncode != expected:
        raise SystemExit("Observed behavior changed: " + lines[-1])
(HERE / "results-fixed.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
print("\n".join(lines))
