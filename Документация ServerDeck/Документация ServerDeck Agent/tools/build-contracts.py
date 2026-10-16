"""Authoring helper for documentation schemas/examples; contains no Agent code.
Run only when editing this technical specification, then run check-docs.ps1.
"""
import copy
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1] / "contracts"
BASE.mkdir(exist_ok=True)
(BASE / "examples").mkdir(exist_ok=True)
DRAFT = "http://json-schema.org/draft-07/schema#"

def s(maximum=256, minimum=0, **kw):
    return dict(type="string", minLength=minimum, maxLength=maximum, **kw)
def n(lo=0, hi=2147483647):
    return dict(type="integer", minimum=lo, maximum=hi)
def enum(*values):
    return {"enum": list(values)}
def arr(item, maximum=100, minimum=0):
    return dict(type="array", items=item, minItems=minimum, maxItems=maximum)
def obj(props, optional=()):
    return dict(type="object", properties=props,
                required=[k for k in props if k not in optional], additionalProperties=False)
def ref(name):
    return {"$ref": "#/definitions/" + name}
def nullable(value):
    return {"anyOf": [value, {"type": "null"}]}
def write(name, definitions, root):
    definitions = copy.deepcopy(definitions)
    if "JsonValue" in definitions:
        # Finite depth avoids cyclic-schema compiler differences between validators.
        scalar = [{"type": "null"}, {"type": "boolean"}, {"type": "number"}, s(4096)]
        definitions["JsonValue0"] = {"anyOf": scalar}
        for depth in range(1, 33):
            child = ref("JsonValue" + str(depth - 1))
            definitions["JsonValue" + str(depth)] = {"anyOf": [*scalar, arr(child, 100),
                {"type": "object", "maxProperties": 100, "additionalProperties": child}]}
        definitions["JsonValue"] = ref("JsonValue32")
    document = {"$schema": DRAFT, "$id": "urn:serverdeck:" + name + ":1",
                "title": "ServerDeck " + name + " specification 1.0",
                **root, "definitions": definitions}
    (BASE / (name + ".schema.json")).write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
def example(name, value):
    (BASE / "examples" / (name + ".json")).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

ID = s(36, 36, pattern=r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
OS_UUID = s(36, 36, pattern=r"^[0-9a-f-]{36}$")
VER = s(256, 1)
SEMVER = s(80, 5, pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$")
TIME = s(30, 20, pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z$", format="date-time")
HASH = s(64, 64, pattern=r"^[0-9a-f]{64}$")
U64 = s(20, 1, pattern=r"^(0|[1-9][0-9]{0,19})$")
B64 = s(340, 1, pattern=r"^[A-Za-z0-9_-]+$")
TOKEN = s(43, 43, pattern=r"^[A-Za-z0-9_-]{43}$")
MODULE = s(128, 3, pattern=r"^[a-z0-9][a-z0-9.-]*\.[a-z0-9][a-z0-9.-]*$")
BOOL = {"type": "boolean"}
NUM = {"type": "number"}
PATH = s(4096, 1, pattern=r"^/")
RANGE = obj({"min_inclusive": SEMVER, "max_exclusive": SEMVER})
UNIT = enum("percent", "byte", "byte_per_second", "packet", "packet_per_second", "count", "second", "hertz", "celsius", "watt", "bit_per_second", "ratio", "bool")
LOC = obj({"root_id": ID, "components": arr(B64, 256)})

# Strict finite structure around dynamic, separately registered module schemas.
JSONVAL = {"anyOf": [{"type": "null"}, BOOL, NUM, s(4096),
    arr(ref("JsonValue"), 100),
    {"type": "object", "maxProperties": 100, "additionalProperties": ref("JsonValue")}]}
SCHEMA = {"type": "object", "maxProperties": 128, "additionalProperties": ref("JsonValue")}
CAP = obj({"id": s(128, 1), "available": BOOL, "reason": nullable(s(128)), "version": VER})

runtime = obj({
    "history": obj({"budget_bytes": n(16000000, 16000000000), "module_share_percent": n(0, 25)}),
    "events": obj({"retention_days": n(1, 365), "budget_bytes": n(1000000, 1000000000)}),
    "audit": obj({"retention_days": n(1, 365), "budget_bytes": n(4000000, 2000000000)}),
    "files": obj({"full_text_bytes": n(1000, 1000000), "edit_bytes": n(1000, 512000),
        "upload_bytes": n(1000, 1000000000), "download_bytes": n(1000, 2000000000),
        "roots": arr(obj({"root_id": ID, "path": PATH}), 32, 1)}),
    "trash": obj({"retention_days": n(1, 365), "budget_bytes_per_fs": n(1000000, 100000000000)}),
    "icmp": obj({"target": nullable(s(253, 1)), "background_enabled": BOOL})})
changes = copy.deepcopy(runtime)
changes["required"] = []
changes["minProperties"] = 1
config = obj({"config_version": {"const": 1}, "installation_id": ID,
    "runtime_user": s(80, 1, pattern=r"^[a-zA-Z_][a-zA-Z0-9_.-]*\$?$"),
    "paths": obj({"state": PATH, "runtime": PATH, "releases": PATH}),
    "tls": obj({"certificate_file": PATH, "private_key_file": PATH}),
    "transport": obj({"mode": enum("localhost", "lan_vpn", "external"),
        "listen_addresses": arr(s(253, 1), 16, 1), "allowed_cidrs": arr(s(64, 1), 64), "port": n(1, 65535)}),
    "adapters": obj({"docker_socket": nullable(PATH), "security_sources": {"const": "auto_supported"}, "ping_executable": PATH}),
    "modules": obj({"cgroup_delegation": BOOL}), "limits_profile": {"const": "default-v1"},
    "runtime_initial": runtime})
write("config", {}, config)

metric = obj({"key": s(128, 1), "resource_id": VER, "series_schema": VER,
    "unit": UNIT, "value": nullable({"anyOf": [NUM, BOOL, U64]}),
    "availability": enum("available", "absent", "unsupported", "permission_denied", "source_error"),
    "freshness": enum("fresh", "stale", "unknown"), "measured_at": nullable(TIME),
    "attempted_at": TIME, "expected_interval_ms": nullable(n(1, 3600000)), "source": s(128, 1),
    "reason": nullable(s(128))})
process = obj({"process_ref": VER, "boot_id": OS_UUID, "pid": n(1, 4194304), "start_ticks": U64,
    "pid_namespace": U64, "name": s(256), "uid": n(0, 4294967295), "state": s(32),
    "observed_at": TIME, "metrics": arr(ref("Metric"), 32), "parent_ref": nullable(VER),
    "threads": n(0, 10000000), "systemd_unit": nullable(s(256)), "container_id": nullable(s(128)),
    "cgroup": nullable(s(1024)), "actions": arr(CAP, 16), "visibility": enum("complete", "limited")})
file = obj({"location": LOC, "display_name": s(1024), "kind": enum("file", "directory", "symlink", "special"),
    "size_bytes": nullable(U64), "modified_at": nullable(TIME), "changed_at": nullable(TIME), "mode": s(4, 4, pattern=r"^[0-7]{4}$"),
    "uid": n(0, 4294967295), "gid": n(0, 4294967295), "version": VER, "filesystem_id": VER, "actions": arr(CAP, 16)})
root = obj({"root_id": ID, "display_name": s(256), "path": PATH, "version": VER, "filesystem_id": VER,
    "available_bytes": nullable(U64), "actions": arr(CAP, 16), "reason": nullable(s(128))})
ticket = obj({"transfer_id": ID, "mode": enum("text", "download", "upload", "edit"), "file_version": nullable(VER),
    "size_bytes": U64, "sha256": nullable(HASH), "encoding": nullable(enum("utf-8", "utf-8-bom")),
    "expires_at": TIME, "truncated": BOOL, "byte_from": U64, "byte_to": U64, "next_cursor": nullable(s(2048, 1))})
initiator = obj({"kind": enum("device", "local", "system"), "id": s(128, 1)})
op = obj({"operation_id": ID, "revision": VER, "initiator": initiator, "action": s(128, 1), "object_ref": s(1024),
    "state": enum("preparing", "running", "succeeded", "rejected", "failed", "cancelled", "unknown"),
    "phase": s(128, 1), "created_at": TIME, "updated_at": TIME, "effect_status": enum("none", "applied", "partial", "unknown"),
    "audit_status": enum("durable", "result_pending", "unavailable"), "cancellable": BOOL,
    "progress": nullable(obj({"completed": U64, "total": nullable(U64), "unit": s(32, 1)})),
    "result": nullable(ref("JsonValue")), "error": nullable(ref("Error")), "dedup_until": nullable(TIME)},
    ("progress", "result", "error", "dedup_until"))
event = obj({"epoch": ID, "sequence": U64, "event_id": ID, "problem_id": nullable(ID),
    "kind": enum("begin", "repeat", "recovery", "observation", "gap"), "severity": enum("info", "warning", "critical"),
    "resource_id": VER, "observed_at": TIME, "first_at": TIME, "last_at": TIME, "count": U64,
    "code": s(128, 1), "details": ref("JsonValue")})
problem = obj({"problem_id": ID, "rule_id": s(128, 1), "resource_id": VER, "state": enum("active", "source_unknown"),
    "since": TIME, "observed_at": TIME, "severity": enum("warning", "critical"), "code": s(128, 1)})
audit = obj({"epoch": ID, "sequence": U64, "operation_id": nullable(ID), "kind": enum("intent", "result", "rejection", "gap"),
    "initiator": initiator, "action": s(128, 1), "object_ref": s(1024), "observed_at": TIME,
    "effect_status": enum("none", "applied", "partial", "unknown"), "code": s(128)})
coverage = obj({"from": nullable(TIME), "to": nullable(TIME), "complete": BOOL,
    "gaps": arr(obj({"from": TIME, "to": TIME, "reason": s(128, 1)}), 256)})
def page(item):
    return obj({"items": arr(item), "next_cursor": nullable(s(2048, 1)), "coverage": ref("Coverage"), "revision": VER})

device = obj({"device_id": ID, "name": s(80, 1), "version": VER, "created_at": TIME,
    "last_seen_at": nullable(TIME), "revoked_at": nullable(TIME)})
modstate = obj({"module_id": MODULE, "version": SEMVER, "registration_revision": VER,
    "desired": enum("enabled", "disabled"), "process": enum("stopped", "starting", "running", "stopping", "exited", "unknown"),
    "ipc": enum("disconnected", "handshaking", "ready", "unresponsive"), "health": enum("ok", "degraded", "error", "incompatible"),
    "resource_isolation": enum("available", "unavailable"), "capabilities": arr(CAP, 256), "reason": nullable(s(128))})
rule = obj({"id": s(128, 1), "version": VER, "enabled": BOOL,
    "kind": enum("threshold", "device_threshold", "source_stale", "ssh_window"),
    "resource_selector": s(256, 1), "metric": s(128, 1), "unit": UNIT,
    "comparison": enum("lt", "lte", "gt", "gte"), "threshold": nullable(NUM), "duration_ms": n(0, 86400000),
    "recovery_comparison": enum("lt", "lte", "gt", "gte"), "recovery_threshold": nullable(NUM),
    "recovery_duration_ms": n(0, 86400000), "repeat_ms": n(3600000, 2592000000)})
storage = obj({"kind": s(32, 1), "status": enum("ok", "degraded", "unavailable"), "used_bytes": U64,
    "budget_bytes": U64, "wal_bytes": U64, "reserve_bytes": U64, "reason": nullable(s(128))})
info = obj({"agent_id": ID, "agent_run_id": ID, "version": SEMVER,
    "api_majors": arr(n(1, 100), 2, 1), "ipc_min": SEMVER, "ipc_max": SEMVER, "ui_schema": n(1, 100),
    "runtime": obj({"user": s(80, 1), "uid": n(0, 4294967295), "gid": n(0, 4294967295), "root_warning": BOOL}),
    "capabilities": arr(CAP, 256), "storage": arr(storage, 16),
    "limits": obj({"json_bytes": {"const": 1000000}, "history_bytes": {"const": 4000000}, "history_points": {"const": 2000},
        "process_page": {"const": 100}, "active_operations": {"const": 4}, "file_transfers": {"const": 2}}),
    "tls": obj({"fingerprint_sha256": HASH, "not_after": TIME, "rotation_warning": BOOL}),
    "sources": arr(CAP, 128)})

# Resource record variants; metrics carry units and precise availability.
def resource(kind, props, optional=()):
    return obj({"record_type": {"const": kind}, "resource_id": VER, **props}, optional)
records = [resource("system", {"hostname": s(256), "machine_id": nullable(s(128)), "os": s(256), "kernel": s(256),
    "architecture": s(32), "timezone": s(128), "uptime_seconds": NUM}),
    resource("cpu", {"logical_id": n(0, 1048576), "model": s(256), "topology": s(256), "observed_at": TIME}, ("observed_at",)),
    resource("cpu_summary", {"logical_cpu_count": nullable(n(1, 256))}),
    resource("gpu", {"uuid": s(128, 1), "name": s(256), "driver": nullable(s(80)), "cuda": nullable(s(80)),
        "pcie": nullable(s(128)), "processes": arr(obj({"process_ref": nullable(VER), "pid": n(1, 4194304), "metrics": arr(ref("Metric"), 16)}), 4096)}),
    resource("network", {"name": s(256), "interface_type": s(64), "addresses": arr(s(128), 128), "mtu": n(0, 10000000),
        "routes": arr(s(512), 256), "dns": arr(s(253), 64), "duplex": nullable(enum("half", "full")), "link_bps": nullable(U64),
        "observed_at": TIME, "operstate": s(32)}, ("observed_at", "operstate")),
    resource("network_summary", {"included_resource_ids": arr(VER, 256),
        "warning": {"const": "BRIDGE_VETH_DOUBLE_COUNT_POSSIBLE"}}),
    resource("filesystem", {"mountpoint": s(4096), "source": s(4096), "filesystem_type": s(80), "readonly": BOOL}),
    resource("docker", {"engine_version": nullable(s(80)), "api_version": nullable(s(80)),
        "containers": arr(obj({"id": s(128, 1), "name": s(256), "state": s(64), "health": nullable(s(64)),
            "compose_project": nullable(s(256)), "compose_service": nullable(s(256)), "metrics": arr(ref("Metric"), 16)}), 4096)}),
    resource("security", {"coverage": enum("complete", "partial", "unavailable"),
        "observations": arr(obj({"kind": enum("firewall", "ssh_session", "ssh_login", "fail2ban"),
            "code": s(128), "observed_at": TIME, "summary": s(512)}), 4096)})]
snapshot = obj({"snapshot_id": ID, "agent_run_id": ID, "boot_id": OS_UUID, "segment_id": ID,
    "captured_at": TIME, "partial": BOOL,
    "blocks": arr(obj({"block_id": s(128, 1), "collection_mode": enum("periodic", "on_demand", "event"),
        "observed_at": nullable(TIME), "expected_interval_ms": nullable(n(1, 3600000)), "metrics": arr(ref("Metric"), 4096),
        "records": arr({"anyOf": records + [ref("Process")]}, 4096),
        "availability": enum("available", "absent", "unsupported", "permission_denied", "source_error"), "reason": nullable(s(128))}), 64)})
point = obj({"bucket_id": VER, "revision": VER, "segment_id": ID, "from": TIME, "to": TIME,
    "step_ms": n(1, 86400000), "covered_ms": n(0, 86400000), "counter_covered_ms": n(0, 86460000), "sample_count": n(0, 10000000), "complete": BOOL,
    "statistics": obj({"mean": nullable(NUM), "min": nullable(NUM), "max": nullable(NUM), "last": nullable(NUM),
        "sum": nullable({"anyOf": [NUM, U64]}), "observed_true": nullable(BOOL)},
        ("mean", "min", "max", "last", "sum", "observed_true")), "gap_reason": nullable(s(128))}, ("counter_covered_ms",))
series = obj({"series_id": VER, "unit": UNIT, "schema": VER, "step_ms": n(1, 86400000), "coverage": ref("Coverage"), "points": arr(point, 2000)})
hist = obj({"items": arr(series, 32), "next_cursor": nullable(s(2048, 1)), "coverage": ref("Coverage"), "revision": VER})
icmp = obj({"target": nullable(s(253, 1)), "target_version": VER, "background_enabled": BOOL,
    "observed_at": nullable(TIME), "resolved_ip": nullable(s(64)), "packets_sent": n(0, 5), "packets_received": n(0, 5),
    "latency_ms": nullable(NUM), "loss_percent": nullable(NUM), "status": enum("available", "not_configured", "permission_denied", "source_error", "stale")})
errcodes = "INVALID_REQUEST INVALID_PATH UNSUPPORTED_QUERY UNSUPPORTED_ACTION UNAUTHORIZED PAIRING_REJECTED PERMISSION_DENIED POLICY_DENIED PROTECTED_OBJECT NOT_FOUND OPERATION_NOT_FOUND VERSION_CONFLICT OBJECT_CHANGED IDEMPOTENCY_CONFLICT DEPENDENCY_CONFLICT CURSOR_GAP BUSY PLAN_EXPIRED CURSOR_EXPIRED TRANSFER_EXPIRED LIMIT_EXCEEDED INCOMPATIBLE_VERSION INVALID_MANIFEST UNSUPPORTED_ENCODING SAFETY_UNAVAILABLE RATE_LIMITED AUDIT_UNAVAILABLE STORAGE_UNAVAILABLE SOURCE_UNAVAILABLE MAINTENANCE MODULE_UNAVAILABLE NO_SPACE QUOTA_EXCEEDED INTERNAL_ERROR".split()
error = obj({"code": enum(*errcodes), "message": s(512), "retryable": BOOL, "operation_id": ID,
    "details": obj({"field": s(128), "current_version": VER, "earliest_cursor": s(2048), "latest_cursor": s(2048),
        "retry_after_ms": n(0, 3600000), "effect_status": enum("none", "applied", "partial", "unknown"), "active_problems": arr(problem, 100), "active_problems_more": BOOL},
        ("field", "current_version", "earliest_cursor", "latest_cursor", "retry_after_ms", "effect_status", "active_problems", "active_problems_more"))}, ("operation_id", "details"))
defs = dict(JsonValue=JSONVAL, Metric=metric, Process=process, File=file, Coverage=coverage, Operation=op,
    Error=error, Runtime=runtime, ConfigChanges=changes, Rule=rule, Snapshot=snapshot, SeriesPage=hist,
    Info=info, ModuleState=modstate, Ticket=ticket)
def envelope(props):
    return {"schema_version": {"const": "1.0"}, "request_id": ID, **props}
def response(props):
    return envelope({"agent_id": ID, "served_at": TIME, **props})
page_params = {"cursor": s(2048, 1), "limit": n(1, 100)}
def params(props=None, optional=(), paged=False):
    values = props or {}
    if paged:
        return obj({**values, **page_params}, (*optional, "cursor", "limit"))
    return obj(values, optional)

queries = {
    "agent.info": (params(), ref("Info")),
    "snapshot.get": (params({"view": enum("summary", "detail"), "blocks": arr(s(128, 1), 64), "resource_ids": arr(VER, 256)}, ("blocks", "resource_ids")), ref("Snapshot")),
    "history.get": (params({"series_ids": arr(VER, 32, 1), "from": TIME, "to": TIME, "max_points": n(1, 2000), "cursor": s(2048, 1)}, ("cursor",)), ref("SeriesPage")),
    "history.series": (params({"metric_key": s(128, 1), "logical_key": s(512, 1)}, ("metric_key", "logical_key"), True), page(obj({"series_id": VER, "resource_id": VER, "logical_key": s(512, 1), "key": s(128, 1), "unit": UNIT, "schema": VER, "source": s(128, 1)}))),
    "events.list": (params({"from": TIME, "to": TIME, "resource_id": VER, "severity": enum("info", "warning", "critical")}, ("from", "to", "resource_id", "severity"), True), page(event)),
    "problems.list": (params(paged=True), page(problem)),
    "audit.list": (params({"from": TIME, "to": TIME, "operation_id": ID}, ("from", "to", "operation_id"), True), page(audit)),
    "processes.list": (params({"search": s(256), "sort": enum("cpu", "rss", "pid", "name"), "order": enum("asc", "desc")}, ("search",), True), page(ref("Process"))),
    "processes.get": (params({"process_ref": VER}), ref("Process")),
    "files.roots": (params(), obj({"items": arr(root, 32), "version": VER})),
    "files.list": (params({"location": LOC, "sort": enum("name", "size", "modified"), "order": enum("asc", "desc")}, paged=True), page(ref("File"))),
    "files.stat": (params({"location": LOC}), ref("File")),
    "files.text": (params({"location": LOC, "mode": enum("full", "tail"), "lines": enum(100, 500, 1000), "cursor": s(2048, 1)}, ("lines", "cursor")), ref("Ticket")),
    "files.download": (params({"location": LOC, "expected_version": VER}), ref("Ticket")),
    "trash.list": (params({"filesystem_id": VER}, ("filesystem_id",), True), page(obj({"trash_id": ID, "version": VER, "filesystem_id": VER,
        "original_location": LOC, "initiator": initiator, "deleted_at": TIME, "expires_at": TIME, "size_bytes": U64, "actions": arr(CAP, 4)}))),
    "devices.list": (params(paged=True), page(device)),
    "modules.list": (params(paged=True), page(ref("ModuleState"))),
    "modules.describe": (params({"module_id": MODULE}), obj({"module_id": MODULE, "version": SEMVER, "reads": arr(SCHEMA, 64),
        "actions": arr(SCHEMA, 64), "series": arr(SCHEMA, 256), "ui": arr(obj({"package_digest": HASH, "size_bytes": n(1, 5000000), "version": SEMVER, "publisher_id": MODULE}), 16)})),
    "modules.read": (params({"module_id": MODULE, "read_id": s(128, 1), "params": ref("JsonValue")}), obj({"module_id": MODULE, "schema": VER,
        "observed_at": nullable(TIME), "freshness": enum("fresh", "stale", "unknown"), "data": ref("JsonValue")})),
    "config.get": (params(), obj({"version": VER, "runtime": ref("Runtime")})),
    "rules.list": (params(paged=True), page(ref("Rule"))),
    "diagnostics.icmp": (params(), icmp),
    "operations.list": (params({"state": op["properties"]["state"]}, ("state",), True), page(ref("Operation"))),
}
defs["QueryRequest"] = {"oneOf": [obj(envelope({"query": {"const": q}, "params": p})) for q, (p, d) in queries.items()]}
defs["QueryResponse"] = {"oneOf": [obj(response({"query": {"const": q}, "data": d})) for q, (p, d) in queries.items()]}
source = {"location": LOC, "expected_version": VER}
target = {"target_parent": LOC, "target_name": B64, "target_parent_version": VER}
actions = {
    "config.set": params({"changes": ref("ConfigChanges")}),
    "rules.put": params({"rule": ref("Rule")}), "rules.delete": params({"rule_id": s(128, 1)}),
    "files.create": params({"parent": LOC, "name": B64, "kind": enum("file", "directory"), "parent_version": VER}),
    "files.write.begin": params({**source, "size_bytes": n(0, 512000), "sha256": HASH, "encoding": enum("utf-8", "utf-8-bom")}),
    "files.upload.begin": params({"parent": LOC, "name": B64, "parent_version": VER, "size_bytes": n(0, 1000000000), "sha256": HASH,
        "conflict": enum("fail", "replace"), "replace_version": VER}, ("replace_version",)),
    "files.transfer.commit": params({"transfer_id": ID, "sha256": HASH, "size_bytes": n(0, 1000000000), "expected_version": VER}),
    "files.rename": params({**source, **target}), "files.move": params({**source, **target}),
    "files.trash": params(source),
    "trash.restore": params({"trash_id": ID, "expected_version": VER, **target, "conflict": enum("fail", "replace"), "replace_version": VER}, ("replace_version",)),
    "trash.purge": params({"trash_id": ID, "expected_version": VER}),
    "process.term": params({"process_ref": VER}), "process.kill": params({"process_ref": VER}),
    "diagnostics.icmp.run": params({"target_version": VER}),
    "devices.revoke": params({"device_id": ID, "expected_version": VER}),
    "modules.set_desired": params({"module_id": MODULE, "expected_version": VER, "desired": enum("enabled", "disabled"),
        "affected_dependency_versions": arr(obj({"module_id": MODULE, "version": VER}), 64)}),
    "modules.policy.set": params({"module_id": MODULE, "expected_version": VER, "reads": arr(s(128, 1), 64), "actions": arr(s(128, 1), 64),
        "series": arr(s(128, 1), 256), "history_budget_bytes": n(0, 4000000000)}),
    "modules.remove": params({"module_id": MODULE, "expected_version": VER, "purge_data": BOOL,
        "affected_dependency_versions": arr(obj({"module_id": MODULE, "version": VER}), 64)}),
    "modules.action": params({"module_id": MODULE, "action_id": s(128, 1), "module_version": SEMVER, "params": ref("JsonValue")}),
    "operations.cancel": params({"target_operation_id": ID, "expected_version": VER})}
signal_result = obj({"process_ref": VER, "signal_sent": BOOL, "exit_observed": BOOL, "observed_at": TIME})
results = {
    "config.set": obj({"version": VER, "cleanup_operation_id": nullable(ID)}),
    "rules.put": obj({"rule_id": s(128, 1), "version": VER}),
    "rules.delete": obj({"rule_id": s(128, 1), "version": VER}),
    "files.create": ref("File"), "files.write.begin": ref("Ticket"), "files.upload.begin": ref("Ticket"),
    "files.transfer.commit": ref("File"), "files.rename": ref("File"),
    "files.move": obj({"source_status": enum("retained", "trashed", "unknown"), "target": nullable(ref("File")),
        "trash_id": nullable(ID), "completed_phases": arr(s(128, 1), 16), "unknown_phases": arr(s(128, 1), 16)}),
    "files.trash": obj({"trash_id": ID, "version": VER}),
    "trash.restore": obj({"file": ref("File"), "replaced_trash_id": nullable(ID)}),
    "trash.purge": obj({"trash_id": ID, "purged": BOOL}),
    "process.term": signal_result, "process.kill": signal_result,
    "diagnostics.icmp.run": icmp,
    "devices.revoke": obj({"device_id": ID, "revoked_at": TIME}),
    "modules.set_desired": ref("ModuleState"),
    "modules.policy.set": obj({"module_id": MODULE, "revision": VER}),
    "modules.remove": obj({"module_id": MODULE, "registration_removed": BOOL, "code_removed": BOOL, "data_removed": BOOL,
        "retained_paths": arr(s(4096, 1), 64)}),
    "modules.action": obj({"module_id": MODULE, "action_id": s(128, 1), "result_schema": SEMVER, "data": ref("JsonValue")}),
    "operations.cancel": obj({"target_operation_id": ID, "state": enum("cancelled", "too_late", "unknown")}),
    "system.trash.expire": obj({"trash_id": ID, "purged": BOOL}),
    "system.storage.cleanup": obj({"kind": enum("history", "events", "audit", "staging"), "freed_bytes": U64, "complete": BOOL}),
    "devices.pair": obj({"device_id": ID, "created_at": TIME}),
    # Read-only views of local maintenance/bootstrap audit operations. These
    # names are deliberately absent from public Prepare/OperationRequest.
    "pairing.issue": obj({"pairing_id": ID, "expires_at": TIME}),
    "storage.backup": obj({"complete": BOOL}),
    "storage.restore": obj({"complete": BOOL}),
    "storage.inventory.confirm": obj({"inventory_attested": BOOL}),
    "system.files.cleanup": obj({"cleaned": BOOL}),
    "system.files.rotate": obj({"rotated": BOOL}),
    "files.reconcile": {"oneOf": [obj({"reconciled": BOOL}), obj({"discarded": BOOL})]},
    "modules.register": ref("ModuleState")}
op_variants = []
for action, result in results.items():
    variant = copy.deepcopy(op)
    variant["properties"]["action"] = {"const": action}
    variant["properties"]["result"] = nullable(result)
    op_variants.append(variant)
defs["Operation"] = {"oneOf": op_variants}
defs["TransferReceipt"] = obj({"schema_version": {"const": "1.0"}, "transfer_id": ID, "received_bytes": n(0, 1000000000), "sha256": s(64,64,pattern="^[0-9a-f]{64}$"), "ready": {"const": True}})
defs["LocalTransferInput"] = obj({"transfer_id": ID, "size_bytes": n(0,1000000000), "sha256": s(64,64,pattern="^[0-9a-f]{64}$")})
defs["FileReconcileInput"] = obj({"record_id": ID,"expected_version":s(64,64,pattern="^[0-9a-f]{64}$"),"state":enum("trashed","purged","published","restored","discard"),"observed_proof":s(64,64,pattern="^[0-9a-f]{64}$")},("observed_proof",))
defs["InventoryConfirmationInput"] = obj({"known_regions":arr(s(1024,1,pattern="^/"),32),"absent_operation_ids":arr(ID,0),"artifact_bindings":arr(obj({"artifact_id":ID,"region_path":s(1024,1,pattern="^/")}),32)},("artifact_bindings",))
for name, prepared in [("PrepareRequest", False), ("OperationRequest", True)]:
    variants = []
    for action, p in actions.items():
        props = envelope({"operation_id": ID, "action": {"const": action}, "params": p, "expected_version": VER})
        if prepared:
            props["plan_id"] = s(22, 22, pattern=r"^[A-Za-z0-9_-]{22}$")
        variants.append(obj(props, () if action in ("config.set", "rules.put", "rules.delete") else ("expected_version",)))
    defs[name] = {"oneOf": variants}
defs["PrepareResult"] = obj(response({"plan_id": s(22, 22), "operation_id": ID, "expires_at": TIME,
    "object_versions": arr(obj({"object_ref": s(1024), "version": VER}), 128),
    "consequences": arr(obj({"code": s(128, 1), "description": s(512), "irreversible": BOOL}), 128)}))
defs["PairRequest"] = obj(envelope({"pairing_id": ID, "pairing_code": s(22, 22, pattern=r"^[A-Za-z0-9_-]{22}$"), "device_name": s(80, 1)}))
defs["PairResult"] = obj(response({"device_id": ID, "token": TOKEN, "api_majors": arr(n(1, 100), 2, 1), "created_at": TIME}))
defs["ErrorEnvelope"] = obj(envelope({"agent_id": ID, "served_at": TIME, "error": ref("Error")}), ("agent_id",))
# Topic parameters reuse the corresponding query filters, without pagination.
sub_variants = []
for topic, query in [("snapshot", "snapshot.get"), ("events", "events.list"), ("operations", "operations.list"), ("problems", "problems.list"), ("storage", None)]:
    topic_params = copy.deepcopy(queries[query][0]) if query else obj({})
    for field in ("cursor", "limit"):
        topic_params["properties"].pop(field, None)
        if field in topic_params["required"]:
            topic_params["required"].remove(field)
    props = {"id": s(64, 1), "topic": {"const": topic}, "params": topic_params}
    if topic != "snapshot":
        props["after"] = s(2048, 1)
    sub_variants.append(obj(props, ("after",)))
defs["WssSubscription"] = {"oneOf": sub_variants}
ws_common = {"schema_version": {"const": "1.0"}, "subscription_id": s(64, 1), "server_time": TIME}
defs["WssClientMessage"] = {"oneOf": [obj(envelope({"type": {"const": "subscribe"}, "subscriptions": arr(ref("WssSubscription"), 16, 1)})),
    obj({"schema_version": {"const": "1.0"}, "type": {"const": "ack"}, "subscription_id": s(64, 1), "cursor": s(2048, 1)})]}
changes_variants = []
problem_change = {"oneOf": [problem, obj({"problem_id": ID, "removed": {"const": True}, "observed_at": TIME})]}
for topic, item in [("events", event), ("operations", ref("Operation")), ("problems", problem_change), ("storage", storage)]:
    name = "WssChanges" + topic.title()
    defs[name] = obj({**ws_common, "type": {"const": "changes"}, "topic": {"const": topic},
        "data": arr(item, 100), "cursor": s(2048, 1)})
    changes_variants.append(ref(name))
defs["WssServerMessage"] = {"oneOf": [obj({**ws_common, "type": {"const": "snapshot"}, "data": ref("Snapshot")}),
    *changes_variants,
    obj({**ws_common, "type": {"const": "gap"}, "error": ref("Error")}),
    obj({**ws_common, "type": {"const": "error"}, "error": ref("Error")}),
    obj({**ws_common, "type": {"const": "subscribed"}, "cursor": nullable(s(2048, 1))}),
    obj({"schema_version": {"const": "1.0"}, "type": {"const": "heartbeat"}, "server_time": TIME})]}
defs["WssMessage"] = {"oneOf": [ref("WssClientMessage"), ref("WssServerMessage")]}
write("api", defs, {"anyOf": [ref(k) for k in ["PairRequest", "PairResult", "QueryRequest", "QueryResponse", "PrepareRequest", "PrepareResult", "OperationRequest", "Operation", "ErrorEnvelope", "WssMessage", "TransferReceipt"]]})

read_decl = obj({"id": s(128, 1), "schema_version": SEMVER, "params_schema": SCHEMA, "result_schema": SCHEMA, "timeout_ms": n(1, 10000)})
action_decl = obj({"id": s(128, 1), "schema_version": SEMVER, "params_schema": SCHEMA, "result_schema": SCHEMA,
    "effect": enum("read_only", "mutation"), "cancellation": enum("before_effect", "supported", "unsupported"),
    "confirmation": {"const": "native_plan"}, "reconcile_supported": BOOL})
series_decl = obj({"id": s(128, 1), "schema_version": SEMVER, "unit": UNIT, "value_type": enum("number", "u64", "boolean"),
    "aggregation": arr(enum("mean", "min", "max", "last", "sum", "observed_true"), 6, 1),
    "interval_ms": n(1000, 3600000), "max_cardinality": n(1, 256), "history_allowed": BOOL})
managed = obj({"mode": {"const": "managed"}, "executable": PATH, "args": arr(s(1024), 64), "code_dir": PATH, "data_dir": PATH})
external = obj({"mode": {"const": "external"}, "uid": n(0, 4294967295), "endpoint_id": ID, "launch_policy_id": ID, "code_dir": PATH, "data_dir": PATH})
manifest = obj({"manifest_version": {"const": 1}, "module_id": MODULE, "publisher_id": MODULE, "version": SEMVER,
    "compatibility": obj({"os": {"const": "linux"}, "architectures": arr(enum("amd64", "arm64"), 2, 1), "agent": RANGE, "ipc": RANGE, "data_schema": RANGE}),
    "execution": {"oneOf": [managed, external]}, "dependencies": arr(obj({"module_id": MODULE, "version": RANGE, "required": BOOL}), 32),
    "reads": arr(read_decl, 64), "actions": arr(action_decl, 64), "series": arr(series_decl, 256),
    "ui": arr(obj({"package_digest": HASH, "size_bytes": n(1, 5000000), "version": SEMVER, "publisher_id": MODULE,
        "server_schema": RANGE, "client_components": RANGE}), 16),
    "resource_request": obj({"max_series": n(0, 256), "history_budget_bytes": n(0, 4000000000), "memory_bytes": n(1000000, 16000000000), "cpu_percent": n(1, 10000), "pids": n(1, 4096)})})
write("module", {"JsonValue": JSONVAL}, manifest)

ipcdefs = copy.deepcopy(defs)
hello = obj({"registration_id": ID, "module_id": MODULE, "instance_id": ID, "secret": TOKEN,
    "ipc_min": SEMVER, "ipc_max": SEMVER, "capabilities": arr(s(128, 1), 256), "schema_digest": HASH})
execute = obj({"operation_id": ID, "action_id": s(128, 1), "params": ref("JsonValue"), "params_digest": HASH,
    "durable_intent_receipt": obj({"operation_id": ID, "audit_sequence": U64, "intent_digest": HASH})})
rpc_methods = {
    "hello": hello,
    "collect": obj({"sample_id": ID, "requested_series": arr(s(128, 1), 256), "deadline_ms": n(1, 10000)}),
    "read": obj({"read_id": s(128, 1), "params": ref("JsonValue"), "request_id": ID}),
    "operation.prepare": obj({"operation_id": ID, "action_id": s(128, 1), "params": ref("JsonValue"), "params_digest": HASH}),
    "operation.execute": execute,
    "operation.report": obj({"operation": ref("Operation")}),
    "operation.reconcile": obj({"operation_id": ID, "params_digest": HASH}),
    "operation.cancel": obj({"operation_id": ID, "revision": VER}),
    "event.publish": obj({"event_id": ID, "kind": s(128, 1), "resource_id": VER, "observed_at": TIME, "data": ref("JsonValue")}),
    "heartbeat": obj({"session_id": ID, "sequence": U64}),
    "shutdown": obj({"reason": s(128), "deadline_ms": n(1, 15000)})}
ipcdefs["Request"] = {"oneOf": [obj({"jsonrpc": {"const": "2.0"}, "id": s(64, 1), "method": {"const": m}, "params": p}) for m, p in rpc_methods.items()]}
ipcdefs["Welcome"] = obj({"session_id": ID, "ipc_version": SEMVER, "grants": arr(s(128, 1), 256),
    "limits": obj({"message_bytes": {"const": 1000000}, "in_flight": {"const": 8}, "rpc_timeout_ms": {"const": 10000}}), "agent_run_id": ID})
ipcdefs["Receipt"] = obj({"durable": {"const": True}, "id": ID, "sequence": U64})
ipcdefs["CollectResult"] = obj({"sample_id": ID, "block": snapshot["properties"]["blocks"]["items"]})
ipcdefs["ReadResult"] = obj({"read_id": s(128, 1), "schema_version": SEMVER, "observed_at": nullable(TIME), "data": ref("JsonValue")})
ipcdefs["OperationPlan"] = obj({"operation_id": ID, "allowed": BOOL, "cancellable": BOOL, "phases": arr(s(128, 1), 32), "reason": nullable(s(128))})
ipcdefs["Accepted"] = obj({"operation_id": ID, "accepted": {"const": True}})
ipcdefs["CancelResult"] = obj({"operation_id": ID, "status": enum("cancelled", "too_late", "unknown")})
ipcdefs["ShutdownResult"] = obj({"stopping": {"const": True}})
ipcdefs["HeartbeatResult"] = obj({"session_id": ID, "sequence": U64})
ipcdefs["Response"] = {"oneOf": [obj({"jsonrpc": {"const": "2.0"}, "id": s(64, 1), "result": {"anyOf": [ref(k) for k in
    ["Welcome", "Receipt", "Operation", "CollectResult", "ReadResult", "OperationPlan", "Accepted", "CancelResult", "ShutdownResult", "HeartbeatResult"]]}}),
    obj({"jsonrpc": {"const": "2.0"}, "id": nullable(s(64, 1)), "error": obj({"code": enum(-32700, -32600, -32601, -32602, -32603, -32001, -32002, -32003, -32004, -32005, -32006),
        "message": s(512), "data": ref("Error")}, ("data",))})]}
ipcdefs["Notification"] = obj({"jsonrpc": {"const": "2.0"}, "method": {"const": "heartbeat"}, "params": rpc_methods["heartbeat"]})
write("ipc", ipcdefs, {"anyOf": [ref("Request"), ref("Response"), ref("Notification")]})

node = obj({"node_id": s(64, 1), "type": enum("column", "row", "section", "text", "metric", "status", "chart", "table", "text_input", "number_input", "toggle", "select", "button"),
    "label_key": s(128), "children": arr(ref("Node"), 64), "binding": obj({"read_id": s(128, 1), "pointer": s(1024, 0, pattern=r"^(|/.*)$")}),
    "action_id": s(128, 1), "form_bindings": arr(obj({"parameter": s(128, 1), "field_node_id": s(64, 1)}), 64),
    "series_ids": arr(s(128, 1), 32), "options": arr(obj({"label_key": s(128, 1), "value": s(256)}), 100),
    "min": NUM, "max": NUM, "max_length": n(1, 4096), "max_rows": n(1, 100), "max_columns": n(1, 16)},
    ("label_key", "children", "binding", "action_id", "form_bindings", "series_ids", "options", "min", "max", "max_length", "max_rows", "max_columns"))
node["allOf"] = [
    {"if": {"properties": {"type": enum("column", "row", "section")}}, "then": {"required": ["children"]}, "else": {"not": {"required": ["children"]}}},
    {"if": {"properties": {"type": {"const": "button"}}}, "then": {"required": ["action_id"]}, "else": {"not": {"required": ["action_id"]}}}]
inventory_path = s(128, 1, pattern=r"^(ui\.json|assets/[A-Za-z0-9_./-]+|locales/[A-Za-z0-9_-]+\.json)$")
uimanifest = obj({"module_id": MODULE, "publisher_id": MODULE, "package_version": SEMVER, "ui_schema": {"const": 1},
    "server_schema": RANGE, "client_components": RANGE,
    "inventory": arr(obj({"path": inventory_path, "size_bytes": n(0, 20000000), "sha256": HASH}), 254, 1)})
ui = obj({"ui_schema": {"const": 1}, "screens": arr(obj({"screen_id": s(64, 1), "title_key": s(128, 1), "root": ref("Node")}), 32, 1)})
sig = obj({"algorithm": {"const": "Ed25519"}, "key_id": s(128, 1), "signature": s(86, 86, pattern=r"^[A-Za-z0-9_-]{86}$")})
write("ui", {"Node": node, "Manifest": uimanifest, "Ui": ui, "Signature": sig}, {"anyOf": [ref("Manifest"), ref("Ui"), ref("Signature")]})
release = obj({"release_id": ID, "version": SEMVER, "os": {"const": "linux"}, "architecture": enum("amd64", "arm64"),
    "kernel_min": s(80, 1), "glibc_min": s(80, 1), "native_libraries": arr(s(128, 1), 32), "api_majors": arr(n(1, 100), 2, 1),
    "ipc": RANGE, "ui_schema": n(1, 100), "security_floor_version": n(1, 1000),
    "databases": arr(obj({"name": enum("critical", "events", "history"), "read_min": n(1, 1000000), "read_max": n(1, 1000000), "write_version": n(1, 1000000)}), 3, 3),
    "rollback_release_ids": arr(ID, 16), "files": arr(obj({"path": s(128, 1), "size_bytes": U64, "sha256": HASH}), 256, 1)})
write("release", {}, release)

TEST_ID = "11111111-1111-4111-8111-111111111111"
TEST_ID2 = "22222222-2222-4222-8222-222222222222"
example("wss-client", {"schema_version": "1.0", "request_id": TEST_ID, "type": "subscribe",
    "subscriptions": [{"id": "summary", "topic": "snapshot", "params": {"view": "summary"}},
        {"id": "events", "topic": "events", "params": {}}]})
example("wss-server", {"schema_version": "1.0", "subscription_id": "storage", "server_time": "2026-10-13T00:00:00Z",
    "type": "changes", "topic": "storage", "cursor": "synthetic-example",
    "data": [{"kind": "audit", "status": "ok", "used_bytes": "0", "budget_bytes": "64000000", "wal_bytes": "0", "reserve_bytes": "0", "reason": None}]})
example("config", {"config_version": 1, "installation_id": TEST_ID, "runtime_user": "operator",
    "paths": {"state": "/var/lib/serverdeck", "runtime": "/run/serverdeck", "releases": "/opt/serverdeck/releases"},
    "tls": {"certificate_file": "/etc/serverdeck/tls/server.crt", "private_key_file": "/etc/serverdeck/tls/server.key"},
    "transport": {"mode": "localhost", "listen_addresses": ["127.0.0.1", "::1"], "allowed_cidrs": ["127.0.0.0/8", "::1/128"], "port": 8443},
    "adapters": {"docker_socket": None, "security_sources": "auto_supported", "ping_executable": "/usr/bin/ping"},
    "modules": {"cgroup_delegation": False}, "limits_profile": "default-v1",
    "runtime_initial": {"history": {"budget_bytes": 256000000, "module_share_percent": 25},
        "events": {"retention_days": 7, "budget_bytes": 32000000}, "audit": {"retention_days": 30, "budget_bytes": 64000000},
        "files": {"full_text_bytes": 1000000, "edit_bytes": 512000, "upload_bytes": 50000000, "download_bytes": 100000000,
            "roots": [{"root_id": TEST_ID2, "path": "/home/operator"}]},
        "trash": {"retention_days": 7, "budget_bytes_per_fs": 1000000000}, "icmp": {"target": None, "background_enabled": False}}})
example("query", {"schema_version": "1.0", "request_id": TEST_ID, "query": "history.get",
    "params": {"series_ids": ["system.cpu.busy.v1"], "from": "2026-10-12T00:00:00Z", "to": "2026-10-12T01:00:00Z", "max_points": 2000}})
example("operation", {"schema_version": "1.0", "request_id": TEST_ID, "operation_id": TEST_ID2,
    "action": "process.term", "params": {"process_ref": "boot:pid:123:start:456"}, "plan_id": "example_plan_id_000000"})
example("module", {"manifest_version": 1, "module_id": "example.health", "publisher_id": "example.publisher", "version": "1.0.0",
    "compatibility": {"os": "linux", "architectures": ["amd64", "arm64"], "agent": {"min_inclusive": "1.0.0", "max_exclusive": "2.0.0"},
        "ipc": {"min_inclusive": "1.0.0", "max_exclusive": "2.0.0"}, "data_schema": {"min_inclusive": "1.0.0", "max_exclusive": "2.0.0"}},
    "execution": {"mode": "managed", "executable": "/opt/serverdeck/modules/example.health/1.0.0/health", "args": [],
        "code_dir": "/opt/serverdeck/modules/example.health/1.0.0", "data_dir": "/var/lib/serverdeck/modules/example.health"},
    "dependencies": [], "reads": [], "actions": [], "series": [], "ui": [],
    "resource_request": {"max_series": 0, "history_budget_bytes": 0, "memory_bytes": 128000000, "cpu_percent": 25, "pids": 64}})
example("ipc", {"jsonrpc": "2.0", "id": "h1", "method": "heartbeat", "params": {"session_id": TEST_ID, "sequence": "1"}})
example("ipc-response", {"jsonrpc": "2.0", "id": "h1", "result": {"session_id": TEST_ID, "sequence": "1"}})
example("error", {"schema_version": "1.0", "request_id": TEST_ID, "agent_id": TEST_ID2, "served_at": "2026-10-12T10:00:00Z",
    "error": {"code": "AUDIT_UNAVAILABLE", "message": "Начало изменения не сохранено", "retryable": False}})
example("operation-state", {"operation_id": TEST_ID, "revision": "2", "initiator": {"kind": "device", "id": TEST_ID2},
    "action": "process.term", "object_ref": "boot:pid:123:start:456", "state": "unknown", "phase": "reconcile_required",
    "created_at": "2026-10-12T10:00:00Z", "updated_at": "2026-10-12T10:00:01Z", "effect_status": "unknown",
    "audit_status": "result_pending", "cancellable": False, "result": None})
example("snapshot-response", {"schema_version": "1.0", "request_id": TEST_ID, "agent_id": TEST_ID2, "served_at": "2026-10-12T10:00:08Z",
    "query": "snapshot.get", "data": {"snapshot_id": TEST_ID, "agent_run_id": TEST_ID2, "boot_id": TEST_ID, "segment_id": TEST_ID2,
        "captured_at": "2026-10-12T10:00:08Z", "partial": True, "blocks": [{"block_id": "cpu", "collection_mode": "periodic",
            "observed_at": "2026-10-12T10:00:00Z", "expected_interval_ms": 2000, "availability": "permission_denied", "reason": "SOURCE_ACCESS_DENIED",
            "metrics": [{"key": "busy_percent", "resource_id": "cpu.total.generation1", "series_schema": "1.0.0", "unit": "percent", "value": 0,
                "availability": "permission_denied", "freshness": "stale", "measured_at": "2026-10-12T10:00:00Z", "attempted_at": "2026-10-12T10:00:08Z",
                "expected_interval_ms": 2000, "source": "proc.stat", "reason": "SOURCE_ACCESS_DENIED"}], "records": []}]}})
example("ui", {"ui_schema": 1, "screens": [{"screen_id": "main", "title_key": "main.title",
    "root": {"node_id": "root", "type": "column", "children": [{"node_id": "intro", "type": "text", "label_key": "main.intro"}]}}]})
example("release", {"release_id": TEST_ID, "version": "1.0.0", "os": "linux", "architecture": "amd64", "kernel_min": "5.6", "glibc_min": "2.35",
    "native_libraries": ["libc.so.6", "libdl.so.2"], "api_majors": [1], "ipc": {"min_inclusive": "1.0.0", "max_exclusive": "2.0.0"}, "ui_schema": 1,
    "security_floor_version": 1, "databases": [{"name": name, "read_min": 1, "read_max": 1, "write_version": 1} for name in ("critical", "events", "history")],
    "rollback_release_ids": [], "files": [{"path": "serverdeck-agent", "size_bytes": "1", "sha256": "0" * 64}]})

# A transparent catalog links endpoint definitions to documentation/tooling.
for revision, complete, covered, mean in [("1", False, 7000, 12.0), ("2", True, 15000, 18.0)]:
    example("history-response" + ("-updated" if complete else ""), {
        "schema_version": "1.0", "request_id": TEST_ID, "agent_id": TEST_ID2,
        "served_at": "2026-10-12T00:00:20Z", "query": "history.get",
        "data": {"items": [{"series_id": "system.cpu.busy.v1", "unit": "percent", "schema": "1", "step_ms": 15000,
            "coverage": {"from": "2026-10-12T00:00:00Z", "to": "2026-10-12T00:00:15Z", "complete": complete, "gaps": []},
            "points": [{"bucket_id": "fixture-cpu-15s-0", "revision": revision, "segment_id": TEST_ID,
                "from": "2026-10-12T00:00:00Z", "to": "2026-10-12T00:00:15Z", "step_ms": 15000,
                "covered_ms": covered, "sample_count": 7 if complete else 3, "complete": complete,
                "statistics": {"mean": mean}, "gap_reason": None if complete else "WARMING_UP"}]}],
            "next_cursor": None, "coverage": {"from": "2026-10-12T00:00:00Z", "to": "2026-10-12T00:00:15Z", "complete": complete, "gaps": []}, "revision": revision}})
example("wss-problem-removed", {"schema_version": "1.0", "subscription_id": "problems", "server_time": "2026-10-12T00:00:20Z", "type": "changes", "topic": "problems", "data": [{"problem_id": TEST_ID, "removed": True, "observed_at": "2026-10-12T00:00:20Z"}], "cursor": "signed_fixture_cursor"})
example("catalog", {"queries": sorted(queries), "actions": sorted(actions), "ipc_methods": sorted(rpc_methods)})
print(f"Generated {len(list(BASE.glob('*.schema.json')))} schemas and {len(list((BASE / 'examples').glob('*.json')))} documentation examples/catalog files; no application implementation.")

example("transfer-receipt", {"schema_version":"1.0","transfer_id":TEST_ID,"received_bytes":0,"sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","ready":True})
