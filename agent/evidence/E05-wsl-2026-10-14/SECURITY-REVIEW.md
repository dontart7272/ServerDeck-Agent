# E05 scoped security review and fixes

14 October 2026. Applied local `.agents/skills/owasp-audit/SKILL.md`; scope: new history/events, telemetry SQLite, migration3/rules/config handlers, protected reads/WSS resume. This is not a whole-product or release certification. Final Ubuntu runtime evidence is recorded in README.md/linux-checks.txt/full-filesystem.txt; it is not a whole-product security certification.

- A01/A07: existing session/Unix peer authorization and shared operation service retained; rules/config require durable intent and version checks. Unauthenticated rules read and cross-actor cursors exercised in real TLS tests.
- A02: existing cursor HMAC key, trusted actor/run/query scope; SQLite0600/private directory FD reused. No new credentials or crypto dependency. No claim of at-rest encryption against host admin.
- A03/A10: SQL values parameterized; numeric PRAGMA only from bounded integers. No shell/network-fetch/HTML sinks introduced by E05 application code. Native source interfaces accept typed observations, not log text.
- A04/A08: fixed normal-event duplicate begin/recovery after lost commit acknowledgment using frozen event IDs and real SQLite unique index/deduplication; real-DB acknowledgment-loss test passes. Rule revision namespace prevents delete/recreate and restore ABA. Auxiliary schemas/checksums/Agent binding checked before use. SSH lost-ack and quota edge cases require second pass/final checks.
- A05: unknown/corrupt schema fails closed without replacement; FULL/WAL, bounded readers/batches, protected sidecars. Physical byte/WAL accounting and reclaim need final stress and isolated ENOSPC evidence.
- A06: no new Go/native dependency; existing pins/lock unchanged. CVE scan is not performed/claimed here; release gate remains E12.
- A09: independent RAM health for history/events; no raw logs, command lines or tokens stored by E05. Gap markers and current active state retained separately from rotated events. All ignored loop errors must remain visible via health; second pass checks this explicitly.

Checked clean so far: no unauthenticated E05 route, no arbitrary command endpoint, no string-concatenated SQL value, no external HTTP request, no client actor trusted from body, no removal of critical identity/tokens for telemetry space. Runtime tests and bounds, not this checklist alone, determine readiness.


## Adversarial second pass and fixes

A separate read-only agent was instructed to assume the author overconfident. It identified lost counter deltas at15s boundaries, SSH lost-commit acknowledgment and silently failed rule reads. Its further review stopped at account usage limit, so this is NOT a completed independent whole-scope audit. The primary agent repeated the adversarial pass after fixes.

- Boundary attribution now retains exact delta once, independently retains the full counter interval duration, and marks differing bucket coverage partial. The user delegated this decision on14 October; schema/technical docs updated together. TestCrossingCounterKeepsExactDeltaAndFullRateDenominator exercises both sides and rollup.
- SSH duplicate offset reconciles durable active state; recovery checks committed deletion before allocating a fresh event. TestSSHLostCommitReplyReconcilesDurableState wraps real SQLite commit, not mocked effects.
- Policy read failure marks current state source_unknown and independent health degraded. TestPolicyReadFailureIsVisibleWithoutJournal covers health.
- Cleanup admission now uses checkpoint/remaining WAL/allocated bytes/free space and bounded candidate cost, not just row count. Incremental vacuum is stepped to completion with page cap; emergency reclaim keeps latest history by arrival rowid across backward UTC and never selects active problems/offsets. Logical event journal cap is distinct from active allowance; unsuccessful shrink cannot report success. TestTelemetryJournalShrinkAndGrowthAreConfirmedAgainstActualState uses real DB and verifies floor/state/page ceiling.
- New negative transport tests exercise cross-actor large-history cursor, failed intent audit, real ACK timeout1013 and retained critical state. Native no-phone collection/persistence is exercised separately.

A01/A07 checked protected routes/cursor/session guards; A02 no new cryptography/credentials; A03 parameterized values, bounded numeric PRAGMA; A04/A08 state transitions/dedup/migrations; A05 explicit quotas/fail closed; A06 existing pinned dependencies verified but live CVE scan remains E12; A09 independent health/gaps, no secret payload logging; A10 no outbound URL sink introduced, N/A for E05. No finding is called accepted risk simply because it is difficult. Runtime fixture limitations (native adapters/Android/host matrix) remain explicit planned gates.

Final repeat: vet/tests/race/fuzz, failed-audit guard, real-DB lost acknowledgments, isolated physical ENOSPC and contracts/docs passed. Gap retry now also keeps row filter timestamp identical to frozen observed_at. No completed independent whole-scope audit or CVE scan is claimed.

15 October follow-up: retention reduction cannot return success while expiration is unconfirmed. The existing durable config operation is returned as cleanup_operation_id; unknown/partial retains E02 locks/intent and requires reconciliation, never blind retry. Added real-DB old-record/empty-journal regression tests. No new authorization path or internal auto-effect replay introduced.
