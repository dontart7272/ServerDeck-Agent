# E05 — Ubuntu WSL evidence

Tests dated14 October2026 UTC; completion15 October2026 Moscow. Current complete-stage work supersedes the historical [aggregation-only snapshot](../E05-aggregation-2026-10-14/README.md). E05 is closed in its planned Agent scope on the stated Ubuntu WSL environment. Conditional E06/E09/E10/E11/E12 work is not declared implemented or tested.

Commands from D:\Projects\ServerDeck:

```powershell
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e05.sh
wsl -d Ubuntu-22.04 -u root -- unshare --mount --propagation private bash /mnt/d/Projects/ServerDeck/agent/tools/e05-full-filesystem.sh
wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/tools/wsl-e05-export.sh
pwsh -NoProfile -File 'Документация ServerDeck/Документация ServerDeck Agent/tools/check-docs.ps1'
```

The first script creates a new Linux ext4 source.XXXXXX under /home/dontart7272/serverdeck-e05-complete-2026-10-14. Byte identity is verified before checks; build/test/tooling input inventory and hashes are verified again during export. Caches/tmp/test SQLite stay in Linux FS. Source manifest is a snapshot before later Markdown evidence updates, not a claim that documentation never changes. Export copies evidence only, not application sources or unrelated Windows dist.

Environment: Ubuntu22.04.5/WSL2 x86_64 kernel6.6.87.2-microsoft-standard-WSL2; UID1000; Go1.27.2/cgo1/GOTOOLCHAINlocal; GCC11.4.0, glibc2.35; pinned native/cross lock31packages/4372files. No new dependencies/licenses; go mod verify checks existing modules. SQLite runtime3.53.4 bundled pinned amalgamation, source ID and options in linux-checks.txt. Cross arm64 uses aarch64-linux-gnu-gcc-11. No native ARM run is claimed.

Final run: source.JBbv3g,182 byte-identical snapshot files;166 build/test/tooling inputs reverified at export. PASS gofmt/modverify/vet/test -v -count=1/race -count=1 on all packages, fuzz10s/178405 executions with2 workers, cgo amd64/arm64 builds and ELF checks; compiled TLS/CLI and critical schema3 backup/replay/restore smoke. Both binaries require max GLIBC2.34, not fully static. PASS repeated physical ENOSPC on final storage.test in private16MB ext4 namespace. Full commands/log: linux-checks.txt; ELF/link/provenance: amd64-build-evidence.txt/arm64-build-evidence.txt and *-elf-summary.json; fault log: full-filesystem.txt. binaries.sha256 describes Linux-copy binaries, Windows dist was not overwritten.

Ordinary suite SKIPs are explicit: TestTelemetryPhysicalFullFilesystem passed separately here; old E02 TestPhysicalFullFilesystem and E03 foreign-UID/root opt-in procedure were not re-run as separate root procedures for E05. Their prior evidence remains historical, not a new E05 PASS. Native ARM execution/race/QEMU and full VPS/systemd/GPU/security-source/Android runtime matrix were not run.

Additional evidence command after build: `wsl -d Ubuntu-22.04 -- bash /mnt/d/Projects/ServerDeck/agent/evidence/E05-wsl-2026-10-14/collect-artifacts.sh`; WSL inventory recorded with Python subprocess UTF16 decoding, confirming Ubuntu-22.04 WSL2 was selected explicitly although docker-desktop is default/stopped. Some starts print systemd user-session warnings; no system settings were changed and no systemd guarantee is inferred.

Coverage: real SQLite rollback/corruption/read-only/quota/checkpoint/SIGKILL; normal/SSH lost commit replies; rule hysteresis/source loss/repeats; active state after journal rotation; realTLS/WSS resume/problem removal/cursor gap; contract cache fixtures. No public service, VPS, host settings or native SSH/GPU adapter test. NativeARM/ordinaryLinuxhost/systemd release matrix E12, adaptersE06 and Android runtime remain their planned gates. Security review is scoped, not a CVE/full release certification.


| E05 criterion | Actual result / test |
|---|---|
| Weighted tiers, counter sums, partial/revision | PASS TestWeightedCoverageAndTiers, TestCounterExactSumRatesAndOverflow, TestCrossingCounterKeepsExactDeltaAndFullRateDenominator, TestMissingZeroAndPartialRevision, persistent tiers + fuzz |
| Native server-side recording without phone | PASS TestTelemetryPersistsSharedNativeCollectionWithoutPhones, real /proc collector and SQLite |
| Bounded DB/WAL, failure/recovery | PASS quota/read-only/corruption/schema, pinned-reader/deadline, real SIGKILL atomic prefix, physical ENOSPC |
| Quota changes and active protection | PASS TestTelemetryJournalShrinkAndGrowthAreConfirmedAgainstActualState, atomic rotation/restart, critical identity retained |
| History read/continuation/limits | PASS TestHistoryLargePageContinuationAndDurableRegistry:2010→2000+10, schema≤4MB, actor mismatch rejected |
| Rules/events/hysteresis/source loss/SSH | PASS threshold boundary/hold/recovery/repeat/restart/clock segment, typedSSH rotation/address/window fixtures; real native adapter reserved E06 |
| No duplicate after lost commit acknowledgment | PASS normal begin/recovery and SSH commit tests; frozen gap time/filter position checked |
| Audit-before-policy mutation and versions | PASS TestTelemetryMutationCannotBypassFailedAudit; rules/config intent test; delete/recreate/overflow/restore namespace test |
| WSS resume/gap/slow client | PASS TestTelemetryWSSResumeProblemRemovalAndGap, TestTelemetrySlowConsumerClosesWithoutDeletingState (1013 after~30s) |
| Android cache boundary | PASS positive partial→new revision and problem removal codec/docs fixtures; Kotlin runtime is E10 |
| Docs and identity | PASS штатный validator; build-inputs.json/source-copy.json/binaries.sha256; document/evidence hashes verified by verify.ps1 |

No product blocker remains before starting E06 by a separate user instruction. Native GPU/SSH/Docker adapters, modules, Android cache/runtime, full lifecycle backup/install/update, host/native ARM release matrix remain the already assigned stages. Live CVE scan and complete independent second-opinion security review are not claimed; scope and interrupted second review are recorded in SECURITY-REVIEW.md.


Final policy-result correction: TestRetentionReductionReportsObservablePendingCleanup and TestEmptyRetentionReductionNeedsNoCleanupOperation verify real old records, committed new policy, observable current cleanup operation, no blind retry and normal empty-journal success. If cleanup outcome remains unknown/partial, E02 reconciliation/admin resolve is required; no autonomous replay/success is claimed. The same config operation tracks policy+cleanup, so its ID is returned as cleanup_operation_id. This availability limit is explicit in HISTORY/config docs.


Final local verification commands: `python -X utf8 agent/evidence/E05-wsl-2026-10-14/seal.py` records document/evidence checksums; `pwsh -NoProfile -File agent/evidence/E05-wsl-2026-10-14/verify.ps1` verifies166 tested build inputs plus those checksums. Local test date is15 October Moscow (14 October UTC); directory names preserve the UTC run date. E05 is complete within the plan, with the documented conservative unknown/partial reconciliation path; E06 has not started.
