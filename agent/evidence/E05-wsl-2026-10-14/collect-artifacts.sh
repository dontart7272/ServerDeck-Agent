#!/usr/bin/env bash
# Additional read-only artifact collection after wsl-e05.sh completes.
set -euo pipefail
base="$HOME/serverdeck-e05-complete-2026-10-14"
copy=$(cat "$base/copy-path.txt")
for arch in amd64 arm64; do
 cp "$copy/agent/dist/linux-$arch/build-evidence.txt" "$base/evidence/$arch-build-evidence.txt"
 cp "$copy/agent/dist/linux-$arch/elf-summary.json" "$base/evidence/$arch-elf-summary.json"
done
cp "$base/copy-path.txt" "$base/evidence/copy-path.txt"
sha256sum "$base/storage.test" > "$base/evidence/fault-test-binary.sha256"
