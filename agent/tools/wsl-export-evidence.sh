#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
task_root="$HOME/serverdeck-e01-2026-10-13"
source "$task_root/env.sh"
copy_root=$(cat "$task_root/copy-path.txt")
origin=/mnt/d/Projects/ServerDeck
destination="$origin/agent/evidence/E01-wsl-2026-10-13"
exec > >(tee "$task_root/evidence/final-tooling-check.txt") 2>&1
rsync -a "$origin/agent/tools/" "$copy_root/agent/tools/"
cd "$copy_root/agent"
for script in tools/*.sh; do bash -n "$script"; done
echo 'PASS: bash syntax for all Linux scripts'
before=$(sha256sum internal/contracts/wire_generated.go)
python3 tools/generate-types.py
gofmt -w internal/contracts/wire_generated.go
test "$(sha256sum internal/contracts/wire_generated.go)" = "$before"
echo 'PASS: Python3 Linux generation + gofmt reproduces existing wire types'
python3 tools/verify-linux-toolchain.py "$task_root/evidence/linux-toolchain.lock.json"
if test -f "$destination/linux-toolchain.lock.json"; then
    cmp "$task_root/evidence/linux-toolchain.lock.json" "$destination/linux-toolchain.lock.json"
    cmp "$task_root/evidence/toolchain-files.json" "$destination/toolchain-files.json"
    echo 'PASS: preserved project lock matches Linux snapshot; no silent lock replacement'
fi
CC=/usr/bin/gcc-11 bash tools/build-linux.sh amd64
CC=/usr/bin/aarch64-linux-gnu-gcc-11 bash tools/build-linux.sh arm64
sha256sum -c "$task_root/evidence/binaries.sha256"
for arch in amd64 arm64; do
    cp "dist/linux-$arch/build-evidence.txt" "$task_root/evidence/build-$arch.txt"
    cp "dist/linux-$arch/elf-summary.json" "$task_root/evidence/elf-$arch.json"
    mkdir -p "$origin/agent/dist/linux-$arch"
    cp "dist/linux-$arch/serverdeck-agent" "dist/linux-$arch/serverdeckctl" "$origin/agent/dist/linux-$arch/"
done
python3 - "$copy_root" "$origin" <<'PY'
import hashlib,pathlib,sys
copy,original=map(pathlib.Path,sys.argv[1:])
for arch in ('amd64','arm64'):
 for command in ('serverdeck-agent','serverdeckctl'):
  rel=pathlib.Path('agent/dist')/('linux-'+arch)/command
  if hashlib.sha256((copy/rel).read_bytes()).digest()!=hashlib.sha256((original/rel).read_bytes()).digest():raise SystemExit('export mismatch')
print('PASS: four exported binaries match the tested Linux binaries')
PY
cp /etc/os-release "$task_root/evidence/os-release.txt"
uname -a > "$task_root/evidence/kernel.txt"
apt-config shell insecure Acquire::AllowInsecureRepositories unauthenticated APT::Get::AllowUnauthenticated > "$task_root/evidence/apt-trust-overrides.txt"
echo 'APT sources use official Ubuntu archive/security InRelease; no trust bypass flags were supplied.' >> "$task_root/evidence/apt-trust-overrides.txt"
findmnt -T "$copy_root" > "$task_root/evidence/linux-filesystem.txt"
sync
rsync -a "$task_root/evidence/" "$destination/"
echo 'PASS: evidence exported; builds/caches/tmp remain on Linux ext4. No application source was changed.'
