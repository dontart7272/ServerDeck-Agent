#!/usr/bin/env python3
"""Capture exact Ubuntu builder packages, sources and toolchain file hashes.
SPDX-License-Identifier: Apache-2.0
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

destination = Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
if (destination/'linux-toolchain.lock.json').exists():
    raise SystemExit('Lock already exists; preserve it and capture a new environment into a separate directory')
def command(*args):
    return subprocess.check_output(args, text=True)

installed = command('dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Architecture}\n')
(destination/'ubuntu-packages.tsv').write_text(installed)
packages = {}
for line in installed.splitlines():
    name, version, arch = line.split('\t')
    packages[name] = {'version': version, 'architecture': arch}
selected = ['gcc-11', 'cpp-11', 'gcc-11-base', 'gcc-11-aarch64-linux-gnu',
 'cpp-11-aarch64-linux-gnu', 'gcc-11-aarch64-linux-gnu-base', 'gcc-11-cross-base',
 'gcc-12-cross-base', 'binutils', 'binutils-common', 'binutils-x86-64-linux-gnu',
 'binutils-aarch64-linux-gnu', 'libgcc-11-dev:amd64', 'libgcc-11-dev-arm64-cross',
 'libgcc-s1:amd64', 'libgcc-s1-arm64-cross', 'libc6:amd64', 'libc6-dev:amd64',
 'libc-dev-bin', 'libc6-arm64-cross', 'libc6-dev-arm64-cross', 'linux-libc-dev',
 'linux-libc-dev-arm64-cross', 'libisl23:amd64', 'libmpc3:amd64', 'libmpfr6:amd64',
 'libgmp10:amd64', 'qemu-user', 'ubuntu-keyring', 'ca-certificates', 'curl']
metadata = []
paths = set()
selected = [name if name in packages else name+':amd64' for name in selected]
for name in selected:
    version = packages[name]['version']
    metadata.append(command('apt-cache', 'show', name+'='+version))
    paths.update(command('dpkg-query', '-L', name).splitlines())
(destination/'ubuntu-package-metadata.txt').write_text('\n'.join(metadata))
files = []
for name in sorted(paths):
    p = Path(name)
    if not p.is_file(): continue
    files.append({'path': name, 'sha256': hashlib.sha256(p.read_bytes()).hexdigest(),
                  'link': os.readlink(p) if p.is_symlink() else None})
manifest = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
(destination/'toolchain-files.json').write_text(json.dumps(files, indent=2)+'\n')
lock = {'os': 'Ubuntu 22.04.5 WSL2', 'kernel': command('uname','-r').strip(),
        'architecture': command('uname','-m').strip(),
        'packages': {name: packages[name] for name in selected},
        'toolchain_manifest_sha256': hashlib.sha256(manifest).hexdigest(),
        'file_count': len(files), 'image_digest': None,
        'note': 'Package and content lock of the actual WSL builder; no container image is used.'}
(destination/'linux-toolchain.lock.json').write_text(json.dumps(lock, indent=2)+'\n')
for p in sorted(Path('/var/lib/apt/lists').glob('*InRelease')):
    (destination/p.name).write_bytes(p.read_bytes())
print('Captured', len(selected), 'pinned packages and',len(files),'toolchain/sysroot files')
