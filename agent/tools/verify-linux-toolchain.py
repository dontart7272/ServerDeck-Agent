#!/usr/bin/env python3
"""Verify the recorded Ubuntu WSL builder without changing system packages.
SPDX-License-Identifier: Apache-2.0
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

lock_path = Path(sys.argv[1])
lock = json.loads(lock_path.read_text())
for name, expected in lock['packages'].items():
    actual = subprocess.check_output(['dpkg-query','-W','-f=${Version}\t${Architecture}',name],text=True)
    if actual != expected['version']+'\t'+expected['architecture']:
        raise SystemExit('Toolchain package drift: '+name)
manifest = json.loads((lock_path.parent/'toolchain-files.json').read_text())
digest = hashlib.sha256(json.dumps(manifest,sort_keys=True,separators=(',',':')).encode()).hexdigest()
if digest != lock['toolchain_manifest_sha256']:
    raise SystemExit('Toolchain manifest mismatch')
for item in manifest:
    if hashlib.sha256(Path(item['path']).read_bytes()).hexdigest() != item['sha256']:
        raise SystemExit('Toolchain file drift: '+item['path'])
print('PASS: exact package revisions and',len(manifest),'native/cross toolchain files match lock')
