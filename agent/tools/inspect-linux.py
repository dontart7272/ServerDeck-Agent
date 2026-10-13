#!/usr/bin/env python3
"""Inspect produced ELF without executing cross-target binaries.
SPDX-License-Identifier: Apache-2.0
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

arch = sys.argv[1]
expected_machine = {'amd64': 'Advanced Micro Devices X86-64', 'arm64': 'AArch64'}[arch]
expected_interpreter = {'amd64':'/lib64/ld-linux-x86-64.so.2','arm64':'/lib/ld-linux-aarch64.so.1'}[arch]
environment = dict(os.environ, LC_ALL='C')
records = []
for name in ('serverdeck-agent', 'serverdeckctl'):
    p = Path('dist') / ('linux-'+arch) / name
    elf = subprocess.check_output(['readelf','-h','-l','-d','-V',str(p)],text=True,env=environment)
    if not re.search(r'Machine:\s+'+re.escape(expected_machine)+r'\s*\n',elf):
        raise SystemExit('ELF machine mismatch')
    if not re.search(r'Class:\s+ELF64',elf):
        raise SystemExit('ELF class mismatch')
    match = re.search(r'Requesting program interpreter: ([^]]+)',elf)
    if not match or match.group(1) != expected_interpreter:
        raise SystemExit('ELF interpreter mismatch')
    versions = sorted({tuple(map(int,v.split('.'))) for v in re.findall(r'GLIBC_([0-9.]+)',elf)})
    if not versions or max(versions) > (2,35):
        raise SystemExit('Missing/excessive GLIBC requirement')
    needed = re.findall(r'\(NEEDED\).*\[([^]]+)\]',elf)
    if 'libc.so.6' not in needed or any('sqlite' in x.lower() or 'nvidia' in x.lower() for x in needed):
        raise SystemExit('Unexpected native dependency set')
    go = subprocess.check_output(['go','version','-m',str(p)],text=True,env=environment)
    if 'CGO_ENABLED=1' not in go or 'GOARCH='+arch not in go or 'GOOS=linux' not in go:
        raise SystemExit('Go build settings mismatch')
    records.append({'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest(),
       'machine':expected_machine,'class':'ELF64','interpreter':match.group(1),'needed':needed,'max_glibc':'.'.join(map(str,max(versions))),
       'cgo':True,'execution':'not performed by ELF inspector'})
print(json.dumps(records,indent=2))
