#!/usr/bin/env python3
"""Run compiled test harnesses with fixture-only administrator permissions."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess

parser=argparse.ArgumentParser()
parser.add_argument('build_messages',type=Path)
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
executables=set()
with args.build_messages.open() as stream:
    for line in stream:
        if len(line)>1024*1024:raise ValueError('compiler message exceeds bound')
        message=json.loads(line)
        if message.get('reason')!='compiler-artifact' or message.get('profile',{}).get('test') is not True:continue
        if message.get('executable') is None:continue
        executable=Path(message['executable']).absolute()
        if not executable.is_relative_to(root/'target') or executable.is_symlink():raise ValueError('test executable is outside the build target')
        info=executable.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode&0o022 or not info.st_mode&0o111:raise ValueError('test executable is not a controlled regular binary')
        executables.add(executable)
if not executables:raise ValueError('Cargo produced no test harnesses')
for executable in sorted(executables):
    command=['/usr/bin/env','-i','PATH=/usr/bin:/bin','LANG=C.UTF-8','TMPDIR=/tmp',str(executable)]
    if os.geteuid()!=0:command=['/usr/bin/sudo','--']+command
    subprocess.run(command,cwd=root,check=True,timeout=600)
