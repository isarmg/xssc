#!/usr/bin/env python3
"""Generate the actual selected Rust runtime graph and final release inventory."""
import argparse
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT=Path(__file__).resolve().parents[1]


def run(arguments):
    return subprocess.check_output(arguments,cwd=ROOT,stdin=subprocess.DEVNULL,timeout=1800).decode().strip()


def generate(stage,tools,revision,target):
    stage=Path(stage).resolve(strict=True);tools=Path(tools).resolve(strict=True)
    pin=json.loads((ROOT/'build-tools-source.json').read_text())
    if pin.get('repository')!='https://github.com/isarmg/xssi.git' or not isinstance(pin.get('revision'),str) or not re.fullmatch('[0-9a-f]{40}',pin['revision']):
        raise ValueError('release inventory requires the immutable reviewed tool revision')
    if run(['git','-C',str(tools),'rev-parse','HEAD'])!=pin['revision'] or run(['git','-C',str(tools),'status','--porcelain','--untracked-files=all']):
        raise ValueError('release inventory tools differ from the pinned clean source')
    if run(['git','rev-parse','HEAD'])!=revision or run(['git','status','--porcelain','--untracked-files=all']):
        raise ValueError('release inventory source differs from the clean compiled source')
    sys.path.insert(0,str(tools/'scripts'))
    import sbom,sqlite_receipt,release_sbom
    environment={key:value for key,value in os.environ.items()
        if not any(part in key.upper() for part in ('TOKEN','PASSWORD','SECRET','SIGNING','PRIVATE_KEY'))}
    with tempfile.TemporaryDirectory(prefix='xssc-runtime-inventory-') as temporary:
        private=Path(temporary);source=private/'source';source.mkdir(mode=0o700)
        archive=private/'source.tar'
        run(['git','archive','--format=tar','--output',str(archive),revision])
        with tarfile.open(archive) as package:
            for item in package:
                path=PurePosixPath(item.name)
                if path.is_absolute() or '..' in path.parts or not(item.isfile()or item.isdir()):
                    raise ValueError('release source export contains an uncontrolled path')
                package.extract(item,source,filter='data')
        archive.unlink()
        (stage/'share').mkdir(exist_ok=True)
        graph=sbom.produce_runtime_cargo_bom(source,source/'Cargo.toml','xssc',stage,'xssc',
            [(source,revision)],target=target,environment=environment)
        external=stage/'share/external-components.json'
        external.write_text(json.dumps({'format_version':1,'runtime_roots':[],'components':[]})+'\n');external.chmod(0o644)
        native=sqlite_receipt.record(source,stage,'xssc','bin/xssc')
        sqlite_receipt.merge(stage,[native],[(graph,'bin/xssc')])
        import tomllib
        version=tomllib.loads((source/'Cargo.toml').read_text())['package']['version']
        release_sbom.finalize(stage,[graph],external,'xssc',version,revision,target)
    if run(['git','rev-parse','HEAD'])!=revision or run(['git','status','--porcelain','--untracked-files=all']):
        raise ValueError('release source changed during inventory generation')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',type=Path,required=True)
    parser.add_argument('--tools',type=Path,required=True)
    parser.add_argument('--source-revision',required=True)
    parser.add_argument('--target',required=True)
    args=parser.parse_args();generate(args.stage,args.tools,args.source_revision,args.target)


if __name__=='__main__':main()
