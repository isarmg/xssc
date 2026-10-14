#!/usr/bin/env python3
"""Exercise release identity and complete final SHA-256 delivery checks."""

import hashlib
import importlib.util
import json
import os
import subprocess
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REVISION = "a" * 40
VERSION = "1.2.3"
TOOLS = ROOT.parent / "xssi"
sys.path.insert(0,str(TOOLS/"scripts"))
import release_sbom


spec = importlib.util.spec_from_file_location("stage_release_docs", ROOT / "scripts/stage-release-docs.py")
documents = importlib.util.module_from_spec(spec)
spec.loader.exec_module(documents)


class FinalizeReleaseTests(unittest.TestCase):
    def run_finalize(self, changed_file=None, changed_field=None, changed_support=None, changed_provenance=None, overflow_descendant=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            (package / "bin").mkdir(parents=True)
            documents.stage(ROOT, package, VERSION)
            binary = package / "bin" / "xssc"
            catalog = package / "adapter-catalog.json"
            support = {"tool_version": VERSION, "source_revision": REVISION, "compiled_target": "x86_64-unknown-linux-gnu", "formal_release_target": "x86_64-unknown-linux-gnu"}
            if changed_support is not None: support[changed_support] = "wrong"
            # An explicit reporting stand-in tests publisher checks; the real
            # staged ELF and source binding are verified separately.
            report = "#!/usr/bin/python3\nimport sys\n"
            descendant_pid = root / 'descendant.pid'
            if overflow_descendant:
                descendant = "from pathlib import Path; import os,time; Path(" + repr(str(descendant_pid)) + ").write_text(str(os.getpid())); time.sleep(30)"
                report += "import subprocess,time\nsubprocess.Popen(['/usr/bin/python3','-c'," + repr(descendant) + "],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
                report += "from pathlib import Path\nwhile not Path(" + repr(str(descendant_pid)) + ").exists(): time.sleep(.01)\n"
                report += "sys.stdout.write('x'*65537)\nsys.stdout.flush()\nsys.exit(0)\n"
            report += "print(" + repr(json.dumps(support)) + " if sys.argv[1]=='support' else 'xssc " + VERSION + "')\n"
            binary.write_text(report)
            binary.chmod(0o755)
            catalog.write_text(json.dumps(support)+"\n")
            metadata = {
                "product": "xssc",
                "target": "x86_64-unknown-linux-gnu",
                "version": VERSION,
                "source_revision": REVISION,
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "catalog_sha256": hashlib.sha256(catalog.read_bytes()).hexdigest(),
            }
            if changed_field is not None:
                metadata[changed_field] = "wrong"
            (package / "release.json").write_text(json.dumps(metadata))
            provenance = {"source_revision": REVISION, "subject_sha256": metadata["binary_sha256"], "target": metadata["target"]}
            if changed_provenance is not None: provenance[changed_provenance] = "wrong"
            (package / "provenance.json").write_text(json.dumps(provenance))
            # Publisher tests use a declared reporting stand-in. Separate
            # real-ELF and runtime graph tests verify the inventory producer.
            (package/'share').mkdir()
            bom=root/'runtime.json';bom.write_text(json.dumps({'bomFormat':'CycloneDX','specVersion':'1.5','version':1,
                'metadata':{'component':{'type':'application','name':'xssc','version':VERSION,'bom-ref':'fixture-runtime'}},
                'components':[],'dependencies':[{'ref':'fixture-runtime','dependsOn':[]}]}))
            receipt=root/'bindings.json';receipt.write_text(json.dumps({'format_version':1,'runtime_roots':[
                {'ref':'fixture-runtime','files':[{'path':'bin/xssc','sha256':release_sbom.digest(binary),'archive_entry':None}]}],
                'components':[]}))
            release_sbom.finalize(package,[bom],receipt,'xssc',VERSION,REVISION,'x86_64-unknown-linux-gnu')
            scripts=root/'release-tools';scripts.mkdir()
            shutil.copyfile(ROOT/'scripts/finalize-release.sh',scripts/'finalize-release.sh')
            shutil.copyfile(ROOT/'scripts/stage-release-docs.py',scripts/'stage-release-docs.py')
            for filename in ('release_manifest.py','release_sbom.py'):
                shutil.copyfile(TOOLS/'scripts'/filename,scripts/filename)
            if changed_file == "document":
                (package / "docs/platform-setup.md").unlink()
            elif changed_file == "binary":
                binary.write_bytes(b"changed binary")
            elif changed_file == "catalog":
                catalog.write_bytes(b"changed catalog")
            result = subprocess.run(
                [
                    "bash",
                    str(scripts / "finalize-release.sh"),
                    str(package),
                    str(root / "output"),
                    REVISION,
                    VERSION,
                ],
                capture_output=True,
                text=True,
                check=False,
                timeout=45,
            )
            result.descendant_pid = int(descendant_pid.read_text()) if descendant_pid.exists() else None
            return result

    def test_missing_deployment_document_is_rejected_before_packaging(self):
        result = self.run_finalize(changed_file="document")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release documentation validation failed", result.stderr)

    @unittest.skipUnless(shutil.which('zstd'), 'actual release archive verification requires zstd')
    def test_actual_archive_and_final_checksum_verification_pass(self):
        result=self.run_finalize()
        self.assertEqual(result.returncode,0,result.stderr)

    def test_rejects_tampered_release_identity_before_packaging(self):
        for changed_file, changed_field, expected in (
            ("binary", None, "binary_sha256 does not match"),
            ("catalog", None, "catalog_sha256 does not match"),
            (None, "source_revision", "source revision does not match"),
            (None, "version", "version does not match"),
        ):
            with self.subTest(changed_file=changed_file, changed_field=changed_field):
                result = self.run_finalize(changed_file, changed_field)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(expected, result.stderr)

    def test_rejects_unbound_or_wrong_compiled_source_target_and_provenance_before_packaging(self):
        for field in ("source_revision", "compiled_target"):
            result = self.run_finalize(changed_support=field)
            self.assertIn(f"compiled binary {field} does not match", result.stderr)
        for field in ("source_revision", "target", "subject_sha256"):
            result = self.run_finalize(changed_provenance=field)
            self.assertIn(f"provenance {field} does not match", result.stderr)

    @unittest.skipUnless(os.name == 'posix' and Path('/proc').is_dir(), 'actual process-group proof requires Linux')
    def test_overflowing_report_terminates_its_descendant(self):
        result = self.run_finalize(overflow_descendant=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('binary identity report exceeded its limit', result.stderr)
        self.assertIsNotNone(result.descendant_pid)
        process = Path('/proc') / str(result.descendant_pid) / 'stat'
        if process.exists():
            self.assertEqual(process.read_text().rsplit(')', 1)[1].split()[0], 'Z')


if __name__ == "__main__":
    unittest.main()
