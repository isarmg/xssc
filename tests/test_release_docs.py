#!/usr/bin/env python3
"""Exercise the actual release document staging and archived reader paths."""

import importlib.util
from pathlib import Path
import tarfile
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parents[1]
CURRENT_VERSION = tomllib.loads((ROOT / 'Cargo.toml').read_text())['package']['version']
spec = importlib.util.spec_from_file_location("stage_release_docs", ROOT / "scripts/stage-release-docs.py")
documents = importlib.util.module_from_spec(spec)
spec.loader.exec_module(documents)


class ReleaseDocumentsTests(unittest.TestCase):
    def fixture(self, root):
        source = root / "source"
        package = root / "package"
        (source / "docs/guide/assets").mkdir(parents=True)
        package.mkdir()
        (source / "docs/operations.md").write_text(
            "# Operations\n[contract](offline-upgrades.md#准备)\n"
            "[nested][guide]\n\n[guide]: guide/next.md#write-mode\n"
        )
        (source / "docs/offline-upgrades.md").write_text(
            "# Contract\n## 准备\n[deployment](platform-setup.md)\n"
        )
        (source / "docs/platform-setup.md").write_text(
            "# Deployment\n[cycle](operations.md)\n"
            "```md\n[example only](missing-example.md)\n```\n"
            "`[inline example](another-missing.md)`\n"
        )
        (source / "docs/guide/next.md").write_text(
            "# Next\n## `write mode`\n![diagram](assets/diagram.txt)\n"
            "[back](../operations.md)\n"
        )
        (source / "docs/guide/assets/diagram.txt").write_text("offline diagram\n")
        return source, package

    def test_current_real_package_contains_deployment_and_preserves_reader_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            package = Path(temporary) / "package"
            package.mkdir()
            files = documents.stage(ROOT, package, CURRENT_VERSION)
            required = set(documents.DOCUMENTS) | {
                "README.md", "OFFLINE-UPGRADES.md", "docs/platform-setup.md",
                "docs/development-contract.md", "docs/common-support.md",
            }
            self.assertLessEqual(required, set(files))
            for name in set(files) - {"README.md", "OFFLINE-UPGRADES.md"}:
                self.assertEqual((package / name).read_bytes(), (ROOT / name).read_bytes())
            self.assertIn("xssc --version", (package / "docs/platform-setup.md").read_text())
            self.assertIn("docs/operations.md", (package / "README.md").read_text())
            self.assertIn("docs/offline-upgrades.md", (package / "OFFLINE-UPGRADES.md").read_text())
            documents.verify(package, CURRENT_VERSION)
            archive = Path(temporary) / "release.tar"
            with tarfile.open(archive, "w") as output:
                for name in sorted(files):
                    output.add(package / name, arcname=name, recursive=False)
            extracted = Path(temporary) / "extracted"
            extracted.mkdir()
            with tarfile.open(archive) as packaged:
                packaged.extractall(extracted, filter="data")
            self.assertEqual(documents.verify(extracted, CURRENT_VERSION), files)
            (extracted / "docs/platform-setup.md").unlink()
            with self.assertRaises(ValueError):
                documents.verify(extracted, CURRENT_VERSION)

    def test_nested_documents_references_assets_anchors_and_cycles_are_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, package = self.fixture(Path(temporary))
            files = documents.stage(source, package, "1.2.3")
            self.assertIn("docs/guide/next.md", files)
            self.assertIn("docs/guide/assets/diagram.txt", files)
            self.assertNotIn("docs/missing-example.md", files)
            self.assertNotIn("docs/another-missing.md", files)
            self.assertEqual((package / "docs/guide/assets/diagram.txt").read_text(), "offline diagram\n")
            documents.verify(package, "1.2.3")

    def test_missing_reference_or_anchor_refuses_staging_before_any_document_write(self):
        for missing in ["file", "anchor"]:
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as temporary:
                source, package = self.fixture(Path(temporary))
                nested = source / "docs/guide/next.md"
                if missing == "file":
                    nested.unlink()
                else:
                    nested.write_text("# Different heading\n")
                with self.assertRaises(ValueError):
                    documents.stage(source, package, "1.2.3")
                self.assertEqual(list(package.iterdir()), [])

    def test_escaping_or_linked_inputs_never_enter_the_release_tree(self):
        for unsafe in ["escape", "link"]:
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, package = self.fixture(root)
                outside = root / "outside.md"
                outside.write_text("outside input\n")
                if unsafe == "escape":
                    (source / "docs/operations.md").write_text("[outside](../../outside.md)\n")
                else:
                    nested = source / "docs/guide/next.md"
                    nested.unlink()
                    nested.symlink_to(outside)
                with self.assertRaises(ValueError):
                    documents.stage(source, package, "1.2.3")
                self.assertEqual(list(package.iterdir()), [])

    def test_actual_package_missing_nested_document_or_wrong_version_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, package = self.fixture(Path(temporary))
            documents.stage(source, package, "1.2.3")
            with self.assertRaises(ValueError):
                documents.verify(package, "1.2.4")
            (package / "docs/guide/next.md").unlink()
            with self.assertRaises(ValueError):
                documents.verify(package, "1.2.3")

    def test_existing_document_destination_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, package = self.fixture(Path(temporary))
            existing = package / "README.md"
            existing.write_text("preserve previous input\n")
            with self.assertRaises(ValueError):
                documents.stage(source, package, "1.2.3")
            self.assertEqual(existing.read_text(), "preserve previous input\n")
            self.assertFalse((package / "docs").exists())


if __name__ == "__main__":
    unittest.main()
