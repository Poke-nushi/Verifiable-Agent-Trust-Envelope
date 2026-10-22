"""Filesystem-boundary regressions for standard-library preparation."""

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import prepare_ci_stdlib as preparation


class PreparationTests(unittest.TestCase):
    def test_only_stdlib_sources_are_compiled_and_source_bytes_stay_unchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "stdlib"
            root.mkdir()
            sources = ["example.py", "package/__init__.py", "package/member.py",
                       "site-packages/third_party.py", "dist-packages/dependency.py",
                       "test/invalid.py", "package/tests/invalid.py"]
            for name in sources:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("invalid syntax !!!" if "invalid" in name else "VALUE = 1\n")
            outside = Path(directory) / "outside"
            outside.mkdir()
            (outside / "external.py").write_text("VALUE = 2\n")
            (root / "linked.py").symlink_to(outside / "external.py")
            (root / "linked-directory").symlink_to(outside, target_is_directory=True)
            # A dependency directory linked into the tree must also stay excluded.
            (root / "package/site-packages").symlink_to(outside, target_is_directory=True)
            before = {p: p.read_bytes() for p in root.rglob("*.py") if not p.is_symlink()}
            result = preparation.prepare(root)
            self.assertEqual(result["source_files"], 3)
            self.assertEqual(before, {p: p.read_bytes() for p in before})
            for name in sources[:3]:
                self.assertTrue(Path(importlib.util.cache_from_source(str(root / name))).is_file())
            for name in sources[3:]:
                self.assertFalse(Path(importlib.util.cache_from_source(str(root / name))).exists())
            self.assertEqual(list(outside.iterdir()), [outside / "external.py"])
            self.assertFalse(Path(importlib.util.cache_from_source(str(root / "linked.py"))).exists())
            self.assertEqual(preparation.prepare(root)["source_files"], 3)

    def test_symlinked_cache_is_rejected_before_any_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "stdlib"
            root.mkdir()
            (root / "example.py").write_text("VALUE = 1\n")
            outside = Path(directory) / "outside"
            outside.mkdir()
            (root / "__pycache__").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symlink"):
                preparation.prepare(root)
            self.assertEqual(list(outside.iterdir()), [])

    def test_alternate_prefix_is_rejected(self):
        with patch.object(sys, "pycache_prefix", "/unused-private-prefix"):
            with self.assertRaisesRegex(ValueError, "alternate"):
                preparation.prepare(Path("/unused"))

    def test_cli_refuses_a_local_interpreter(self):
        with patch.dict("os.environ", {}, clear=True):
            with self.assertRaisesRegex(SystemExit, "GitHub Actions"):
                preparation.main()


if __name__ == "__main__":
    unittest.main()
