from __future__ import annotations

import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.scan_public_tree import ROOT, public_files, scan


class PublicTreeTests(unittest.TestCase):
    def test_public_tree_is_allowlisted_and_clean(self) -> None:
        self.assertEqual(scan(), [])

    def test_scanner_output_excludes_git_metadata(self) -> None:
        relative_files = [path.relative_to(ROOT) for path in public_files()]
        self.assertTrue(relative_files)
        self.assertFalse(any(".git" in relative.parts for relative in relative_files))


if __name__ == "__main__":
    unittest.main()
