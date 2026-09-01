from __future__ import annotations

import unittest
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.scan_public_tree import scan


class PublicTreeTests(unittest.TestCase):
    def test_public_tree_is_allowlisted_and_clean(self) -> None:
        self.assertEqual(scan(), [])


if __name__ == "__main__":
    unittest.main()
