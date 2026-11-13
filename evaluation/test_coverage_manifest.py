import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import coverage_manifest
import evaluate


class CoverageTests(unittest.TestCase):
    def test_manifest_keeps_every_planned_cell_and_held_out_partition(self):
        data = coverage_manifest.manifest()
        self.assertEqual(data["planned_rows"], 24 * 3 * 10 * 3 * 2)
        self.assertEqual(data["status_counts"], {"not_run": data["planned_rows"]})
        self.assertEqual(set(data["training"]), set(evaluate.TRAIN))
        self.assertEqual(set(data["holdout"]), set(evaluate.HOLDOUT))
        self.assertFalse(set(data["training"]) & set(data["holdout"]))
        self.assertEqual(len(data["rows"]), data["planned_rows"])
        self.assertEqual(len(data["inputs_sha256"]["fixtures.c"]), 64)
        self.assertEqual(data["inputs_sha256"]["owned_scope.py"],
                         hashlib.sha256((evaluate.HERE / "owned_scope.py").read_bytes()).hexdigest())
        self.assertEqual(data["generator_sha256"],
                         hashlib.sha256(Path(coverage_manifest.__file__).read_bytes()).hexdigest())
        self.assertEqual(data["python_version"], sys.version.split()[0])
        self.assertTrue(data["git_head"] is None or len(data["git_head"]) == 40)

    def test_git_unavailable_is_explicit(self):
        with patch.object(coverage_manifest.subprocess, "run", side_effect=OSError("missing git")):
            self.assertIsNone(coverage_manifest.git_head())

    def test_cli_never_overwrites_an_existing_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "coverage.json"
            script = Path(coverage_manifest.__file__)
            args = [sys.executable, str(script), "--output", str(output)]
            subprocess.run(args, check=True, capture_output=True, text=True)
            first = output.read_bytes()
            self.assertEqual(json.loads(first)["planned_rows"], 4320)
            again = subprocess.run(args, capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)
            self.assertEqual(output.read_bytes(), first)


if __name__ == "__main__":
    unittest.main()
