import ctypes
import json
import sys
from unittest.mock import patch
import random
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import research_data_encoding as r


class DataEncodingTests(unittest.TestCase):
    def test_declared_boundary_rejects_unsupported_region(self):
        base = dict(operations=("add", "multiply_runtime"), flags_dead=True,
                    scratch=(10, 11), operands=(1, 2))
        self.assertTrue(r.supported_region(**base))
        for key, value in (("flags_dead", False), ("operations", ("add", "call")),
                           ("operations", ("add", "multiply_const")),
                           ("has_memory", True), ("has_calls", True),
                           ("has_branches", True), ("has_pointers", True),
                           ("floating_point", True), ("scratch", (10, 10)),
                           ("scratch", (1, 11))):
            args = dict(base, **{key: value})
            self.assertFalse(r.supported_region(**args), key)
        self.assertTrue(r.supported_region(**dict(base, operands=(1, 1))))

    def test_bad_clang_outputs_save_inconclusive_receipt(self):
        for scenario in ("missing_ll", "malformed_ll", "empty_version", "failed_version"):
            with self.subTest(scenario=scenario), tempfile.TemporaryDirectory() as tmp:
                out = Path(tmp) / "out"
                def run(argv, **kwargs):
                    if "--version" in argv:
                        return subprocess.CompletedProcess(argv, 1 if scenario == "failed_version" else 0,
                                                           "" if scenario == "empty_version" else "clang test\n", "bad version")
                    if scenario == "malformed_ll":
                        Path(argv[-1]).write_text("define invalid\n")
                    elif scenario != "missing_ll":
                        Path(argv[-1]).write_text("define i64 @plain() {\n ret i64 0\n}\n")
                    return subprocess.CompletedProcess(argv, 0, "", "")
                with patch.object(sys, "argv", ["driver", "--output", str(out)]), \
                     patch.object(r.subprocess, "run", side_effect=run):
                    status = r.main()
                receipt = json.loads((out / "result.json").read_text())
                self.assertNotEqual(status, 0)
                self.assertEqual(receipt["normalization_status"], "error")
                self.assertEqual(receipt["decision"], "INCONCLUSIVE")

    @unittest.skipUnless(shutil.which("clang-18"), "clang-18 unavailable")
    def test_compiled_fixture_matches_independent_arithmetic(self):
        with tempfile.TemporaryDirectory() as tmp:
            libpath = Path(tmp) / "fixture.so"
            subprocess.run(["clang-18", "-O0", "-shared", "-fPIC", str(r.SOURCE), "-o", str(libpath)], check=True)
            library = ctypes.CDLL(str(libpath))
            functions = [getattr(library, name) for name in ("plain", "immediate_pair", "encoded_region")]
            for function in functions:
                function.argtypes = [ctypes.c_uint64] * 4
                function.restype = ctypes.c_uint64
            edge = [0, 1, 2, (1 << 63), (1 << 64) - 1]
            cases = [(x, b, a, k) for x in edge for b in edge for a in edge for k in edge]
            rng = random.Random(0x4844)
            cases.extend(tuple(rng.getrandbits(64) for _ in range(4)) for _ in range(1000))
            for x, b, a, k in cases:
                expected = ((x + b) * a) & ((1 << 64) - 1)
                for function in functions:
                    self.assertEqual(function(x, b, a, k), expected)
            # An omitted final decode must be detected by the oracle.
            x, b, a, k = 1, 2, 3, 5
            broken = (((x + k + b) * a + (1 - a) * k) & ((1 << 64) - 1))
            self.assertNotEqual(broken, ((x + b) * a) & ((1 << 64) - 1))

    @unittest.skipUnless(shutil.which("clang-18"), "clang-18 unavailable")
    def test_normalization_report_matches_llvm_bodies(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "out"
            result = subprocess.run(["python3", str(Path(r.__file__)), "--output", str(out)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((out / "normalized.ll").exists())
            self.assertEqual(set(r.normalized_bodies(out / "normalized.ll")),
                             {"plain", "immediate_pair", "encoded_region"})


if __name__ == "__main__":
    unittest.main()
