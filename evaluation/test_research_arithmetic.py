import ctypes
import ctypes.util
import json
import os
import sys
import random
import shutil
import tempfile
import subprocess
import unittest
from unittest.mock import patch
from pathlib import Path

import research_arithmetic as r


class ArithmeticTests(unittest.TestCase):
    def test_differential_overflow_and_alias(self):
        rng = random.Random(8128)
        vectors = [0, 1, 2, (1 << 63) - 1, 1 << 63, r.MASK]
        vectors.extend(rng.getrandbits(64) for _ in range(256))
        for seed in range(20):
            expr = r.candidate(seed, flags_dead=True, dst=0, src=1, scratch=(256, 257, 258))
            for a, b in zip(vectors, reversed(vectors)):
                self.assertEqual(r.evaluate(expr, a, b), (a + b) & r.MASK)
                self.assertEqual(r.evaluate(expr, a, a), (a + a) & r.MASK)

    def test_preconditions_deny_live_flags_and_scratch(self):
        self.assertIsNone(r.candidate(0, flags_dead=False, dst=0, src=1))
        self.assertIsNone(r.candidate(0, flags_dead=True, dst=256, src=1, scratch=(256,)))
        self.assertIsNone(r.candidate(0, flags_dead=True, dst=0, src=256, scratch=(256,)))
        self.assertIsNotNone(r.candidate(0, flags_dead=True, dst=0, src=0))

    def test_solver_receipt_requires_exact_structured_statuses(self):
        expr = r.candidate(1, flags_dead=True, dst=0, src=1)
        good = {"solver": "Z3 test", "answers": ["unsat", "unsat", "sat"]}
        with patch.object(r.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(good), "")):
            result = r.verify(expr)
        self.assertTrue(result["admitted"])
        self.assertEqual(result["general_equivalence"], "unsat")
        self.assertEqual(result["alias_equivalence"], "unsat")
        self.assertEqual(result["negative_control"], "sat")
        for output in (json.dumps(dict(good, answers=["unsat", "unknown", "sat"])),
                       json.dumps(good) + " garbage", json.dumps(dict(good, extra=1))):
            with self.subTest(output=output), patch.object(r.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, output, "")):
                self.assertFalse(r.verify(expr)["admitted"])

    def test_missing_clang_saves_inconclusive_report(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "result"
            with patch.object(sys, "argv", ["research_arithmetic.py", "--output", str(out)]), \
                 patch.object(r, "admitted", return_value=(None, {"admitted": False, "reason": "solver unavailable"})), \
                 patch.object(r.subprocess, "run", side_effect=FileNotFoundError("clang-18")):
                status = r.main()
            report = json.loads((out / "result.json").read_text())
            self.assertNotEqual(status, 0)
            self.assertEqual(report["normalization_status"], "unavailable")
            self.assertEqual(report["decision"], "INCONCLUSIVE")
            self.assertEqual({row["seed_group"] for row in report["rows"]}, {"group_a", "group_b"})
            self.assertTrue((out / "composed.c").exists())

    def test_solver_failure_timeout_and_unknown_are_rejected(self):
        kwargs = dict(flags_dead=True, dst=0, src=1)
        for response in (subprocess.CompletedProcess([], 1, '', 'error'),
                         subprocess.CompletedProcess([], 0, 'unknown\n', '')):
            with patch.object(r.subprocess, 'run', return_value=response):
                expr, result = r.admitted(0, **kwargs)
                self.assertIsNone(expr)
                self.assertFalse(result['admitted'])
        with patch.object(r.subprocess, 'run', side_effect=subprocess.TimeoutExpired('z3', 1)):
            expr, result = r.admitted(0, **kwargs)
            self.assertIsNone(expr)
            self.assertEqual(result['reason'], 'TimeoutExpired')

    @unittest.skipUnless(shutil.which("clang-18"), "clang-18 unavailable")
    def test_compiled_c_against_independent_wrapping_oracle(self):
        source = ['#include <stdint.h>']
        for seed in range(20):
            expr = r.candidate(seed, flags_dead=True, dst=0, src=1)
            source.append(f'uint64_t f{seed}(uint64_t a, uint64_t b) {{ return {r.emit(expr, "c")}; }}')
        with tempfile.TemporaryDirectory() as temp:
            source_path = Path(temp) / 'candidate.c'
            library_path = Path(temp) / 'candidate.so'
            source_path.write_text('\n'.join(source) + '\n')
            subprocess.run(['clang-18', '-O1', '-shared', '-fPIC', str(source_path), '-o', str(library_path)], check=True)
            library = ctypes.CDLL(str(library_path))
            rng = random.Random(441)
            values = [0, 1, r.MASK, 1 << 63, (1 << 63) - 1]
            values.extend(rng.getrandbits(64) for _ in range(100))
            for seed in range(20):
                function = getattr(library, f'f{seed}')
                function.argtypes = [ctypes.c_uint64, ctypes.c_uint64]
                function.restype = ctypes.c_uint64
                for a, b in zip(values, reversed(values)):
                    self.assertEqual(function(a, b), (a + b) & r.MASK)
                    self.assertEqual(function(a, a), (a + a) & r.MASK)

    @unittest.skipUnless(ctypes.util.find_library("z3"), "libz3 unavailable")
    def test_real_solver_and_negative_control(self):
        expr = r.candidate(1, flags_dead=True, dst=0, src=1)
        result = r.verify(expr)
        self.assertTrue(result['admitted'], result)
        bad = ('add', expr, ('const', 1))
        self.assertFalse(r.verify(bad)['admitted'])


if __name__ == '__main__':
    unittest.main()
