import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import owned_scope


class ScopeTests(unittest.TestCase):
    def run_case(self, code, *, limits=None):
        result = owned_scope.run(["/usr/bin/python3", "-c", code], budget=60, _limits=limits)
        if result["status"] == "unsupported":
            self.skipTest(result["reason"])
        return result

    def test_configured_budgets_and_output_cap(self):
        for budget in owned_scope.BUDGETS:
            with self.subTest(budget=budget):
                result = owned_scope.run(["/usr/bin/python3", "-c", "print(42)"], budget=budget)
                if result["status"] == "unsupported":
                    self.skipTest(result["reason"])
                self.assertEqual(result["status"], "pass", result)
                self.assertEqual(result["stdout"], "42\n")
                self.assertIn("--property=RuntimeMaxSec=" + str(budget), result["command"])
                self.assertIn("--property=MemoryMax=8589934592", result["command"])
                self.assertIn("--property=MemorySwapMax=0", result["command"])
        result = self.run_case("import os; os.write(1,b'x'*2000000)")
        self.assertEqual(result["status"], "error")
        self.assertLessEqual(len(result["stdout"].encode()), owned_scope.OUTPUT_LIMIT)

    def test_child_has_fresh_working_directory(self):
        result = self.run_case("import os; print(os.getcwd())")
        self.assertEqual(result["status"], "pass", result)
        self.assertTrue(Path(result["stdout"].strip()).name.startswith("vmkek-scope-"))
        self.assertNotEqual(result["stdout"].strip(), os.getcwd())

    def test_kernel_scope_limits(self):
        code = ("from pathlib import Path; p=Path('/sys/fs/cgroup') / "
                "Path('/proc/self/cgroup').read_text().partition('::')[2].strip().lstrip('/'); "
                "print((p/'memory.max').read_text().strip(), (p/'memory.swap.max').read_text().strip())")
        result = self.run_case(code)
        self.assertEqual(result["status"], "pass", result)
        self.assertEqual(result["stdout"].strip(), "8589934592 0")

    def test_timeout_and_descendant_are_terminated(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = str(Path(directory) / "late")
            code = ("import subprocess,time; subprocess.Popen([" + repr(sys.executable) +
                    ",'-c'," + repr("import time,pathlib;time.sleep(4);pathlib.Path(" + repr(marker) + ").touch()") +
                    "]); time.sleep(30)")
            result = self.run_case(code, limits=(1, 64 * 1024 * 1024))
            self.assertEqual(result["status"], "timeout", result)
            time.sleep(4)
            self.assertFalse(Path(marker).exists())

    def test_child_memory_limit_and_error(self):
        code = ("import subprocess,sys; p=subprocess.run([sys.executable,'-c',"
                "'x=bytearray(128*1024*1024); print(len(x))']); sys.exit(p.returncode)")
        result = self.run_case(code, limits=(5, 64 * 1024 * 1024))
        self.assertEqual(result["status"], "oom", result)
        result = self.run_case("raise RuntimeError('test error')")
        self.assertEqual(result["status"], "error", result)

    def test_landlock_denies_file_but_runs_candidate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            forbidden = root / "target"
            forbidden.write_text("hidden")
            candidate = root / "candidate.py"
            candidate.write_text("import pathlib\ntry:\n pathlib.Path(" + repr(str(forbidden)) +
                                 ").read_text()\n print('exposed')\nexcept PermissionError:\n print('denied')\n")
            result = owned_scope.run(["/usr/bin/python3", str(candidate)], budget=60,
                                     isolate_file=str(candidate))
            if result["status"] == "unsupported":
                self.skipTest(result["reason"])
            self.assertEqual(result["status"], "pass", result)
            self.assertEqual(result["stdout"], "denied\n")

    def test_rejects_unknown_budget(self):
        with self.assertRaises(ValueError):
            owned_scope.run(["/usr/bin/true"], budget=10)


if __name__ == "__main__":
    unittest.main()
