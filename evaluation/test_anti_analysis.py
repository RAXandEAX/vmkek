import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import anti_analysis as lab


class AssessmentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.seeds = list(range(1, 11))
        self.corpus = {str(seed): [[index, seed] for index in range(lab.CASE_COUNT)] for seed in self.seeds}
        self.binary = self.write("fixture.exe", b"test fixture identity")
        self.error = self.write("error.log", b"")
        self.manifest = {
            "schema": 1,
            "source_manifest": self.write("source.sha256", b"test source identity"),
            "binary": self.binary,
            "corpus": self.write("oracle.json", json.dumps(self.corpus).encode()),
            "host": {"os": "Windows", "build": "test build", "arch": "x86_64", "cpu": "test cpu"},
            "tools": {name: "test tool" for name in ("rustc", "cargo", "msvc", "python")},
            "seeds": self.seeds,
            "rows": [self.row(seed, profile) for seed in self.seeds for profile in lab.PROFILES],
            "external_assessment": {
                item: {"status": "not-run", "reason": "independent measurement unavailable"}
                for item in lab.MISSING_EXTERNAL
            },
        }

    def write(self, path, data):
        (self.root / path).write_bytes(data)
        return {"path": path, "sha256": hashlib.sha256(data).hexdigest()}

    def raw(self, seed, profile, inputs=None, wrong=False):
        cases = self.corpus[str(seed)] if inputs is None else inputs
        payload = "".join(f"{left} {right}\n" for left, right in cases).encode()
        sha = hashlib.sha256(payload).hexdigest()
        policy = "none" if profile == "baseline" else "1" * 64
        lines = [f"policy sha256={policy} epoch={0 if profile == 'baseline' else 1}"]
        lines.extend(f"sample kind={kind} finding=NotObservedWithinScope reason=None"
                     for kind in lab.PROFILES[profile])
        program = bytes([seed])
        lines += [
            f"fixture seed={seed} profile={profile} bytecode_sha256={hashlib.sha256(program).hexdigest()} "
            f"input_sha256={sha} ready_ns=100",
            f"artifact descriptor={seed:02x} program={program.hex()}",
        ]
        for index, (left, right) in enumerate(cases):
            value = (left + right + seed + (wrong and index == 0)) & lab.U64_MASK
            lines.append(f"result index={index} status=0 bits={value} ns=1 metadata=true")
        return ("\n".join([*lines, "done cpu_ns=90 private_bytes=64"]) + "\n").encode()

    def row(self, seed, profile):
        return {
            "seed": seed,
            "profile": profile,
            "command": ["fixture.exe", "--assessment", profile, str(seed)],
            "status": "recorded",
            "exit_code": 0,
            "wall_ns": 1_000_000,
            "stdout": self.write(f"{seed}-{profile}.log", self.raw(seed, profile)),
            "stderr": self.error,
        }

    def test_full_grid_preserves_unqualified_resistance_gate(self):
        result = lab.evaluate(self.manifest, self.root)
        self.assertEqual(result["benchmark"]["status"], "verified")
        self.assertEqual(result["resistance_gate"], "not-run")
        self.assertEqual(result["benchmark"]["distinct_baseline_artifacts"],
                         {"bytecode_sha256": 10, "descriptor_sha256": 10})
        self.assertEqual(result["benchmark"]["clean_observation_coverage"]["integrity-only"],
                         {"CodeIntegrity": 10})

    def test_equal_result_from_different_inputs_is_rejected(self):
        swapped = [[right, left] for left, right in self.corpus["1"]]
        stdout = self.raw(1, "baseline", swapped)
        row = self.manifest["rows"][0]
        row["stdout"] = self.write("swapped.log", stdout)
        result = lab.evaluate(self.manifest, self.root)
        self.assertEqual(result["rows"][0]["reason"], "fixture stdin digest mismatch")
        self.assertEqual(result["benchmark"]["status"], "failed")

    def test_wrong_abi_result_and_not_run_remain_distinct(self):
        first = self.manifest["rows"][0]
        first["stdout"] = self.write("wrong.log", self.raw(1, "baseline", wrong=True))
        second = self.manifest["rows"][1]
        self.manifest["rows"][1] = {
            **{key: second[key] for key in ("seed", "profile", "command")},
            "status": "not-run",
            "reason": "native fixture unavailable",
        }
        rows = lab.evaluate(self.manifest, self.root)["rows"]
        self.assertEqual(rows[0]["failures"], {"wrong_result": 1})
        self.assertEqual(rows[1]["status"], "not-run")
        self.assertNotIn("wall_ns", rows[1])

    def test_rejects_duplicate_grid_and_numeric_booleans(self):
        variant = copy.deepcopy(self.manifest)
        variant["rows"][-1] = variant["rows"][0]
        with self.assertRaisesRegex(ValueError, "duplicate or missing"):
            lab.evaluate(variant, self.root)
        self.manifest["rows"][0]["exit_code"] = False
        with self.assertRaisesRegex(ValueError, "invalid process exit code"):
            lab.evaluate(self.manifest, self.root)

    def test_rejects_wrong_hash_and_path_escape(self):
        self.manifest["binary"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            lab.evaluate(self.manifest, self.root)
        self.manifest["binary"]["path"] = "../fixture.exe"
        with self.assertRaisesRegex(ValueError, "escapes"):
            lab.evaluate(self.manifest, self.root)
        (self.root / "alias.exe").symlink_to(self.root / "fixture.exe")
        self.manifest["binary"]["path"] = "alias.exe"
        with self.assertRaisesRegex(ValueError, "symlink"):
            lab.evaluate(self.manifest, self.root)

    def test_rejects_unbounded_raw_and_duplicate_json_fields(self):
        self.manifest["rows"][0]["stdout"] = self.write("huge.log", b"1" * (lab.MAX_RAW + 1))
        with self.assertRaisesRegex(ValueError, "size limit"):
            lab.evaluate(self.manifest, self.root)
        with self.assertRaisesRegex(ValueError, "duplicate JSON key"):
            lab.json_data('{"schema": 1, "schema": 2}')

    def test_cli_refuses_existing_output(self):
        output = self.root / "out"
        output.mkdir()
        (output / "summary.json").write_text("earlier summary")
        path = self.root / self.write("manifest.json", json.dumps(self.manifest).encode())["path"]
        with patch("sys.argv", ["anti_analysis.py", "--manifest", str(path), "--output", str(output)]):
            with patch("sys.stderr"):
                self.assertEqual(lab.main(), 2)
        self.assertEqual((output / "summary.json").read_text(), "earlier summary")


if __name__ == "__main__":
    unittest.main()
