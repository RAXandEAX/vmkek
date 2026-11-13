import json
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from pathlib import Path

import evaluate


class CorpusTests(unittest.TestCase):
    def test_exact_corpus_and_seed_rotation(self):
        self.assertEqual(len(evaluate.TRAIN), 16)
        self.assertEqual(len(evaluate.HOLDOUT), 8)
        self.assertEqual(len(set(evaluate.TRAIN + evaluate.HOLDOUT)), 24)
        rows = list(evaluate.planned_rows(("affine_xor",)))
        self.assertEqual(len(rows), 180)
        for budget in (60, 600, 3600):
            trial = [row for row in rows if row["wall_seconds"] == budget and row["adapter"] == "symbolic"]
            fresh = [row for row in trial if row["mode"] == "fresh"]
            transfer = [row for row in trial if row["mode"] == "transfer"]
            self.assertEqual(len(fresh), 10)
            self.assertEqual(len(transfer), 10)
            self.assertEqual({row["source_seed"] for row in transfer}, set(evaluate.CATALOG["seeds"]))
            self.assertEqual({row["target_seed"] for row in transfer}, set(evaluate.CATALOG["seeds"]))
            self.assertTrue(all(row["source_seed"] != row["target_seed"] for row in transfer))
            self.assertTrue(all(row["status"] == "not_run" for row in trial))

    def test_original_observations_match_independent_oracle(self):
        parameters = tuple(range(11, 19))
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "fixture.elf"
            evaluate.build_original(original, parameters)
            for fixture in evaluate.TRAIN + evaluate.HOLDOUT:
                with self.subTest(fixture=fixture):
                    cases = evaluate.public_cases() if fixture in evaluate.TRAIN else evaluate.held_cases(7, parameters)
                    evaluate.compare(original, fixture, cases, parameters)

    def test_parallel_oracle_keeps_serial_digest_and_vector_order(self):
        name = "affine_xor"
        cases = evaluate.public_cases()
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "fixture.elf"
            evaluate.build_original(original, [], name)
            serial = evaluate.compare(original, name, cases, [])
            self.assertEqual(evaluate.compare(original, name, cases, [], workers=2), serial)

        completed = []
        second = threading.Event()

        def reordered(_path, fixture, case):
            if case == cases[0]:
                self.assertTrue(second.wait(2))
            actual = evaluate.oracle(fixture, case, [])
            completed.append(case)
            if case == cases[1]:
                second.set()
            return actual

        with patch.object(evaluate, "observed", side_effect=reordered):
            self.assertEqual(evaluate.compare(None, name, cases, [], workers=2), serial)
        self.assertLess(completed.index(cases[1]), completed.index(cases[0]))

    def test_parallel_oracle_refills_before_slow_mate_finishes(self):
        name = "affine_xor"
        cases = evaluate.public_cases()
        third_started = threading.Event()

        def observed(_path, fixture, case):
            if case == cases[0]:
                self.assertTrue(third_started.wait(2))
            elif case == cases[2]:
                third_started.set()
            return evaluate.oracle(fixture, case, [])

        expected = evaluate.digest_json([evaluate.oracle(name, case, []) for case in cases])
        with patch.object(evaluate, "observed", side_effect=observed):
            self.assertEqual(evaluate.compare(None, name, cases, [], workers=2), expected)

    def test_parallel_oracle_drains_active_mate_and_reports_earliest_error(self):
        cases = evaluate.public_cases()
        both_active = threading.Barrier(2)
        finished_first = threading.Event()
        finished_second = threading.Event()

        def observed(_path, _fixture, case):
            self.assertIn(case, cases[:2])
            both_active.wait(timeout=2)
            if case == cases[0]:
                self.assertTrue(finished_second.wait(2))
                finished_first.set()
            else:
                finished_second.set()
            return {}

        with patch.object(evaluate, "observed", side_effect=observed) as compare:
            with self.assertRaisesRegex(ValueError, "semantic mismatch at case 0"):
                evaluate.compare(None, "affine_xor", cases, [], workers=2)
        self.assertEqual(compare.call_count, 2)
        self.assertTrue(finished_first.is_set())

    def test_parallel_oracle_does_not_start_another_batch_after_failure(self):
        with patch.object(evaluate, "observed", return_value={}) as observed:
            with self.assertRaisesRegex(ValueError, "semantic mismatch at case 0"):
                evaluate.compare(None, "affine_xor", evaluate.public_cases(), [], workers=2)
        self.assertIn(observed.call_count, (1, 2))

    def test_build_keeps_completed_control_and_terminal_seed_on_interrupt(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            fake = folder / "fixture-input"
            fake.write_bytes(b"owned test input")
            output = folder / "result"
            args = SimpleNamespace(fixture=["affine_xor"], holdout=None, affine_probe=False,
                                   output=output, signer=fake, pin=fake, oracle_workers=1)
            failed = subprocess.CompletedProcess([], 1, "", "unsupported private test detail")
            progress = output / "baseline-progress.json"

            def protected(*_args):
                state = evaluate.load_json(progress)
                self.assertIs(state["complete"], False)
                self.assertEqual([row["fixture"] for row in state["controls"]], ["affine_xor"])
                if state["rows"]:
                    raise KeyboardInterrupt()
                return failed

            with (patch.object(evaluate, "PROTECTOR", fake), patch.object(evaluate, "HELPER", fake),
                  patch.object(evaluate, "protect_one", side_effect=protected)):
                with self.assertRaises(KeyboardInterrupt):
                    evaluate.build_baselines(args)
            self.assertFalse((output / "baseline.json").exists())
            state = evaluate.load_json(progress)
            self.assertEqual([(row["seed"], row["status"]) for row in state["rows"]],
                             [(evaluate.CATALOG["seeds"][0], "unsupported")])
            self.assertNotIn("compiler_command", state["controls"][0])
            self.assertNotIn("private test detail", progress.read_text())
            with self.assertRaisesRegex(ValueError, "invalid baseline manifest"):
                evaluate.read_baseline(progress)

            completed = folder / "completed"
            args.output = completed
            with (patch.object(evaluate, "PROTECTOR", fake), patch.object(evaluate, "HELPER", fake),
                  patch.object(evaluate, "protect_one", return_value=failed)):
                self.assertEqual(evaluate.build_baselines(args), 1)
            self.assertFalse((completed / progress.name).exists())
            self.assertEqual(len(evaluate.read_baseline(completed / "baseline.json")["rows"]), 10)

    def test_atomic_publication_keeps_previous_json_if_replace_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline-progress.json"
            evaluate.publish_json(path, {"rows": [1]})
            with patch.object(Path, "replace", side_effect=OSError("owned replace failure")):
                with self.assertRaisesRegex(OSError, "owned replace failure"):
                    evaluate.publish_json(path, {"rows": [1, 2]})
            self.assertEqual(evaluate.load_json(path), {"rows": [1]})
            self.assertEqual(list(path.parent.iterdir()), [path])

    def test_selected_holdout_binary_excludes_other_functions(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "fixture.elf"
            parameters = tuple(range(11, 19))
            evaluate.build_original(original, parameters, "lane_sum")
            symbols = evaluate.command(["nm", "-S", original]).stdout
            self.assertIn(" lane_sum", symbols)
            for fixture in set(evaluate.TRAIN + evaluate.HOLDOUT) - {"lane_sum"}:
                self.assertNotIn(f" {fixture}\n", symbols)
            evaluate.compare(original, "lane_sum", evaluate.public_cases(), parameters)

    def test_grading_checks_ordered_side_effects_and_types(self):
        fixture = "two_helpers"
        observations = {
            f"case-{index:03}": evaluate.oracle(fixture, case)
            for index, case in enumerate(evaluate.public_cases())
        }
        self.assertEqual(evaluate.grade(fixture, observations, None)["status"], "matched_observations")
        observations["case-000"]["effects"].reverse()
        self.assertEqual(evaluate.grade(fixture, observations, None)["status"], "mismatch")
        observations["case-000"]["effects"].reverse()
        observations["case-000"]["status"] = False
        self.assertEqual(evaluate.grade(fixture, observations, None)["status"], "mismatch")

    def test_holdout_pack_rejects_extra_or_nonnumeric_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            pack = Path(directory) / "pack.json"
            valid = {"parameters": list(range(8)), "vector_seed": 31}
            pack.write_text(json.dumps(valid))
            self.assertEqual(evaluate.private_pack(pack), valid)
            for malformed in [dict(valid, argv=["ignored"]), dict(valid, parameters=[True] * 8)]:
                pack.write_text(json.dumps(malformed))
                with self.assertRaises(ValueError):
                    evaluate.private_pack(pack)


    def test_plan_keeps_failed_donor_and_uses_exact_artifact_digest(self):
        prior, target = evaluate.CATALOG["seeds"][:2]
        baseline = {
            "version": 1, "run_config_sha256": "c" * 64,
            "rows": [
                {"fixture": "affine_xor", "seed": prior, "status": "error",
                 "profile": "elf-authenticated-lab"},
                {"fixture": "affine_xor", "seed": target, "status": "pass",
                 "profile": "elf-authenticated-lab", "artifact_sha256": "a" * 64},
            ],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "baseline.json"
            path.write_text(json.dumps(baseline))
            rows = list(evaluate.planned_rows(("affine_xor",), evaluate.read_baseline(path)))
            selected = next(row for row in rows if row["target_seed"] == target and row["mode"] == "transfer")
            self.assertEqual(selected["source_seed"], prior)
            self.assertEqual(selected["status"], "not_run")
            self.assertEqual(selected["artifact_sha256"], "a" * 64)
            self.assertEqual(selected["reason"], "preregistered donor unavailable")
            baseline["rows"].append(baseline["rows"][0])
            path.write_text(json.dumps(baseline))
            with self.assertRaises(ValueError):
                evaluate.read_baseline(path)


    def test_training_grading_ignores_holdout_pack(self):
        pack = {"parameters": list(range(8)), "vector_seed": 99}
        observations = {
            f"case-{index:03}": evaluate.oracle("affine_xor", case)
            for index, case in enumerate(evaluate.public_cases())
        }
        self.assertEqual(evaluate.grade("affine_xor", observations, pack)["status"], "matched_observations")

    def test_tool_version_failure_is_preserved(self):
        failed = SimpleNamespace(returncode=2, stdout="", stderr="version failure")
        with patch.object(evaluate.shutil, "which", return_value="/usr/bin/tool"):
            with patch.object(evaluate, "command", return_value=failed):
                actual = evaluate.version("tool")
        self.assertEqual(actual["status"], "error")
        self.assertEqual(actual["exit_code"], 2)

    def test_holdout_cases_cover_private_threshold_and_tlv_boundaries(self):
        params = tuple(range(11, 19))
        cases = evaluate.held_cases(7, params)
        directed = [case[0] for case in cases[-5:-2]]
        self.assertEqual(directed, [params[1] - 1, params[1], params[1] + 1])
        self.assertEqual(
            [evaluate.oracle("bounded_tlv", case, params)["status"] for case in cases[-2:]],
            [0, 1],
        )

    def test_invalid_source_control_output_is_an_error(self):
        runs = [{"exit_code": 0, "stdout": "{broken json"}]
        self.assertEqual(evaluate.matching_dfsan_runs(runs, {"label": 3}), 0)
        with tempfile.TemporaryDirectory() as directory:
            listing = Path(directory) / "empty.ll"
            listing.touch()
            self.assertIsNone(evaluate.normalized_listing(listing))


    def test_baseline_config_digest_binds_private_pack(self):
        manifest = {
            name: "a" * 64 for name in (
                "catalog_sha256", "fixtures_sha256", "linker_script_sha256", "startup_sha256",
                "holdout_pack_sha256", "protector_sha256", "helper_sha256",
            )
        }
        manifest.update(compiler={"version": "test"}, controls=[{"original_sha256": "b" * 64}])
        initial = evaluate.baseline_config_digest(manifest, ("lane_sum",))
        manifest["holdout_pack_sha256"] = "c" * 64
        self.assertNotEqual(initial, evaluate.baseline_config_digest(manifest, ("lane_sum",)))


    def test_tool_version_timeout_and_spawn_error_are_local(self):
        with patch.object(evaluate.shutil, "which", return_value="/usr/bin/tool"):
            for error, status in [(subprocess.TimeoutExpired("tool", 10), "timeout"),
                                  (OSError("spawn failed"), "error")]:
                with patch.object(evaluate, "command", side_effect=error):
                    self.assertEqual(evaluate.version("tool")["status"], status)

    def test_adce_missing_output_preserves_other_control_rows(self):
        fake = SimpleNamespace(returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "controls"
            with patch.object(evaluate.shutil, "which", return_value="/usr/bin/tool"):
                with patch.object(evaluate, "command", return_value=fake):
                    evaluate.run_controls(output)
            rows = {row["adapter"]: row for row in json.loads((output / "controls.json").read_text())}
            self.assertEqual(rows["llvm-adce-projection"]["status"], "error")
            self.assertIn("unreadable LLVM projection", rows["llvm-adce-projection"]["reason"])
            self.assertIn("slicing", rows)

    def test_control_launch_error_preserves_prior_commands_and_other_adapters(self):
        success = SimpleNamespace(returncode=0, stdout="", stderr="")

        def launch(argv, **_options):
            if argv[0] == "llvm-dis-18":
                raise PermissionError("control executable cannot launch")
            return success

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "controls"
            with patch.object(evaluate.shutil, "which", return_value="/usr/bin/tool"):
                with patch.object(evaluate, "command", side_effect=launch):
                    self.assertEqual(evaluate.run_controls(output), 1)
            rows = {row["adapter"]: row for row in json.loads((output / "controls.json").read_text())}
            failed = rows["llvm-normalization"]
            self.assertEqual(failed["status"], "error")
            self.assertEqual(failed["commands"][0]["exit_code"], 0)
            self.assertEqual(failed["commands"][1]["argv"][0], "llvm-dis-18")
            self.assertIn("control executable cannot launch", failed["commands"][1]["error"])
            self.assertIn("slicing", rows)

    def test_normalized_listing_rejects_io_and_encoding_errors(self):
        with tempfile.TemporaryDirectory() as directory:
            listing = Path(directory) / "fixtures.ll"
            listing.write_bytes(b"\xff")
            self.assertIsNone(evaluate.normalized_listing(listing))
            with patch.object(Path, "read_text", side_effect=PermissionError("unreadable")):
                self.assertIsNone(evaluate.normalized_listing(listing))

    def test_affine_candidate_rejects_non_list_json(self):
        response = {"status": "pass", "stdout": "null"}
        with patch.object(evaluate.owned_scope, "run", return_value=response):
            with self.assertRaises(ValueError):
                evaluate.score_affine((12, 11), [(1, 2, 3, 0, ())], [{}])

    def test_legacy_affine_probe_rejected_before_creating_output(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "out"
            run = subprocess.run([
                sys.executable, str(evaluate.HERE / "evaluate.py"), "build",
                "--fixture", "affine_xor", "--output", str(output),
                "--signer", "missing-signer", "--pin", "missing-pin", "--affine-probe",
            ], capture_output=True, text=True)
            self.assertNotEqual(run.returncode, 0)
            self.assertIn("affine_cells.py", run.stderr)
            self.assertFalse(output.exists())

    def test_affine_candidate_fails_closed_without_isolation(self):
        unavailable = {"status": "unsupported", "reason": "user bus unavailable"}
        with patch.object(evaluate.owned_scope, "run", return_value=unavailable):
            with self.assertRaises(evaluate.ScopeFailure) as failure:
                evaluate.score_affine((12, 11), [], [])
        self.assertEqual(failure.exception.status, "unsupported")

    def test_declared_affine_hypothesis_fits_and_grades_detached(self):
        rows = [(0, 0, 11), (1, 2, 21), (2, 3, 32)]
        model = evaluate.fit_affine(rows)
        self.assertEqual(model, (12, 11))
        private_case = (3, 0, 8, 0, (7,) * 16)
        expected = evaluate.result(47, 8, private_case[-1])
        def run_candidate(argv, *, budget, input_data, isolate_file):
            self.assertEqual(budget, 60)
            self.assertEqual(Path(isolate_file), evaluate.HERE / "affine_candidate.py")
            completed = subprocess.run(argv, input=input_data, capture_output=True, check=True)
            return {"status": "pass", "stdout": completed.stdout.decode(),
                    "budget_seconds": budget, "memory_limit_bytes": 8 * 1024**3,
                    "memory_peak": None, "elapsed_seconds": 0, "systemd_result": "success"}

        with patch.object(evaluate.owned_scope, "run", side_effect=run_candidate):
            matching = evaluate.score_affine(model, [private_case], [expected])
            self.assertEqual(matching["status"], "hypothesis_match")
            self.assertEqual(matching["runner_sha256"], evaluate.digest(evaluate.HERE / "owned_scope.py"))
            corrupted_buffer = dict(expected, buffer="00" * 16)
            self.assertEqual(evaluate.score_affine(model, [private_case], [corrupted_buffer])["status"], "mismatch")
            extra_effect = dict(expected, effects=[1], effect_count=1)
            self.assertEqual(evaluate.score_affine(model, [private_case], [extra_effect])["status"], "mismatch")
        rows[-1] = (2, 3, 33)
        with self.assertRaises(ValueError):
            evaluate.fit_affine(rows)


if __name__ == "__main__":
    unittest.main()
