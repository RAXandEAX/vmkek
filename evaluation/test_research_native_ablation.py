import copy
import tempfile
from pathlib import Path
import unittest

import research_native_ablation as ablation


class NativeAblationTests(unittest.TestCase):
    def test_complete_manifest_requires_all_successful_unique_rows_and_controls(self):
        fixtures = ("affine_xor", "counter")
        good = {"controls": [{"fixture": f, "status": "pass"} for f in fixtures],
                "rows": [{"fixture": f, "seed": seed, "status": "pass"}
                         for f in fixtures for seed in range(0x401, 0x40b)]}
        self.assertEqual(ablation.manifest_errors(good), [])
        for change in ("error", "missing", "duplicate", "bad_control", "missing_control"):
            case = copy.deepcopy(good)
            if change == "error":
                case["rows"][0]["status"] = "error"
            elif change == "missing":
                case["rows"].pop()
            elif change == "duplicate":
                case["rows"][-1] = case["rows"][0].copy()
            elif change == "bad_control":
                case["controls"][0]["status"] = "error"
            else:
                case["controls"].pop()
            with self.subTest(change=change):
                self.assertTrue(ablation.manifest_errors(case))

    def test_missing_balanced_flatten_seam_does_not_write_partial_patch(self):
        original = (Path(ablation.__file__).resolve().parent.parent / "src/obf/mod.rs").read_text()
        seam = "    Ok(finish(flatten_balanced(&func)?, passes, rng))"
        self.assertEqual(original.count(seam), 1)
        changed = original.replace(seam, "    /* changed seam */")
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "mod.rs"
            path.write_text(changed)
            with self.assertRaises(ValueError):
                ablation.patch_source(path)
            self.assertEqual(path.read_text(), changed)

    def test_exit_status_rejects_partial_success_even_when_process_passed(self):
        partial = {variant: {"exit_code": 0, "manifest_errors": []} for variant in ablation.VARIANTS}
        self.assertEqual(ablation.final_exit(partial), 0)
        partial["opaque"]["manifest_errors"] = ["missing row"]
        self.assertEqual(ablation.final_exit(partial), 1)
        del partial["shuffle"]
        self.assertEqual(ablation.final_exit(partial), 1)


if __name__ == "__main__":
    unittest.main()
