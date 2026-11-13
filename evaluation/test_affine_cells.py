import json
import unittest
from pathlib import Path
from unittest.mock import patch

import affine_cells


class AffineCellsTests(unittest.TestCase):
    def test_fit_timeout_never_scores_and_preserves_status(self):
        with patch.object(affine_cells.owned_scope, "run", return_value={"status": "timeout"}), \
             patch.object(affine_cells, "restricted_score") as score:
            model, row = affine_cells.fresh_cell(Path("/fixture"), [], [], 600)
        self.assertIsNone(model)
        self.assertEqual(row["status"], "timeout")
        score.assert_not_called()

    def test_fresh_scoring_receives_remaining_budget(self):
        fit = {"status": "pass", "stdout": json.dumps({"model": [12, 11], "observations_sha256": "a" * 64})}
        with patch.object(affine_cells.owned_scope, "run", return_value=fit), \
             patch.object(affine_cells, "restricted_score", return_value=("hypothesis_match", {})) as score:
            model, row = affine_cells.fresh_cell(Path("/fixture"), [], [], 600)
        self.assertEqual(model, [12, 11])
        self.assertEqual(row["status"], "hypothesis_match")
        self.assertLess(score.call_args.args[-1], 600)
        self.assertGreater(score.call_args.args[-1], 0)

    def test_missing_or_invalid_observation_digest_is_error_without_scoring(self):
        for learned in ({"model": [12, 11]}, {"model": [12, 11], "observations_sha256": "h"}):
            with self.subTest(learned=learned):
                fit = {"status": "pass", "stdout": json.dumps(learned)}
                with patch.object(affine_cells.owned_scope, "run", return_value=fit), \
                     patch.object(affine_cells, "restricted_score") as score:
                    model, row = affine_cells.fresh_cell(Path("/fixture"), [], [], 600)
                self.assertIsNone(model)
                self.assertEqual(row["status"], "error")
                score.assert_not_called()

    def test_transfer_has_zero_target_queries(self):
        with patch.object(affine_cells, "restricted_score", return_value=("hypothesis_match", {})) as score:
            row = affine_cells.transfer_cell([12, 11], [], [], 3600)
        self.assertEqual(row["target_queries"], 0)
        self.assertEqual(score.call_args.args[-1], 3600)


if __name__ == "__main__":
    unittest.main()
