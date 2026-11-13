#!/usr/bin/env python3
"""Evaluate the owned affine fixture with per-cell resource budgets."""

import argparse
import hashlib
import json
import math
import sys
import time
from pathlib import Path

import evaluate
import owned_scope

HERE = Path(__file__).resolve().parent
CANDIDATE = HERE / "affine_candidate.py"


def file_sha(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def restricted_score(model, cases, expected, budget, remaining):
    result = owned_scope.run(
        ["/usr/bin/python3", "-B", str(CANDIDATE)], budget=budget,
        _limits=(remaining, owned_scope.MEMORY), isolate_file=str(CANDIDATE),
        input_data=json.dumps({"model": model, "cases": cases}).encode(),
    )
    receipt = {key: result.get(key) for key in
               ("status", "systemd_result", "elapsed_seconds", "memory_peak", "exit_code")}
    if result["status"] != "pass":
        return result["status"], receipt
    try:
        predictions = json.loads(result["stdout"])
        if not isinstance(predictions, list) or len(predictions) != len(expected):
            raise ValueError("wrong result count")
        if any(not isinstance(item, dict) for item in predictions):
            raise ValueError("invalid observation")
        mismatches = sum(evaluate.canonical(a) != evaluate.canonical(b)
                         for a, b in zip(predictions, expected, strict=True))
    except (ValueError, TypeError) as error:
        receipt["reason"] = str(error)
        return "error", receipt
    receipt["mismatches"] = mismatches
    receipt["oracle_sha256"] = evaluate.digest_json(expected)
    return ("mismatch" if mismatches else "hypothesis_match"), receipt


def fresh_cell(artifact, cases, expected, budget):
    start = time.monotonic()
    fit = owned_scope.run(
        ["/usr/bin/python3", "-B", str(Path(__file__).resolve()), "--worker", str(artifact)],
        budget=budget,
    )
    fit_receipt = {key: fit.get(key) for key in
                   ("status", "systemd_result", "elapsed_seconds", "memory_peak", "exit_code")}
    if fit["status"] != "pass":
        return None, {"status": fit["status"], "fit": fit_receipt,
                      "elapsed_seconds": time.monotonic() - start}
    try:
        learned = json.loads(fit["stdout"])
        model = learned["model"]
        if not isinstance(model, list) or len(model) != 2 or any(type(x) is not int or not 0 <= x <= evaluate.MASK for x in model):
            raise ValueError("invalid fitted model")
        if not evaluate.is_sha256(learned["observations_sha256"]):
            raise ValueError("invalid observations digest")
    except (ValueError, TypeError, KeyError) as error:
        return None, {"status": "error", "reason": str(error), "fit": fit_receipt,
                      "elapsed_seconds": time.monotonic() - start}
    remaining = math.floor(budget - (time.monotonic() - start))
    if remaining < 1:
        return None, {"status": "timeout", "fit": fit_receipt,
                      "elapsed_seconds": time.monotonic() - start}
    status, score = restricted_score(model, cases, expected, budget, remaining)
    return model, {"status": status, "fit": fit_receipt, "score": score,
                   "target_queries": len(evaluate.public_cases()),
                   "observations_sha256": learned["observations_sha256"],
                   "model_sha256": evaluate.digest_json(model),
                   "elapsed_seconds": time.monotonic() - start}


def transfer_cell(model, cases, expected, budget):
    start = time.monotonic()
    status, score = restricted_score(model, cases, expected, budget, budget)
    return {"status": status, "score": score, "target_queries": 0,
            "model_sha256": evaluate.digest_json(model), "elapsed_seconds": time.monotonic() - start}


def run(baseline_dir, pack_path, budget):
    baseline_dir = baseline_dir.resolve(strict=True)
    if baseline_dir.is_relative_to("/usr"):
        raise ValueError("targets must be outside trusted /usr")
    manifest_path = baseline_dir / "baseline.json"
    manifest = evaluate.read_baseline(manifest_path)
    pack = evaluate.load_json(pack_path)
    cases = evaluate.held_cases(pack["vector_seed"], pack["parameters"])[len(evaluate.public_cases()):]
    expected = [evaluate.oracle("affine_xor", case) for case in cases]
    seeds = evaluate.CATALOG["seeds"]
    baselines = {row["seed"]: row for row in manifest["rows"] if row["fixture"] == "affine_xor"}
    original_record = next((row for row in manifest.get("controls", [])
                            if row.get("fixture") == "affine_xor"), {})
    original_path = baseline_dir / "affine_xor-original.elf"
    if original_record.get("status") != "pass" or not original_path.is_file() or file_sha(original_path) != original_record.get("original_sha256"):
        raise ValueError("original control unavailable or hash mismatch")
    _, original = fresh_cell(original_path, cases, expected, budget)
    models = {}
    rows = []
    for seed in seeds:
        row = baselines.get(seed, {})
        artifact = baseline_dir / f"affine_xor-{seed}.elf"
        base = {"mode": "fresh", "target_seed": seed, "artifact_sha256": row.get("artifact_sha256"),
                "budget_seconds": budget, "memory_bytes": owned_scope.MEMORY}
        if original.get("status") != "hypothesis_match":
            base.update(status="not_run", reason="original control unavailable")
        elif row.get("status") != "pass":
            base.update(status="not_run", reason="baseline unavailable")
        elif not artifact.is_file() or file_sha(artifact) != row["artifact_sha256"]:
            base.update(status="error", reason="artifact hash mismatch or missing")
        else:
            model, result = fresh_cell(artifact, cases, expected, budget)
            base.update(result)
            if model is not None:
                models[seed] = model
        rows.append(base)
    for index, seed in enumerate(seeds):
        source = seeds[index - 1]
        target = baselines.get(seed, {})
        donor = baselines.get(source, {})
        artifact = baseline_dir / f"affine_xor-{seed}.elf"
        base = {"mode": "transfer", "source_seed": source, "target_seed": seed,
                "artifact_sha256": target.get("artifact_sha256"),
                "donor_sha256": donor.get("artifact_sha256"),
                "budget_seconds": budget, "memory_bytes": owned_scope.MEMORY, "target_queries": 0}
        if source not in models or target.get("status") != "pass":
            base.update(status="not_run", reason="donor or target baseline unavailable")
        elif not artifact.is_file() or file_sha(artifact) != target["artifact_sha256"]:
            base.update(status="error", reason="artifact hash mismatch or missing")
        else:
            base.update(transfer_cell(models[source], cases, expected, budget))
        rows.append(base)
    return {"version": 1, "fixture": "affine_xor", "scope": "owned declared affine hypothesis",
            "baseline_sha256": file_sha(manifest_path), "run_config_sha256": manifest["run_config_sha256"],
            "pack_sha256": file_sha(pack_path), "candidate_sha256": file_sha(CANDIDATE),
            "worker_sha256": file_sha(Path(__file__).resolve()),
            "evaluator_sha256": file_sha(HERE / "evaluate.py"),
            "runner_sha256": file_sha(HERE / "owned_scope.py"),
            "budget_seconds": budget, "original_control": original, "rows": rows}


def main():
    if len(sys.argv) == 3 and sys.argv[1] == "--worker":
        model, digest = evaluate.learn_affine(Path(sys.argv[2]))
        print(json.dumps({"model": model, "observations_sha256": digest}))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--pack", type=Path, required=True)
    parser.add_argument("--budget", type=int, choices=owned_scope.BUDGETS, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.baseline, args.pack, args.budget)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(result, handle, indent=2)
        handle.write("\n")


if __name__ == "__main__":
    main()
