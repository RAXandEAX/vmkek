#!/usr/bin/env python3
"""Measure whole-process latency of owned native ELF ablation outputs."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import statistics
import time
import evaluate


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repetitions", type=int, default=10)
    args = parser.parse_args()
    if not 1 <= args.repetitions <= 100:
        parser.error("repetitions must be between 1 and 100")
    root = args.experiment.resolve(strict=True)
    summary = json.loads((root / "summary.json").read_text())
    jobs = []
    cases = evaluate.public_cases()
    for variant, info in summary["variants"].items():
        manifest_path = root / ("results-" + variant) / "baseline.json"
        if sha(manifest_path) != info["manifest_sha256"]:
            raise ValueError("manifest hash mismatch")
        for row in json.loads(manifest_path.read_text())["rows"]:
            if row["status"] != "pass":
                continue
            name = row["fixture"]
            artifact = manifest_path.parent / (name + "-" + str(row["seed"]) + ".elf")
            if sha(artifact) != row["artifact_sha256"]:
                raise ValueError("artifact hash mismatch")
            jobs.extend([(variant, name, row["seed"], artifact)] * args.repetitions)
    random.Random(0x402).shuffle(jobs)
    durations = {}
    for variant, name, seed, artifact in jobs:
        case = cases[0]
        start = time.monotonic_ns()
        observed = evaluate.observed(artifact, name, case)
        elapsed_ns = time.monotonic_ns() - start
        if evaluate.canonical(observed) != evaluate.canonical(evaluate.oracle(name, case)):
            raise ValueError("output mismatch during timing")
        durations.setdefault((variant, name, seed), []).append(elapsed_ns)
    rows = []
    for (variant, fixture, seed), values in sorted(durations.items()):
        ordered = sorted(values)
        rows.append({"variant": variant, "fixture": fixture, "seed": seed,
                     "samples": len(values), "median_ns": statistics.median(values),
                     "p95_ns": ordered[(95 * len(values) + 99) // 100 - 1]})
    record = {"scope": "warm whole process, one public input; includes startup and harness; not pure function latency",
              "randomization_seed": 0x402, "experiment_sha256": sha(root / "summary.json"),
              "script_sha256": sha(Path(__file__).resolve()), "rows": rows}
    with args.output.open("x", encoding="utf-8") as output:
        json.dump(record, output, indent=2)
        output.write("\n")


if __name__ == "__main__":
    main()
