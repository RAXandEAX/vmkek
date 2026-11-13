#!/usr/bin/env python3
"""Record the planned owned-fixture evaluation and its local provenance."""

import argparse
import hashlib
import json
import platform
import subprocess
import sys
from collections import Counter
from pathlib import Path

import evaluate


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_head():
    try:
        completed = subprocess.run(
            ["git", "-C", str(evaluate.HERE), "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, check=True, timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    revision = completed.stdout.strip()
    return revision if len(revision) == 40 and all(c in "0123456789abcdef" for c in revision) else None


def manifest(baseline_path=None):
    baseline = evaluate.read_baseline(baseline_path) if baseline_path else None
    rows = list(evaluate.planned_rows(evaluate.TRAIN + evaluate.HOLDOUT, baseline))
    inputs = ("catalog.json", "fixtures.c", "fixtures.ld", "start.S", "evaluate.py",
              "affine_candidate.py", "owned_scope.py")
    return {
        "version": 1,
        "git_head": git_head(),
        "python_version": sys.version.split()[0],
        "generator_sha256": sha256(Path(__file__)),
        "scope": "planned authenticated ELF laboratory evaluation",
        "host": platform.uname()._asdict(),
        "inputs_sha256": {name: sha256(evaluate.HERE / name) for name in inputs},
        "baseline_manifest_sha256": sha256(baseline_path) if baseline_path else None,
        "training": list(evaluate.TRAIN),
        "holdout": list(evaluate.HOLDOUT),
        "tool_versions": evaluate.doctor()["tools"],
        "planned_rows": len(rows),
        "status_counts": dict(sorted(Counter(row["status"] for row in rows).items())),
        "reason_counts": dict(sorted(Counter(row["reason"] for row in rows).items())),
        "rows": rows,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, help="complete baseline.json")
    parser.add_argument("--output", type=Path, required=True, help="new output JSON path")
    args = parser.parse_args()
    record = manifest(args.baseline)
    with args.output.open("x", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")


if __name__ == "__main__":
    main()
