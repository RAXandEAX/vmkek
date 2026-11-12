#!/usr/bin/env python3
"""Compare normalized and ADCE-sliced LLVM bodies for the owned R06 terms."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

FUNCTIONS = ("r06_reference", "r06_add_pair", "r06_subtract_negated_pair")


def normalized_bodies(listing):
    bodies = {}
    for function in FUNCTIONS:
        match = re.search(rf"(?m)^define [^\n]*@{function}\([^\n]*\{{\n(.*?)^\}}", listing, re.S)
        if not match:
            raise ValueError(f"LLVM function missing: {function}")
        bodies[function] = match.group(1).strip()
    return bodies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir()
    initial = args.output / "normalized.ll"
    sliced = args.output / "sliced.ll"
    source = Path(__file__).with_name("r06_terms.c").resolve()
    commands = [
        ["clang-18", "-O1", "-S", "-emit-llvm", str(source), "-o", str(initial)],
        ["opt-18", "-passes=adce", "-S", str(initial), "-o", str(sliced)],
    ]
    for command in commands:
        subprocess.run(command, check=True, timeout=30)
    bodies = normalized_bodies(sliced.read_text())
    distinct = sorted(set(bodies.values()))
    result = {
        "scope": "owned arithmetic source terms with fixed R06 fixture constants",
        "tools": {
            tool: subprocess.check_output([tool, "--version"], text=True, timeout=5).splitlines()[0]
            for tool in ("clang-18", "opt-18")
        },
        "commands": commands,
        "distinct_sliced_bodies": len(distinct),
        "bodies": bodies,
        "body_sha256": hashlib.sha256("\n".join(distinct).encode()).hexdigest(),
    }
    print(json.dumps(result, indent=2))
    return 0 if len(distinct) == 1 else 1


if __name__ == "__main__":
    raise SystemExit(main())
