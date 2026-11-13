#!/usr/bin/env python3
"""Reproduce the bounded research checks; does not edit protector sources.

Run on Linux/WSL with --source pointing to a git archive of REVISION and
--repository pointing to a repository containing that commit. Use a fresh
--output directory. Cargo and the tests write only build/temporary artifacts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import time

REVISION = "4cd330d0ba73b6a912506c3c83c2ee1331af262d"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--cargo", default="cargo")
    args = parser.parse_args()
    source = args.source.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    env["PATH"] = str(Path(args.cargo).resolve().parent) + os.pathsep + env["PATH"]
    tree = subprocess.check_output([
        "git", "-C", str(args.repository), "ls-tree", "-rz", REVISION
    ])
    entries = []
    for item in tree.split(b"\0"):
        if not item:
            continue
        meta, raw_path = item.split(b"\t", 1)
        mode, kind, oid = meta.decode().split()
        if kind != "blob":
            raise RuntimeError(f"Unsupported tree entry: {item!r}")
        path = raw_path.decode()
        file = source / path
        data = os.readlink(file).encode() if mode == "120000" else file.read_bytes()
        actual = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
        if actual != oid:
            raise RuntimeError(f"Snapshot differs from pinned commit: {path}")
        entries.append({"path": path, "git_blob": oid, "sha256": hashlib.sha256(data).hexdigest()})
    results = {
        "revision": REVISION,
        "date_context": "2026-11-13 Europe/Moscow",
        "platform": platform.platform(),
        "python": platform.python_version(),
        "scope": "correctness and source-level controls; not protected-binary recovery",
        "source_files_verified": len(entries),
        "commands": [],
    }
    (output / "source-manifest.json").write_text(json.dumps(entries, indent=2) + "\n")
    commands = [
        [args.cargo, "+1.95.0", "--version"],
        [str(Path(args.cargo).with_name("rustc")), "+1.95.0", "--version"],
        [args.cargo, "+1.95.0", "test", "--locked", "--offline", "-p", "vmkek", "--lib", "obf::"],
        [args.cargo, "+1.95.0", "test", "--locked", "--offline", "-p", "vmkek", "--lib", "adversary::"],
        [args.cargo, "+1.95.0", "test", "--locked", "--offline", "-p", "vmkek", "--lib", "vm::"],
        [args.cargo, "+1.95.0", "test", "--locked", "--offline", "-p", "vmkek-protocol", "--features", "r06-experimental", "--test", "lab"],
        ["python3", "-m", "unittest", "discover", "-s", "evaluation", "-p", "test_evaluate.py", "-v"],
        ["python3", "evaluation/r06_normalize.py", str(output / "r06-normalize")],
    ]
    with (output / "checks.txt").open("w") as log:
        for command in commands:
            started = time.monotonic()
            try:
                run = subprocess.run(command, cwd=source, env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, timeout=180)
                text, code, status = run.stdout, run.returncode, "completed"
            except subprocess.TimeoutExpired as error:
                captured = error.stdout or b""
                text = captured.decode(errors="replace") if isinstance(captured, bytes) else captured
                code, status = None, "timeout"
            except OSError as error:
                text, code, status = str(error), None, "unavailable"
            row = {"command": command, "exit_code": code, "status": status,
                   "elapsed_seconds": round(time.monotonic() - started, 3)}
            results["commands"].append(row)
            log.write(json.dumps(row) + "\n" + text + "\n")
            log.flush()
            print(json.dumps(row), flush=True)
    # Independent concrete evaluation of the published predicate's formula.
    # This is NOT a binary deobfuscator or a formal equivalence proof.
    hard = (source / "src/obf/hard.rs").read_text()
    def constant(name):
        value = re.search(rf"(?:pub )?const {name}: u(?:32|64) = (0x[0-9A-Fa-f_]+|[0-9_]+);", hard)
        if not value:
            raise RuntimeError(f"Missing literal constant: {name}")
        return int(value[1].replace("_", ""), 0)
    mask = (1 << 64) - 1
    value = (constant("PREIMAGE") * constant("MUL0")) & mask
    value ^= value >> constant("SHIFT_A")
    value = (value * constant("MUL1")) & mask
    value ^= value >> constant("SHIFT_B")
    value &= (1 << constant("HASH_BITS")) - 1
    results["constant_predicate_probe"] = {
        "source_sha256": hashlib.sha256(hard.encode()).hexdigest(),
        "input": hex(constant("PREIMAGE")), "result": hex(value),
        "matches_source_assertion_0xfe5d": value == 0xFE5D,
        "scope": "concrete evaluation of the source formula; no preimage search required",
    }
    results["checks_log_sha256"] = hashlib.sha256((output / "checks.txt").read_bytes()).hexdigest()
    (output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(json.dumps(results["constant_predicate_probe"]), flush=True)
    return int(any(row["exit_code"] != 0 for row in results["commands"]) or value != 0xFE5D)


if __name__ == "__main__":
    raise SystemExit(main())
