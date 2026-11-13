#!/usr/bin/env python3
"""Owned C fixture control for a regional 64-bit offset encoding."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE / "research_data_encoding.c"


def supported_region(*, operations, flags_dead, scratch, operands, has_memory=False,
                     has_calls=False, has_branches=False, has_pointers=False,
                     floating_point=False):
    """Check declared fixture constraints, not liveness analysis of real IR."""
    return (operations == ("add", "multiply_runtime") and flags_dead is True
            and not any((has_memory, has_calls, has_branches, has_pointers, floating_point))
            and len(set(scratch)) == len(scratch)
            and not set(scratch).intersection(operands))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalized_bodies(path):
    bodies = {}
    name = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("define "):
            if name is not None or "@" not in line or "(" not in line.split("@", 1)[1]:
                raise ValueError("malformed LLVM function header")
            name = line.split("@", 1)[1].split("(", 1)[0]
            if not name or name in bodies:
                raise ValueError("duplicate or empty LLVM function name")
            bodies[name] = []
        elif name is not None and line.strip() == "}":
            name = None
        elif name is not None and line.strip() and not line.lstrip().startswith(";"):
            bodies[name].append(line.strip())
    if name is not None:
        raise ValueError("unterminated LLVM function")
    if set(bodies) != {"plain", "immediate_pair", "encoded_region"} or any(not body for body in bodies.values()):
        raise ValueError("expected three non-empty LLVM function bodies")
    return bodies


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    llvm = args.output / "normalized.ll"
    command = ["clang-18", "-O1", "-S", "-emit-llvm", str(SOURCE), "-o", str(llvm)]
    bodies = {}
    version = None
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if process.returncode != 0:
            raise ValueError("clang normalization failed: " + process.stderr.strip())
        version_process = subprocess.run(["clang-18", "--version"], capture_output=True, text=True, timeout=10)
        versions = version_process.stdout.splitlines()
        if version_process.returncode != 0 or not versions or not versions[0].strip():
            raise ValueError("clang version unavailable: " + version_process.stderr.strip())
        version = versions[0]
        bodies = normalized_bodies(llvm)
        status, detail = "pass", process.stderr
    except FileNotFoundError as exc:
        status, detail = ("unavailable" if exc.filename == "clang-18" else "error"), str(exc)
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired) as exc:
        status, detail = "error", str(exc)
    equivalent = (set(bodies) == {"plain", "immediate_pair", "encoded_region"}
                  and bodies["plain"] == bodies["immediate_pair"] == bodies["encoded_region"])
    result = {"scope": "C source fixture, wrapping u64 arithmetic, no IR or native protector integration",
              "candidate": "E(x)=x+k; E(x+b)=E(x)+b; E(a*x)=a*E(x)+(1-a)*k",
              "source_sha256": digest(SOURCE), "script_sha256": digest(Path(__file__)),
              "clang_version": version, "command": command, "normalization_status": status,
              "detail": detail, "llvm_sha256": digest(llvm) if status == "pass" else None,
              "bodies": bodies, "all_equal": equivalent,
              "decision": "REJECT" if equivalent else "INCONCLUSIVE"}
    (args.output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return 0 if status == "pass" and len(bodies) == 3 else 1


if __name__ == "__main__":
    raise SystemExit(main())
