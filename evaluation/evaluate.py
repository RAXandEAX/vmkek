#!/usr/bin/env python3
"""R04 driver for the repository's owned synthetic fixture corpus."""

import argparse
import hashlib
import itertools
import json
import os
import platform
import random
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

import owned_scope

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOURCE = HERE / "fixtures.c"
PROTECTOR = ROOT / "target/release/vmkek"
HELPER = ROOT / "tools/elf-auth-helper/target/x86_64-unknown-linux-gnu/release/vmkek-elf-auth-helper"
CATALOG = json.loads((HERE / "catalog.json").read_text())
TRAIN = tuple(name for family in CATALOG["families"].values() for name in family[:2])
HOLDOUT = tuple(family[2] for family in CATALOG["families"].values())
MASK = (1 << 64) - 1
APP = "0102030405060708090a0b0c0d0e0f10"
TOOLS = ("cc", "clang-18", "llvm-dis-18", "opt-18", "klee", "frama-c")


def digest(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def digest_json(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def load_json(path):
    with path.open("rb") as handle:
        data = handle.read(1024 * 1024 + 1)
    if len(data) > 1024 * 1024:
        raise ValueError("evaluation JSON exceeds 1 MiB")
    return json.loads(data)


def command(argv, *, timeout=60, data=None):
    return subprocess.run(argv, input=data, text=True, capture_output=True, timeout=timeout, check=False)


def version(tool):
    path = shutil.which(tool)
    if path is None:
        return {"status": "not_run", "reason": "executable unavailable"}
    argv = [path, "--version"]
    try:
        result = command(argv, timeout=10)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "path": path, "command": argv}
    except OSError as error:
        return {"status": "error", "path": path, "command": argv, "reason": str(error)}
    text = result.stdout.splitlines() or result.stderr.splitlines()
    if result.returncode or not text:
        return {"status": "error", "path": path, "command": [path, "--version"],
                "exit_code": result.returncode, "stdout": result.stdout, "stderr": result.stderr}
    return {"status": "available", "path": path, "version": text[0]}


def budget_probe():
    if not shutil.which("systemd-run"):
        return {"status": "not_run", "reason": "systemd-run unavailable"}
    memory = CATALOG["memory_bytes"]
    script = (
        "from pathlib import Path; "
        "group = Path('/proc/self/cgroup').read_text().partition('::')[2].strip(); "
        "print((Path('/sys/fs/cgroup') / group.lstrip('/') / 'memory.max').read_text().strip())"
    )
    argv = [
        "systemd-run", "--user", "--scope", "--quiet", f"--property=MemoryMax={memory}",
        "--", "/usr/bin/python3", "-c", script,
    ]
    try:
        probe = command(argv, timeout=10)
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "command": argv}
    return {
        "status": "pass" if probe.returncode == 0 and probe.stdout.strip() == str(memory) else "error",
        "command": argv, "exit_code": probe.returncode,
        "stdout": probe.stdout, "stderr": probe.stderr,
    }


def doctor():
    return {
        "host": platform.uname()._asdict(),
        "tools": {tool: version(tool) for tool in TOOLS},
        "aggregate_memory_probe": budget_probe(),
        "bounded_external_job_gate": "not_run",
    }


def public_cases():
    pattern = tuple(range(16))
    reverse = tuple(reversed(pattern))
    return [
        (0, 0, 0, 0, pattern),
        (1, 2, 3, 1, (ord("a"),) + pattern[1:]),
        (MASK, 1, MASK, 2, reverse),
        (3, 9, 17, 15, pattern),
        (2, 1, 99, 16, reverse),
        (0x12345678, 0xFEDCBA98, 11, 16, (255,) * 16),
    ]


def private_pack(path):
    data = load_json(path)
    if type(data) is not dict or set(data) != {"parameters", "vector_seed"}:
        raise ValueError("expected private parameters and vector_seed")
    values = data["parameters"]
    if type(values) is not list or len(values) != len(HOLDOUT):
        raise ValueError("expected one private parameter per family")
    if any(type(value) is not int or not 0 <= value <= 255 for value in values):
        raise ValueError("private parameters must be bytes")
    seed = data["vector_seed"]
    if type(seed) is not int or not 0 <= seed <= MASK:
        raise ValueError("private vector seed must be u64")
    return data


def held_cases(seed, parameters):
    rng = random.Random(seed)
    random_cases = [
        (rng.getrandbits(64), rng.getrandbits(64), rng.getrandbits(64), size,
         tuple(rng.randrange(256) for _ in range(16)))
        for size in list(range(17)) * 4
    ]
    threshold = parameters[1]
    nearby = [(a, 257, 0, 0, (0,) * 16) for a in (max(0, threshold - 1), threshold, threshold + 1)]
    tlv = [(0, 0, 0, 3, (7, length, 255) + (0,) * 13) for length in (1, 2)]
    return public_cases() + random_cases + nearby + tlv


def result(value, state, buffer, effects=(), status=0):
    return {
        "status": status, "value": value & MASK, "state": state & MASK,
        "buffer": bytes(buffer).hex(), "canaries": [165, 90],
        "effect_count": len(effects), "effects": list(effects),
    }


def oracle(name, case, parameters=()):
    a, b, state, n, buffer = case
    if name in ("xor_copy", "masked_add", "in_place_swap"):
        out = list(buffer)
        if name == "in_place_swap":
            count = n // 2
            for index in range(count):
                opposite = n - index - 1
                out[index], out[opposite] = buffer[opposite] ^ parameters[4], buffer[index] ^ parameters[4]
        else:
            for index in range(n):
                out[index] = buffer[index] ^ (a & 255) if name == "xor_copy" else (buffer[index] + b) & 255
        return result(n, state, out)
    if name in ("counter", "rolling_state", "finite_state_machine"):
        changes = {
            "counter": lambda: state + a,
            "rolling_state": lambda: (state * 17 + a) ^ b,
            "finite_state_machine": lambda: (state + (a & 1) + parameters[6]) & 3,
        }
        new_state = changes[name]() & MASK
        return result(new_state, new_state, buffer)
    if name in ("two_helpers", "conditional_helper", "callback_sequence"):
        if name == "conditional_helper":
            effects = [((a + 7) if a < b else (b ^ 12)) & MASK]
        else:
            first = (a + 7 + (parameters[7] if name == "callback_sequence" else 0)) & MASK
            effects = [first, (first ^ (b if name == "callback_sequence" else 0)) ^ 12]
        return result(effects[-1], state, buffer, effects)
    if name in ("bounded_u16le", "hex_digit", "bounded_tlv"):
        if name == "bounded_u16le":
            value = int.from_bytes(bytes(buffer[:2]), "little") if n >= 2 else None
        elif name == "bounded_tlv":
            value = ((buffer[0] ^ parameters[5]) << 8) | buffer[1] if n >= 2 and buffer[1] <= n - 2 else None
        else:
            value = "0123456789abcdef".find(chr(buffer[0])) if n else -1
            if value == -1:
                value = None
        return result(value or 0, state, buffer, status=int(value is None))
    if name == "rolling_checksum":
        value = a
        for byte in buffer[:n]:
            value = (value * 33 + byte) & MASK
        return result(value, state, buffer)
    rotate = (a + b) & MASK
    values = {
        "affine_xor": lambda: (a * 7 + 3) ^ b,
        "add_rotate": lambda: (rotate << 9) | (rotate >> 55),
        "lane_sum": lambda: (a & 65535) + (b >> 48) + parameters[0],
        "clamp": lambda: min(a, b),
        "parity_band": lambda: (a & 1) if a < b else a ^ b,
        "threshold_pair": lambda: b if a < parameters[1] else abs(a - b),
        "bounded_sum": lambda: sum(buffer[:n]),
        "count_transitions": lambda: sum((x ^ y) > parameters[2] for x, y in itertools.pairwise(buffer[:n])),
        "lookup4": lambda: (7, 3, 11, 4)[a & 3],
        "lookup16": lambda: (5, 3, 0, 1, 7, 9, 2, 6, 8, 4, 15, 14, 13, 10, 11, 12)[a & 15] ^ b,
        "table_classify": lambda: (2, 0, 6, 3, 5, 1, 7, 4)[(a ^ parameters[3]) & 7],
    }
    return result(values[name](), state, buffer)


def observed(path, name, case):
    a, b, state, n, buffer = case
    data = " ".join(map(str, (a, b, state, n, *buffer))) + "\n"
    run = command([path, name], timeout=5, data=data)
    if run.returncode:
        raise ValueError(f"fixture process exit {run.returncode}: {run.stderr[:300]}")
    return json.loads(run.stdout)


def build_original(path, parameters, fixture=None):
    flags = ["-DR04_HOLDOUT"] if parameters else []
    if fixture is not None:
        if fixture not in TRAIN + HOLDOUT:
            raise ValueError("unknown fixture")
        flags.extend([f"-DR04_ONLY={fixture}", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections"])
    with tempfile.TemporaryDirectory(prefix="r04-private-compiler-") as temporary:
        private_header = Path(temporary) / "parameters.h"
        if parameters:
            active = set(range(len(HOLDOUT))) if fixture is None else {HOLDOUT.index(fixture)}
            private_header.write_text("".join(
                f"#define R04_P{i} {value if i in active else 1}\n"
                for i, value in enumerate(parameters)
            ))
            flags.extend(["-include", private_header])
        argv = [
            "cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O1", "-fno-pie", "-no-pie",
            "-fno-plt", "-fcf-protection=none", "-nostartfiles",
            f"-Wl,--build-id=none,--hash-style=sysv,-T,{HERE / 'fixtures.ld'}",
            *flags, HERE / "start.S", SOURCE, "-o", path,
        ]
        built = command(argv)
        if built.returncode:
            reason = f"exit {built.returncode}" if parameters else built.stderr[:600]
            raise ValueError(f"fixture compilation failed: {reason}")
    return ["<private-parameters>" if item == private_header else str(item) for item in argv]


def new_output(path):
    path = path.resolve()
    if path.is_relative_to(ROOT):
        raise ValueError("generated evidence belongs outside the source checkout")
    path.mkdir(mode=0o700, parents=True, exist_ok=False)
    return path


def protect_one(source, output, name, seed, signer, pin):
    return command([
        PROTECTOR, "protect", source, "-o", output, "--virtualize", name, "--seed", str(seed),
        "--authenticated-lab", "--elf-auth-helper", HELPER, "--manufacturer-signing-key",
        signer, "--manufacturer-public-key", pin, "--application-id", APP,
    ])


def compare(path, name, cases, parameters, *, workers=1):
    def checked(item):
        index, case = item
        actual = observed(path, name, case)
        if canonical(actual) != canonical(oracle(name, case, parameters)):
            raise ValueError(f"semantic mismatch at case {index}")
        return actual

    indexed = enumerate(cases)
    if workers == 1:
        return digest_json([checked(item) for item in indexed])
    if workers != 2:
        raise ValueError("oracle workers must be 1 or 2")
    observations = {}
    with ThreadPoolExecutor(max_workers=workers) as pool:
        pending = {}
        try:
            while True:
                for item in itertools.islice(indexed, workers - len(pending)):
                    pending[pool.submit(checked, item)] = item[0]
                if not pending:
                    break
                wait(pending, return_when=FIRST_COMPLETED)
                done = [job for job in pending if job.done()]
                if any(job.exception() is not None for job in done):
                    for job in pending:
                        job.cancel()
                    # Running processes keep their per-vector timeout. Report the
                    # earliest failed ordinal already admitted, regardless of order.
                    for job in sorted(pending, key=pending.__getitem__):
                        if not job.cancelled():
                            job.result()
                for job in done:
                    observations[pending.pop(job)] = job.result()
        finally:
            for job in pending:
                job.cancel()
    return digest_json([observations[index] for index in sorted(observations)])


def protected_receipt(path, fixture):
    report_path = Path(f"{path}.report.json")
    report = load_json(report_path)
    sha256 = digest(path)
    selected = [item["name"] for item in report.get("virtualized", [])]
    if (report.get("report_version") != 2 or report.get("profile") != "lab"
            or report.get("artifact_sha256") != sha256 or selected != [fixture]
            or "authenticated-bootstrap" not in report.get("passes", [])):
        raise ValueError("protected report does not match the selected Lab artifact")
    return sha256, digest(report_path)


def publish_json(path, value):
    with tempfile.TemporaryDirectory(prefix=".pending-", dir=path.parent) as temporary:
        staged = Path(temporary) / path.name
        staged.write_text(json.dumps(value, indent=2) + "\n")
        staged.replace(path)


def save_baseline_progress(path, manifest):
    control_fields = ("fixture", "cases", "status", "original_sha256", "observations_sha256")
    row_fields = control_fields + ("seed", "profile", "artifact_sha256", "report_sha256", "exit_code")
    provenance = (
        "version", "checkout_head", "catalog_sha256", "fixtures_sha256",
        "linker_script_sha256", "startup_sha256", "holdout_pack_sha256",
        "public_pin_sha256", "protector_sha256", "helper_sha256", "oracle_workers",
    )
    progress = {key: manifest[key] for key in provenance}
    progress.update(
        complete=False,
        controls=[{key: row[key] for key in control_fields} for row in manifest["controls"]],
        rows=[{key: row[key] for key in row_fields if key in row} for row in manifest["rows"]],
    )
    publish_json(path, progress)


def build_baselines(args):
    if args.affine_probe:
        raise ValueError("--affine-probe is retired; build a baseline and use evaluation/affine_cells.py for per-cell measurements")
    selected = tuple(dict.fromkeys(args.fixture))
    pack = private_pack(args.holdout) if args.holdout else None
    if any(name in HOLDOUT for name in selected) and pack is None:
        raise ValueError("holdout fixtures require the evaluator's private pack")
    parameters = pack["parameters"] if pack else []
    cases = held_cases(pack["vector_seed"], parameters) if pack else public_cases()
    output = new_output(args.output)
    progress = output / "baseline-progress.json"
    manifest = {
        "version": 1, "host": platform.uname()._asdict(),
        "checkout_head": command(["git", "-C", ROOT, "rev-parse", "HEAD"]).stdout.strip(),
        "catalog_sha256": digest(HERE / "catalog.json"),
        "fixtures_sha256": digest(SOURCE),
        "linker_script_sha256": digest(HERE / "fixtures.ld"),
        "startup_sha256": digest(HERE / "start.S"),
        "compiler": version("cc"),
        "controls": [], "rows": [],
        "oracle_workers": args.oracle_workers,
        "holdout_pack_sha256": digest_json(pack) if pack else None,
        "public_pin_sha256": digest(args.pin),
        "protector_sha256": digest(PROTECTOR),
        "helper_sha256": digest(HELPER),
    }
    for name in selected:
        original = output / f"{name}-original.elf"
        compiler_argv = build_original(original, parameters if name in HOLDOUT else [], name)
        original_hash = digest(original)
        selected_cases = cases if name in HOLDOUT else public_cases()
        observations = compare(original, name, selected_cases, parameters,
                               workers=args.oracle_workers)
        manifest["controls"].append({
            "fixture": name, "cases": len(selected_cases), "status": "pass",
            "observations_sha256": observations, "original_sha256": original_hash,
            "compiler_command": compiler_argv,
        })
        save_baseline_progress(progress, manifest)
        for seed in CATALOG["seeds"]:
            target = output / f"{name}-{seed}.elf"
            row = {"fixture": name, "seed": seed, "profile": "elf-authenticated-lab",
                   "original_sha256": original_hash}
            try:
                protected = protect_one(original, target, name, seed, args.signer, args.pin)
                if protected.returncode:
                    reason = protected.stderr.strip()[:400]
                    unsupported = (
                        "unsupported" in reason.lower() or reason == "runtime does not fit in the payload"
                    )
                    row.update(status="unsupported" if unsupported else "error",
                               reason=reason, exit_code=protected.returncode)
                else:
                    target.chmod(0o700)
                    artifact, report = protected_receipt(target, name)
                    row.update(artifact_sha256=artifact, report_sha256=report)
                    observations = compare(target, name, selected_cases, parameters,
                                           workers=args.oracle_workers)
                    row.update(status="pass", cases=len(selected_cases), observations_sha256=observations)
            except subprocess.TimeoutExpired:
                row.update(status="timeout")
            except ScopeFailure as error:
                row.update(status=error.status, reason=str(error))
            except (OSError, ValueError) as error:
                row.update(status="error", reason=str(error))
            manifest["rows"].append(row)
            save_baseline_progress(progress, manifest)
    manifest["run_config_sha256"] = baseline_config_digest(manifest, selected)
    publish_json(output / "baseline.json", manifest)
    progress.unlink()
    print(json.dumps({"output": str(output), "rows": len(manifest["rows"]),
                      "passing": sum(row["status"] == "pass" for row in manifest["rows"])}))
    return 0 if any(row["status"] == "pass" for row in manifest["rows"]) else 1


def fit_affine(observations):
    zero, one = observations[:2]
    if (zero[0], one[0]) != (0, 1):
        raise ValueError("missing affine calibration coordinates")
    offset = zero[2] ^ zero[1]
    multiplier = ((one[2] ^ one[1]) - offset) & MASK
    model = (multiplier, offset)
    if any((((a * multiplier + offset) & MASK) ^ b) != value for a, b, value in observations):
        raise ValueError("public observations do not fit the declared affine hypothesis")
    return model


def learn_affine(artifact):
    observations = []
    for case in public_cases():
        value = observed(artifact, "affine_xor", case)["value"]
        observations.append((case[0], case[1], value))
    return fit_affine(observations), digest_json(observations)


def predict_affine(model, case):
    a, b, state, _, buffer = case
    multiplier, offset = model
    return result(((a * multiplier + offset) & MASK) ^ b, state, buffer)


def score_affine(model, cases, expected):
    candidate = HERE / "affine_candidate.py"
    run = owned_scope.run(
        ["/usr/bin/python3", "-B", str(candidate)], budget=60,
        input_data=json.dumps({"model": model, "cases": cases}).encode(),
        isolate_file=str(candidate),
    )
    if run["status"] == "timeout":
        raise subprocess.TimeoutExpired(run["command"], 60)
    if run["status"] in ("unsupported", "oom"):
        raise ScopeFailure(run["status"], run.get("reason", run.get("systemd_result", "")))
    if run["status"] != "pass":
        raise ValueError(f"affine candidate failed: {run.get('stderr', run.get('reason', ''))}")
    predicted = json.loads(run["stdout"])
    if not isinstance(predicted, list) or any(not isinstance(item, dict) for item in predicted):
        raise ValueError("affine candidate output must be a list of observations")
    mismatches = sum(canonical(left) != canonical(right) for left, right in zip(predicted, expected, strict=True))
    return {
        "status": "hypothesis_match" if not mismatches else "mismatch",
        "candidate_sha256": digest(candidate), "model_sha256": digest_json(model), "hidden_cases": len(cases),
        "runner_sha256": digest(HERE / "owned_scope.py"),
        "hidden_oracle_sha256": digest_json(expected), "mismatches": mismatches,
        "candidate_scope": {key: run[key] for key in ("budget_seconds", "memory_limit_bytes",
                                                       "memory_peak", "elapsed_seconds", "systemd_result")},
        "filesystem_restriction": "landlock-usr-candidate",
    }


class ScopeFailure(Exception):
    def __init__(self, status, reason):
        self.status = status
        super().__init__(reason)


def fresh_affine(artifact, cases, expected):
    start = time.monotonic()
    try:
        model, receipt = learn_affine(artifact)
        return model, dict(score_affine(model, cases, expected), public_observations_sha256=receipt,
                           target_queries=len(public_cases()), elapsed_seconds=time.monotonic() - start)
    except subprocess.TimeoutExpired:
        status = {"status": "timeout"}
    except ScopeFailure as error:
        status = {"status": error.status, "reason": str(error)}
    except (OSError, ValueError) as error:
        status = {"status": "error", "reason": str(error)}
    return None, dict(status, elapsed_seconds=time.monotonic() - start)


def baseline_config_digest(manifest, fixtures):
    inputs = (
        "catalog_sha256", "fixtures_sha256", "linker_script_sha256", "startup_sha256",
        "compiler", "holdout_pack_sha256", "protector_sha256", "helper_sha256",
    )
    return digest_json({
        "fixtures": fixtures, "seeds": CATALOG["seeds"], "profile": "elf-authenticated-lab",
        "original_sha256": [row["original_sha256"] for row in manifest["controls"]],
        "inputs": {name: manifest[name] for name in inputs},
    })


def is_sha256(value):
    return isinstance(value, str) and len(value) == 64 and all(
        digit in "0123456789abcdef" for digit in value
    )


def read_baseline(path):
    baseline = load_json(path)
    if (type(baseline) is not dict or baseline.get("version") != 1
            or baseline.get("complete", True) is not True
            or not is_sha256(baseline.get("run_config_sha256"))
            or type(baseline.get("rows")) is not list):
        raise ValueError("invalid baseline manifest")
    workers = baseline.get("oracle_workers", 1)
    if type(workers) is not int or workers not in (1, 2):
        raise ValueError("invalid baseline oracle worker count")
    identities = set()
    for row in baseline["rows"]:
        if type(row) is not dict:
            raise ValueError("invalid baseline row")
        fixture, seed = row.get("fixture"), row.get("seed")
        status = row.get("status")
        if (fixture not in TRAIN + HOLDOUT or seed not in CATALOG["seeds"]
                or status not in ("pass", "unsupported", "error", "timeout")
                or row.get("profile") != "elf-authenticated-lab"):
            raise ValueError("invalid baseline row")
        if (fixture, seed) in identities:
            raise ValueError("duplicate baseline fixture and seed")
        identities.add((fixture, seed))
        if status == "pass" and not is_sha256(row.get("artifact_sha256")):
            raise ValueError("passing baseline row requires an artifact digest")
    return baseline


def planned_rows(fixtures, baseline=None):
    seeds = CATALOG["seeds"]
    records = {} if baseline is None else {
        (row["fixture"], row["seed"]): row for row in baseline["rows"]
    }
    for name, budget, seed_index, adapter in itertools.product(
        fixtures, CATALOG["wall_seconds"], range(len(seeds)), ("symbolic", "taint", "slicing")
    ):
        target = seeds[seed_index]
        for mode, source in (("fresh", None), ("transfer", seeds[seed_index - 1])):
            target_record = records.get((name, target), {})
            donor = records.get((name, source), {})
            reason = "no reviewed protected-image evidence"
            if target_record and target_record.get("status") != "pass":
                reason = f"protected baseline {target_record['status']}"
            elif mode == "transfer" and records and donor.get("status") != "pass":
                reason = "preregistered donor unavailable"
            yield {
                "version": 1, "fixture": name, "platform": "elf-x86_64",
                "profile": "elf-authenticated-lab", "mode": mode, "adapter": adapter,
                "source_seed": source, "target_seed": target, "wall_seconds": budget,
                "memory_bytes": CATALOG["memory_bytes"], "status": "not_run",
                "reason": reason,
                "artifact_sha256": target_record.get("artifact_sha256"),
                "donor_sha256": donor.get("artifact_sha256"),
                "baseline_config_sha256": baseline.get("run_config_sha256") if baseline else None,
                "tool_version": None,
                "command": None, "exit_code": None, "elapsed_seconds": None,
                "memory_peak_bytes": None, "candidate_sha256": None, "oracle_sha256": None,
            }


def grade(name, candidate, pack):
    held = name in HOLDOUT
    if held and pack is None:
        raise ValueError("holdout grading requires the evaluator's private pack")
    params = pack["parameters"] if held else []
    cases = held_cases(pack["vector_seed"], params) if held else public_cases()
    expected = {f"case-{index:03}": oracle(name, case, params) for index, case in enumerate(cases)}
    if type(candidate) is not dict or set(candidate) != set(expected):
        return {"status": "error", "reason": "candidate case IDs do not match the grader"}
    mismatches = sum(canonical(candidate[key]) != canonical(observation) for key, observation in expected.items())
    # Observations can be copied from a target. Independent candidate execution and
    # provenance are an external gate before any empirical recovered claim.
    return {"status": "mismatch" if mismatches else "matched_observations",
            "cases": len(expected), "mismatches": mismatches,
            "oracle_sha256": digest_json(expected), "candidate_sha256": digest_json(candidate)}


def matching_dfsan_runs(executed, expected):
    matches = 0
    for run in executed:
        try:
            if run["exit_code"] == 0 and json.loads(run["stdout"]) == expected:
                matches += 1
        except json.JSONDecodeError:
            continue
    return matches


def normalized_listing(listing):
    try:
        text = listing.read_text().splitlines()
    except (OSError, UnicodeError):
        return None
    if len(text) < 2 or not text[0].startswith("; ModuleID = ") or not text[1].startswith("source_filename = "):
        return None
    text[:2] = ["; ModuleID = 'r04-fixtures'", 'source_filename = "fixtures.c"']
    return "\n".join(text) + "\n"


def run_controls(output):
    output = new_output(output)
    checks = []
    for name, commands, expected in [
        ("llvm-normalization", [
            ["clang-18", "-O1", "-emit-llvm", "-c", SOURCE, "-o", output / "fixtures.bc"],
            ["llvm-dis-18", output / "fixtures.bc", "-o", output / "fixtures.ll"],
        ], None),
        ("z3-bitvector-control", [
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", HERE / "symbolic.c", "-lz3",
             "-o", output / "symbolic"],
            [output / "symbolic"],
        ], None),
        ("llvm-adce-projection", [
            ["opt-18", "-passes=adce", "-S", HERE / "slicing.ll", "-o", output / "sliced.ll"],
        ], None),
        ("dfsan", [
            ["clang-18", "-O1", "-fno-pie", "-no-pie", "-fsanitize=dataflow", "-DR04_DFSAN",
             SOURCE, "-o", output / "dfsan"],
            *[[output / "dfsan"] for _ in range(8)],
        ], {"value": 17, "label": 3}),
    ]:
        row = {"adapter": name, "scope": "owned source control", "status": "pass", "commands": []}
        for argv in commands:
            if isinstance(argv[0], str) and not shutil.which(argv[0]):
                row.update(status="not_run", reason="executable unavailable")
                break
            try:
                run = command(argv)
            except subprocess.TimeoutExpired:
                row.update(status="timeout")
                break
            except OSError as error:
                row["commands"].append({
                    "argv": [str(arg) for arg in argv], "exit_code": None, "error": str(error),
                })
                row.update(status="error", reason="control command could not start")
                break
            row["commands"].append({"argv": [str(arg) for arg in argv], "exit_code": run.returncode,
                                    "stdout": run.stdout, "stderr": run.stderr})
            if run.returncode:
                row.update(status="error", reason="control command failed")
                if name != "dfsan" or len(row["commands"]) == 1:
                    break
        if expected is not None:
            executed = row["commands"][1:]
            matching = matching_dfsan_runs(executed, expected)
            row.update(calibration_runs=len(executed), matching_runs=matching)
            if matching != 8 and row["status"] == "pass":
                row.update(status="error", reason="taint/value calibration mismatch")
        if name == "llvm-normalization" and row["status"] == "pass":
            listing = output / "fixtures.ll"
            text = normalized_listing(listing)
            if text is None:
                row.update(status="error", reason="unexpected LLVM source listing")
            else:
                listing.write_text(text)
                row["artifact_sha256"] = digest(listing)
        if name == "llvm-adce-projection" and row["status"] == "pass":
            listing = output / "sliced.ll"
            try:
                text = listing.read_text()
            except (OSError, UnicodeError) as error:
                row.update(status="error", reason=f"unreadable LLVM projection: {error}")
            else:
                if "%unused" in text or "store i64 %observed" not in text or "ret i64 %observed" not in text:
                    row.update(status="error", reason="LLVM liveness control mismatch")
                else:
                    row["artifact_sha256"] = digest(listing)
        checks.append(row)
    for name, tool in [("symbolic", "klee"), ("slicing", "frama-c")]:
        found = version(tool)
        checks.append({"adapter": name, "scope": "owned source control", "status": "not_run",
                       "tool": found, "reason": found.get("reason", "external fixture execution unverified")})
    (output / "controls.json").write_text(json.dumps(checks, indent=2) + "\n")
    print(json.dumps({item["adapter"]: item["status"] for item in checks}))
    return 0 if all(item["status"] in {"pass", "not_run"} for item in checks) else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    sub.add_parser("doctor")
    build = sub.add_parser("build")
    build.add_argument("--fixture", choices=TRAIN + HOLDOUT, action="append", required=True)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--signer", required=True, type=Path)
    build.add_argument("--pin", required=True, type=Path)
    build.add_argument("--holdout", type=Path)
    build.add_argument("--affine-probe", action="store_true")
    build.add_argument("--oracle-workers", type=int, choices=(1, 2), default=1,
                       help="maximum simultaneous owned fixture processes during oracle comparison")
    controls = sub.add_parser("controls")
    controls.add_argument("--output", required=True, type=Path)
    plan = sub.add_parser("plan")
    plan.add_argument("--fixture", choices=TRAIN + HOLDOUT, action="append")
    plan.add_argument("--baseline", type=Path)
    grade_parser = sub.add_parser("grade")
    grade_parser.add_argument("--fixture", choices=TRAIN + HOLDOUT, required=True)
    grade_parser.add_argument("--candidate", type=Path, required=True)
    grade_parser.add_argument("--holdout", type=Path)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        if args.operation == "build":
            return build_baselines(args)
        if args.operation == "controls":
            return run_controls(args.output)
        if args.operation == "doctor":
            print(json.dumps(doctor(), indent=2))
        elif args.operation == "plan":
            baseline = read_baseline(args.baseline) if args.baseline else None
            for row in planned_rows(args.fixture or TRAIN + HOLDOUT, baseline):
                print(json.dumps(row))
        elif args.operation == "grade":
            pack = private_pack(args.holdout) if args.holdout else None
            if args.fixture in HOLDOUT and pack is None:
                raise ValueError("holdout grading requires the evaluator's private pack")
            result = grade(args.fixture, load_json(args.candidate), pack)
            print(json.dumps(result))
            return 0 if result["status"] == "matched_observations" else 1
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(2, f"evaluation: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
