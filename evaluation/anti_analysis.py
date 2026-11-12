#!/usr/bin/env python3
"""Validate bounded evidence from the owned A09 Lab fixture.

The manifest is data. This evaluator never launches a manifest command. It
compares recorded ABI responses with a private arithmetic corpus.
"""

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

PROFILES = {
    "baseline": (),
    "observe": ("DebuggerAttachment", "CodeIntegrity"),
    "enforce": ("DebuggerAttachment", "CodeIntegrity"),
    "debugger-only": ("DebuggerAttachment",),
    "integrity-only": ("CodeIntegrity",),
}
SEED_COUNT = 10
CASE_COUNT = 128
MAX_JSON = 4 * 1024 * 1024
MAX_RAW = 64 * 1024
MAX_BINARY = 64 * 1024 * 1024
U64_MASK = (1 << 64) - 1
SHA = r"[0-9a-f]{64}"
FIXTURE = re.compile(rf"fixture seed=(\d+) profile=([a-z-]+) bytecode_sha256=({SHA}) input_sha256=({SHA}) ready_ns=(\d+)")
POLICY = re.compile(rf"policy sha256=({SHA}|none) epoch=(\d+)")
SAMPLE = re.compile(r"sample kind=(\w+) finding=(\w+) reason=(\w+)")
RESULT = re.compile(r"result index=(\d+) status=(\d+) bits=(\d+) ns=(\d+) metadata=(true|false)")
ARTIFACT = re.compile(r"artifact descriptor=([0-9a-f]{2,4096}) program=([0-9a-f]{2,4096})")
DONE = re.compile(r"done cpu_ns=(\d+) private_bytes=(\d+)")
MISSING_EXTERNAL = ("first_attempt", "transfer", "external_result_oracle", "client_data")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def unique_pairs(pairs):
    obj = {}
    for name, value in pairs:
        require(name not in obj, f"duplicate JSON key {name}")
        obj[name] = value
    return obj


def json_data(data):
    def invalid_constant(value):
        raise ValueError(f"non-finite JSON constant {value}")

    return json.loads(data, object_pairs_hook=unique_pairs, parse_constant=invalid_constant)


def bounded_bytes(path, limit):
    require(path.is_file(), f"missing evidence file {path.name}")
    with path.open("rb") as file:
        data = file.read(limit + 1)
    require(len(data) <= limit, f"evidence exceeds size limit: {path.name}")
    return data


def artifact(root, reference, limit):
    require(isinstance(reference, dict) and set(reference) == {"path", "sha256"}, "invalid artifact reference")
    name, sha = reference["path"], reference["sha256"]
    require(isinstance(name, str) and 0 < len(name) <= 200, "invalid artifact path")
    require(isinstance(sha, str) and re.fullmatch(SHA, sha), "invalid artifact SHA-256")
    parts = name.split("/")
    require(all(part not in ("", ".", "..") and "\\" not in part and ":" not in part for part in parts),
            "artifact path escapes evidence root")
    path = root
    for part in parts:
        path = path / part
        require(not path.is_symlink(), "artifact path contains a symlink")
    require(path.resolve().is_relative_to(root), "artifact path escapes evidence root")
    data = bounded_bytes(path, limit)
    require(hashlib.sha256(data).hexdigest() == sha, f"artifact digest mismatch: {name}")
    return data


def integer(value, low, high):
    return type(value) is int and low <= value <= high


def parse_corpus(data, seeds):
    corpus = json_data(data)
    require(isinstance(corpus, dict) and set(corpus) == {str(seed) for seed in seeds}, "corpus seed mismatch")
    for cases in corpus.values():
        require(isinstance(cases, list) and len(cases) == CASE_COUNT, "corpus size mismatch")
        require(all(isinstance(case, list) and len(case) == 2 and
                    all(integer(bits, 0, U64_MASK) for bits in case) for case in cases),
                "invalid corpus input")
        require(len(set(map(tuple, cases))) == CASE_COUNT, "duplicate corpus input")
    return corpus


def quantiles(values):
    ordered = sorted(values)
    count = len(ordered)
    return {"count": count, "p50": ordered[(count + 1) // 2 - 1],
            "p95": ordered[(95 * count + 99) // 100 - 1], "max": ordered[-1]}


def parse_header(lines, profile, seed):
    require(len(lines) == 4 + len(PROFILES[profile]) + CASE_COUNT, "fixture line count mismatch")
    policy = POLICY.fullmatch(lines[0])
    require(policy, "missing policy evidence")
    sha, epoch = policy.groups()
    require((sha == "none", int(epoch)) == ((True, 0) if profile == "baseline" else (False, 1)),
            "incorrect policy identity")
    samples = []
    for line in lines[1:1 + len(PROFILES[profile])]:
        sample = SAMPLE.fullmatch(line)
        require(sample, "malformed sample evidence")
        kind, finding, reason = sample.groups()
        require(finding in {"NotObservedWithinScope", "Observed", "SignedMismatch", "Inconclusive", "Unsupported"},
                "unknown observation finding")
        samples.append({"kind": kind, "finding": finding, "reason": reason})
    require(tuple(sample["kind"] for sample in samples) == PROFILES[profile], "wrong configured signals")
    fixture = FIXTURE.fullmatch(lines[1 + len(samples)])
    require(fixture and (int(fixture[1]), fixture[2]) == (seed, profile), "unpaired fixture output")
    return (None if sha == "none" else sha), int(epoch), samples, fixture[3], fixture[4], int(fixture[5])


def parse_run(data, profile, seed, inputs, wall_ns):
    lines = data.decode("ascii").splitlines()
    policy_sha, epoch, samples, bytecode_sha, input_sha, ready_ns = parse_header(lines, profile, seed)
    payload = "".join(f"{left} {right}\n" for left, right in inputs).encode("ascii")
    require(hashlib.sha256(payload).hexdigest() == input_sha, "fixture stdin digest mismatch")
    require(0 <= ready_ns <= wall_ns, "invalid activation duration")
    packed = ARTIFACT.fullmatch(lines[2 + len(samples)])
    require(packed, "missing fixture descriptor/program")
    descriptor, program = map(bytes.fromhex, packed.groups())
    require(hashlib.sha256(program).hexdigest() == bytecode_sha, "fixture bytecode digest mismatch")
    descriptor_sha = hashlib.sha256(descriptor).hexdigest()
    stop = DONE.fullmatch(lines[-1])
    require(stop, "missing fixture completion")
    cpu_ns, private_bytes = int(stop[1]), int(stop[2])
    require(cpu_ns <= min(U64_MASK, wall_ns + 20_000_000) and 0 < private_bytes <= U64_MASK,
            "invalid process resource counters")
    timings, outputs = [], []
    failures = Counter()
    for index, (line, (left, right)) in enumerate(zip(lines[3 + len(samples):-1], inputs, strict=True)):
        result = RESULT.fullmatch(line)
        require(result and int(result[1]) == index, "missing or reordered ABI response")
        status, bits, duration = map(int, result.groups()[1:4])
        require(0 <= status <= 12 and 0 <= bits <= U64_MASK and 0 <= duration <= wall_ns,
                "invalid ABI response")
        metadata = result[5] == "true"
        if not metadata:
            failures["metadata"] += 1
        if status != 0:
            failures["clean_refusal"] += 1
        elif bits != (left + right + seed) & U64_MASK:
            failures["wrong_result"] += 1
        timings.append(duration)
        outputs.append([status, bits, metadata])
    for sample in samples:
        if sample["finding"] in {"Observed", "SignedMismatch"}:
            failures["clean_false_positive"] += 1
        elif sample["finding"] != "NotObservedWithinScope" or sample["reason"] != "None":
            failures["clean_sample_unavailable"] += 1
    return {
        "status": "failed" if failures else "verified",
        "failures": dict(failures),
        "policy_sha256": policy_sha,
        "policy_epoch": epoch,
        "bytecode_sha256": bytecode_sha,
        "descriptor_sha256": descriptor_sha,
        "output_sha256": hashlib.sha256(json.dumps(outputs, separators=(",", ":")).encode()).hexdigest(),
        "input_sha256": input_sha,
        "samples": samples,
        "ready_ns": ready_ns,
        "invoke_ns": quantiles(timings),
        "cpu_ns": cpu_ns,
        "private_bytes": private_bytes,
    }


def process_row(root, row, corpus, binary_path):
    require(isinstance(row, dict), "invalid campaign row")
    profile, seed = row.get("profile"), row.get("seed")
    require(isinstance(profile, str) and profile in PROFILES and integer(seed, 1, 2**32 - 1)
            and str(seed) in corpus, "invalid row seed/profile")
    command = row.get("command")
    require(command == [binary_path, "--assessment", profile, str(seed)], "unexpected recorded command")
    status = row.get("status")
    require(status in ("recorded", "failed", "not-run"), "invalid recorded status")
    result = {"seed": seed, "profile": profile, "command": command}
    if status == "not-run":
        require(set(row) == {"seed", "profile", "command", "status", "reason"}
                and isinstance(row["reason"], str) and 0 < len(row["reason"]) <= 400, "invalid not-run row")
        return {**result, "status": status, "reason": row["reason"]}
    keys = {"seed", "profile", "command", "status", "exit_code", "wall_ns", "stdout", "stderr"}
    require(set(row) == keys, "invalid process record fields")
    exit_code = row["exit_code"]
    require((exit_code is None and status == "failed") or integer(exit_code, -2**31, 2**32 - 1),
            "invalid process exit code")
    require(integer(row["wall_ns"], 0, U64_MASK), "invalid process wall duration")
    stdout = artifact(root, row["stdout"], MAX_RAW)
    stderr = artifact(root, row["stderr"], MAX_RAW)
    result.update(exit_code=exit_code, wall_ns=row["wall_ns"], stdout=row["stdout"], stderr=row["stderr"])
    if status == "failed" or exit_code != 0 or stderr:
        return {**result, "status": "failed", "reason": "fixture process failed or emitted diagnostics"}
    try:
        return {**result, **parse_run(stdout, profile, seed, corpus[str(seed)], row["wall_ns"])}
    except ValueError as error:
        return {**result, "status": "failed", "reason": str(error)}


def budget_status(statistics, limit, complete):
    return {
        "limit_ns": limit,
        "profiles": {
            profile: "not-run" if not complete else "pass" if stats["p95"] <= limit else "failed"
            for profile, stats in statistics.items()
        },
    }


def compare(rows):
    paired = {}
    for row in rows:
        paired.setdefault(row["seed"], {})[row["profile"]] = row
    ready_deltas = {profile: [] for profile in PROFILES if profile != "baseline"}
    invocation = {profile: [] for profile in PROFILES}
    coverage = {profile: Counter() for profile in PROFILES}
    mismatched = []
    for seed, group in paired.items():
        baseline = group["baseline"]
        for profile, row in group.items():
            if row["status"] != "verified":
                continue
            invocation[profile].append(row["invoke_ns"]["p95"])
            coverage[profile].update(sample["kind"] for sample in row["samples"])
            if profile == "baseline" or baseline["status"] != "verified":
                continue
            if any(row[key] != baseline[key] for key in ("bytecode_sha256", "descriptor_sha256", "output_sha256")):
                mismatched.append({"seed": seed, "profile": profile})
                continue
            ready_deltas[profile].append(row["ready_ns"] - baseline["ready_ns"])
    baselines = [group["baseline"] for group in paired.values() if group["baseline"]["status"] == "verified"]
    distinct = {key: len({row[key] for row in baselines}) for key in ("bytecode_sha256", "descriptor_sha256")}
    reused_artifact = any(value != len(baselines) for value in distinct.values())
    ready = {profile: quantiles(values) for profile, values in ready_deltas.items() if values}
    latency = {profile: quantiles(values) for profile, values in invocation.items() if values}
    complete = all(row["status"] == "verified" for row in rows) and not mismatched and not reused_artifact
    return {
        "status": "verified" if complete else "failed" if mismatched or reused_artifact or any(
            row["status"] == "failed" for row in rows) else "not-run",
        "artifact_or_output_mismatches": mismatched,
        "distinct_baseline_artifacts": distinct,
        "clean_observation_coverage": {profile: dict(count) for profile, count in coverage.items()},
        "paired_ready_delta_ns": ready,
        "run_p95_invoke_ns": latency,
        "startup_budget": budget_status(ready, 50_000_000, complete),
        "invocation_budget": budget_status(latency, 100_000, complete),
        "steady_state_budget": "not-run",
        "detection_latency_budget": "not-run",
    }


def evaluate(manifest, root):
    fields = {"schema", "source_manifest", "binary", "corpus", "host", "tools", "seeds", "rows",
              "external_assessment"}
    require(isinstance(manifest, dict) and set(manifest) == fields and type(manifest["schema"]) is int
            and manifest["schema"] == 1, "invalid manifest schema")
    seeds = manifest["seeds"]
    require(isinstance(seeds, list) and len(seeds) == SEED_COUNT and
            all(integer(seed, 1, 2**32 - 1) for seed in seeds) and len(set(seeds)) == SEED_COUNT,
            "expected ten distinct nonzero u32 seeds")
    for kind, names in [("host", {"os", "build", "arch", "cpu"}), ("tools", {"rustc", "cargo", "msvc", "python"})]:
        values = manifest[kind]
        require(isinstance(values, dict) and set(values) == names and
                all(isinstance(value, str) and 0 < len(value) <= 400 for value in values.values()),
                f"missing {kind} provenance")
    require(manifest["host"]["os"] == "Windows" and manifest["host"]["arch"] == "x86_64",
            "unqualified fixture platform")
    external = manifest["external_assessment"]
    require(isinstance(external, dict) and set(external) == set(MISSING_EXTERNAL), "external assessment scope mismatch")
    for item in external.values():
        require(isinstance(item, dict) and set(item) == {"status", "reason"} and item["status"] == "not-run"
                and isinstance(item["reason"], str) and 0 < len(item["reason"]) <= 400,
                "external evidence requires independent qualification")
    artifact(root, manifest["source_manifest"], MAX_JSON)
    artifact(root, manifest["binary"], MAX_BINARY)
    corpus = parse_corpus(artifact(root, manifest["corpus"], MAX_JSON), seeds)
    records = manifest["rows"]
    require(isinstance(records, list) and len(records) == SEED_COUNT * len(PROFILES), "incomplete seed/profile grid")
    rows = [process_row(root, row, corpus, manifest["binary"]["path"]) for row in records]
    keys = {(row["seed"], row["profile"]) for row in rows}
    require(keys == {(seed, profile) for seed in seeds for profile in PROFILES}, "duplicate or missing seed/profile")
    results = compare(rows)
    return {
        "schema": 1,
        "source_manifest": manifest["source_manifest"],
        "binary": manifest["binary"],
        "corpus": manifest["corpus"],
        "host": manifest["host"],
        "tools": manifest["tools"],
        "benchmark": results,
        "rows": rows,
        "external_assessment": external,
        "resistance_gate": "not-run",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        require(not args.output.exists() and not args.output.is_symlink(), "output already exists")
        manifest = json_data(bounded_bytes(args.manifest, MAX_JSON))
        summary = evaluate(manifest, args.manifest.resolve().parent)
        args.output.mkdir()
        with (args.output / "summary.json").open("x", encoding="utf-8") as file:
            json.dump(summary, file, indent=2)
            file.write("\n")
        benchmark = summary["benchmark"]["status"]
        print(f"benchmark={benchmark} resistance_gate={summary['resistance_gate']} rows={len(summary['rows'])}")
        return 0 if benchmark == "verified" else 1
    except (OSError, ValueError, RecursionError) as error:
        print(f"invalid assessment evidence: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
