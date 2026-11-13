#!/usr/bin/env python3
"""Run native ELF pass ablations in a disposable research-only clone."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

BASE = "4cd330d0ba73b6a912506c3c83c2ee1331af262d"
VARIANTS = ("none", "rewrite", "data-mix", "block-split", "opaque", "bogus", "flatten", "shuffle")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(argv, **kwargs):
    return subprocess.run([str(x) for x in argv], check=True, **kwargs)


def replace_one(text, before, after):
    if text.count(before) != 1:
        raise ValueError("source seam must occur exactly once: " + before.splitlines()[0])
    return text.replace(before, after, 1)


def patch_source(path):
    text = path.read_text()
    old = text
    text = replace_one(text, "fn prepare(func: &FuncIr, rng: &mut ChaCha20Rng) -> (FuncIr, Vec<&'static str>) {\n    let (mut func, mut passes, _) = rewrite_ops(func, rng);", """fn omitted(pass: &str) -> bool {
    std::env::var("VMKEK_ECC_ABLATION").is_ok_and(|name| name == pass)
}

fn prepare(func: &FuncIr, rng: &mut ChaCha20Rng) -> (FuncIr, Vec<&'static str>) {
    let (mut func, mut passes, _) = if omitted("rewrite") {
        (func.clone(), Vec::new(), Vec::new())
    } else { rewrite_ops(func, rng) };""")
    for ident, call, pass_name in (("data-mix", "data_mix::apply(&func, rng)", "data-mix"),
                                   ("block-split", "split_blocks(&func)", "block-split"),
                                   ("opaque", "wrap_opaque(&func, rng)", "opaque-predicate"),
                                   ("bogus", "add_bogus(&func, rng)", "bogus-control-flow")):
        before = f'    func = {call};\n    passes.push("{pass_name}");'
        after = f'    if !omitted("{ident}") {{ func = {call}; passes.push("{pass_name}"); }}'
        if text.count(before) != 1:
            raise ValueError(f"cannot locate {ident} seam")
        text = replace_one(text, before, after)
    text = replace_one(text, '    passes.push("template-diversity");', '    if !omitted("rewrite") { passes.push("template-diversity"); }')
    text = replace_one(text, '    Ok(finish(flatten_balanced(&func)?, passes, rng))',
                        '    if omitted("flatten") { Ok(finish(func, passes, rng)) } else { Ok(finish(flatten_balanced(&func)?, passes, rng)) }')
    text = replace_one(text, '    passes.push("control-flow-flatten");\n    passes.push("block-shuffle");\n    Obfuscated {\n        func: shuffle(&func, rng),',
                        '    if !omitted("flatten") { passes.push("control-flow-flatten"); }\n    if !omitted("shuffle") { passes.push("block-shuffle"); }\n    Obfuscated {\n        func: if omitted("shuffle") { func } else { shuffle(&func, rng) },')
    if text == old or 'fn omitted(pass: &str)' not in text or 'if omitted("shuffle") { func }' not in text:
        raise ValueError("source seam mismatch")
    path.write_text(text)



FIXTURES = ("affine_xor", "counter")
SEEDS = tuple(range(0x401, 0x40b))


def manifest_errors(data):
    if not isinstance(data, dict) or not isinstance(data.get("rows"), list) or not isinstance(data.get("controls"), list):
        return ["missing rows or controls"]
    errors = []
    expected = {(fixture, seed) for fixture in FIXTURES for seed in SEEDS}
    identities = []
    for row in data["rows"]:
        if not isinstance(row, dict):
            errors.append("invalid row")
            continue
        identity = (row.get("fixture"), row.get("seed"))
        identities.append(identity)
        if row.get("status") != "pass":
            errors.append(f"non-passing row {identity}")
    if len(identities) != len(expected) or set(identities) != expected:
        errors.append("missing, duplicate or unexpected fixture/seed rows")
    controls = data["controls"]
    names = [row.get("fixture") for row in controls if isinstance(row, dict)]
    if len(names) != len(FIXTURES) or set(names) != set(FIXTURES):
        errors.append("missing, duplicate or unexpected controls")
    if any(not isinstance(row, dict) or row.get("status") != "pass" for row in controls):
        errors.append("non-passing control")
    return errors


def final_exit(variants):
    return 0 if set(variants) == set(VARIANTS) and all(
        item.get("exit_code") == 0 and item.get("manifest_errors") == []
        for item in variants.values()
    ) else 1


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repository", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--signer", type=Path, required=True)
    p.add_argument("--pin", type=Path, required=True)
    p.add_argument("--cargo", default="/home/rax/.cargo/bin/cargo")
    a = p.parse_args()
    a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
    root = a.output.resolve()
    clone = root / "scratch"
    invoke(["git", "clone", "--quiet", "--shared", "--no-checkout", a.repository, clone])
    invoke(["git", "-C", clone, "checkout", "--quiet", "--detach", BASE])
    accepted = a.repository / "docs/plans/obfuscation-ecc/runs/01/accepted.patch"
    invoke(["git", "-C", clone, "apply", accepted.resolve()])
    original = (clone / "src/obf/mod.rs").read_bytes()
    patch_source(clone / "src/obf/mod.rs")
    patched = (clone / "src/obf/mod.rs").read_bytes()
    patch = subprocess.run(["git", "-C", str(clone), "diff", "--", "src/obf/mod.rs"], capture_output=True, check=True).stdout
    (root / "instrumentation.patch").write_bytes(patch)
    helper_rel = "tools/elf-auth-helper/target/x86_64-unknown-linux-gnu/release/vmkek-elf-auth-helper"
    helper = clone / helper_rel
    helper.parent.mkdir(parents=True)
    shutil.copy2(a.repository / helper_rel, helper)
    env = os.environ.copy()
    env.update(CARGO_BUILD_JOBS="4", TMPDIR="/home/rax/.cache/codex-research/obfuscation-ecc-rust/tmp")
    env.pop("CARGO_TARGET_DIR", None)
    build_started = time.monotonic()
    with (root / "build.log").open("w") as log:
        invoke([a.cargo, "+1.95.0", "build", "--locked", "--offline", "--release", "-p", "vmkek", "--bin", "vmkek"], cwd=clone, env=env, stdout=log, stderr=subprocess.STDOUT)
    cli = clone / "target/release/vmkek"
    record = {"base": BASE, "stage01_patch_sha256": sha(accepted), "original_obf_sha256": hashlib.sha256(original).hexdigest(),
              "instrumented_obf_sha256": hashlib.sha256(patched).hexdigest(), "instrumentation_patch_sha256": sha(root / "instrumentation.patch"),
              "protector_sha256": sha(cli), "helper_sha256": sha(helper), "script_sha256": sha(Path(__file__).resolve()),
              "build_elapsed_seconds": time.monotonic() - build_started,
              "description": "Owned authenticated ELF fixtures. Changing a pass changes later RNG draws; authenticated entropy also changes bytes.", "variants": {}}
    for variant in VARIANTS:
        env["VMKEK_ECC_ABLATION"] = variant
        destination = root / ("results-" + variant)
        command = ["python3", "-B", "evaluation/evaluate.py", "build", "--fixture", "affine_xor", "--fixture", "counter",
                   "--output", destination, "--signer", a.signer.resolve(), "--pin", a.pin.resolve()]
        start = time.monotonic()
        with (root / ("run-" + variant + ".log")).open("w") as log:
            result = subprocess.run([str(x) for x in command], cwd=clone, env=env, stdout=log, stderr=subprocess.STDOUT)
        item = {"exit_code": result.returncode, "elapsed_seconds": time.monotonic() - start}
        manifest = destination / "baseline.json"
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text())
                item.update(manifest_sha256=sha(manifest), manifest_errors=manifest_errors(data))
                if isinstance(data, dict) and isinstance(data.get("rows"), list):
                    rows = [row for row in data["rows"] if isinstance(row, dict)]
                    item["statuses"] = {
                        status: sum(row.get("status") == status for row in rows)
                        for status in ("pass", "error", "unsupported", "timeout")
                    }
                    item["observed_rows"] = len(data["rows"])
                if not item["manifest_errors"]:
                    item["artifact_sizes"] = {
                        row["fixture"] + ":" + str(row["seed"]):
                        (destination / (row["fixture"] + "-" + str(row["seed"]) + ".elf")).stat().st_size
                        for row in data["rows"]
                    }
            except (OSError, ValueError, TypeError) as error:
                item["manifest_errors"] = [str(error)]
        else:
            item["manifest_errors"] = ["baseline.json missing"]
        record["variants"][variant] = item
        (root / "summary.json").write_text(json.dumps(record, indent=2) + "\n")
    return final_exit(record["variants"])


if __name__ == "__main__":
    raise SystemExit(main())
