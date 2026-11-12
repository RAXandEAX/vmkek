#!/usr/bin/env python3
"""Run the scoped Linux x64 observation matrix on owned fixtures."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 65536
CASES = (
    "baseline", "clean", "threaded", "profiled", "stale", "gdb", "lldb", "integrity-clean",
    "integrity-changed", "integrity-inaccessible", "integrity-outside",
    "online-clean", "online-gdb",
)
UNAVAILABLE = {
    "native-host": "wsl2-only-when-run-under-wsl",
    "external-pid-namespace": "no-qualified-independent-namespace-stand",
    "frida": "no-qualified-linux-instrumentation-adapter",
    "profiler": "no-qualified-external-profiler",
    "elf-shared-object": "only-main-executable-supported",
}
OBSERVATION = re.compile(r"^observation=(\w+) reason=(\w+) decision=(\w+)(?: unavailable=(\w+))?$", re.M)
POLICY = re.compile(r"^policy_sha256=([a-f0-9]{64}) policy_epoch=(\d+)$", re.M)
INVOKE = re.compile(r"^invoke_status=(\d+) output_verified=(true|false) invoke_ns=(\d+)$", re.M)


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(argv, directory, name, timeout, env=None):
    start = time.monotonic()
    streams = [bytearray(), bytearray()]
    reason = None
    process = subprocess.Popen(
        argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        stdin=subprocess.DEVNULL, start_new_session=True,
    )
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, 0)
            selector.register(process.stderr, selectors.EVENT_READ, 1)
            while selector.get_map():
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fd, 4096)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output = streams[key.data]
                    remaining_bytes = LIMIT - len(output)
                    output.extend(chunk[:remaining_bytes])
                    if len(chunk) > remaining_bytes:
                        reason = "log-limit"
                        break
                if reason:
                    break
            while not reason:
                # Keep the leader unreaped so its numeric PID cannot be reused
                # while the owned process group still needs cleanup.
                if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT):
                    break
                remaining = timeout - (time.monotonic() - start)
                if remaining <= 0:
                    reason = "timeout"
                    break
                time.sleep(min(0.02, remaining))
    finally:
        # This process group still has the unreaped leader identity.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            reason = "process-cleanup-error"
        process.stdout.close()
        process.stderr.close()
    outputs = [directory / f"{name}.{suffix}.log" for suffix in ("stdout", "stderr")]
    for path, output in zip(outputs, streams):
        path.write_bytes(output)
    return {
        "command": [str(item) for item in argv], "exitCode": process.returncode, "reason": reason,
        "elapsedMs": round((time.monotonic() - start) * 1000, 3),
        "stdout": outputs[0].name, "stderr": outputs[1].name,
    }


def tool_path(variable, default):
    candidate = os.environ.get(variable) or shutil.which(default)
    if not candidate:
        return None
    path = Path(candidate).resolve()
    return str(path) if path.is_file() and os.access(path, os.X_OK) else None


def expected(case, profile):
    if case == "baseline":
        return ("Disabled", "None", "Allow", None), 0
    if case == "stale":
        if profile == "enforce":
            return ("NotObservedWithinScope", "None", "Unavailable", "Stale"), 1
        return ("NotObservedWithinScope", "None", "Allow", "None"), 0
    if case in {"integrity-inaccessible", "integrity-outside"}:
        finding = "Inconclusive" if case == "integrity-inaccessible" else "Unsupported"
        reason = "ReadFailure" if case == "integrity-inaccessible" else "OutsideScope"
        if profile == "enforce":
            return (finding, reason, "Unavailable", reason), 1
        return (finding, reason, "ReportOnly", "None"), 0
    finding = "NotObservedWithinScope"
    reason = "None"
    if case in {"gdb", "lldb", "online-gdb"}:
        finding = "Observed"
    elif case == "integrity-changed":
        finding = reason = "SignedMismatch"
    if finding != "NotObservedWithinScope" and profile == "enforce":
        return (finding, reason, "RequestOwnStop", "None"), 3
    return (finding, reason, "ReportOnly", "None"), 0


def verify(case, profile, text, result):
    if result["reason"] or result["exitCode"] != 0:
        return result["reason"] or "child-exit", {}
    values = [pattern.findall(text) for pattern in (OBSERVATION, POLICY, INVOKE)]
    if any(len(matches) != 1 for matches in values):
        return "fixture-metadata", {}
    (observation,), ((digest, epoch),), ((status, intact, invoke_ns),) = values
    observation = observation[:3] + (observation[3] or None,)
    want, want_status = expected(case, profile)
    if observation != want or int(status) != want_status or intact != "true":
        return "decision-or-output-mismatch", {
            "observation": observation, "invokeStatus": int(status), "outputVerified": intact == "true",
        }
    oracle = "direct-owned-child"
    if case in {"gdb", "online-gdb"}:
        if "Program stopped." not in text or not re.search(r"\[Inferior \d+ \(process \d+\) exited normally\]", text):
            return "gdb-exit-oracle", {}
        oracle = "gdb-owned-inferior"
    elif case == "lldb":
        pid = re.search(r"Process (\d+) launched:", text)
        if not pid or f"Process {pid[1]} resuming" not in text or f"Process {pid[1]} exited with status = 0" not in text:
            return "lldb-exit-oracle", {}
        oracle = "lldb-owned-inferior"
    elif case == "integrity-changed":
        if "own_marker_changed=true own_marker_inaccessible=false" not in text:
            return "owned-marker-change-oracle", {}
        oracle = "owned-inert-rx-marker-change"
    elif case == "integrity-inaccessible":
        if "own_marker_changed=false own_marker_inaccessible=true" not in text:
            return "owned-permission-change-oracle", {}
        oracle = "owned-inert-rx-marker-inaccessible"
    if case == "threaded" and "threaded_calls=4" not in text:
        return "thread-count-oracle", {}
    if case == "profiled" and not re.search(r"^profiled_calls=20 profiled_cpu_ns=[1-9]\d*$", text, re.M):
        return "thread-cpu-profile-oracle", {}
    if case == "online-gdb" and profile == "enforce":
        if "online_report=acknowledged repeated_deny=true" not in text:
            return "missing-server-acknowledgement", {}
    metrics = {key: int(value) for key, value in re.findall(
        r"\b(startup_us|sample_us|cold_file_bytes|cold_us|hot_file_bytes|memory_bytes|hot_us|online_sample_us|profiled_cpu_ns)=(\d+)\b", text
    )}
    if case.startswith("integrity-") and (metrics.get("cold_file_bytes", 0) == 0
            or metrics.get("hot_file_bytes") != 0):
        return "integrity-budget-metadata", {}
    return None, {
        "groundTruth": oracle, "policySha256": digest, "policyEpoch": int(epoch),
        "observation": observation[0], "observationReason": observation[1],
        "decision": observation[2], "decisionReason": observation[3], "invokeStatus": int(status),
        "outputVerified": True, "metrics": {**metrics, "invoke_ns": int(invoke_ns)},
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", choices=("all",) + CASES, required=True)
    parser.add_argument("--profile", choices=("observe", "enforce"), required=True)
    parser.add_argument("--repeat", type=int, choices=range(1, 31), required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    out = Path(tempfile.mkdtemp(prefix="a10-", dir=args.output))
    rows = []
    uname = platform.uname()
    wsl = "microsoft" in uname.release.lower()
    manifest = {
        "version": 1, "case": args.case, "profile": args.profile, "repeat": args.repeat,
        "host": {"system": uname.system, "architecture": uname.machine, "release": uname.release,
                 "libc": platform.libc_ver(), "wsl2": wsl,
                 "yamaPtraceScope": Path("/proc/sys/kernel/yama/ptrace_scope").read_text().strip()
                 if Path("/proc/sys/kernel/yama/ptrace_scope").is_file() else None},
        "rows": rows, "tools": {}, "sourceSha256": {}, "build": [],
        "limits": {"maxStreamBytes": LIMIT, "probeSeconds": 15, "buildSeconds": 180},
    }
    selected = CASES if args.case == "all" else (args.case,)
    try:
        if (uname.system, uname.machine) != ("Linux", "x86_64"):
            raise RuntimeError("Linux x64 required")
        if args.case == "all":
            for case, reason in UNAVAILABLE.items():
                if case != "native-host" or wsl:
                    rows.append({"id": case, "required": False, "profile": args.profile,
                                 "iteration": None, "status": "not-run", "reason": reason})
        for relative in (
            "Cargo.lock", "tests/linux/anti_analysis.py", "crates/runtime/examples/linux_observation_lab.rs",
            "crates/runtime/examples/support/linux_observation_online.rs", "crates/runtime/src/observations/linux.rs",
            "crates/runtime/src/observations/linux/integrity.rs", "crates/runtime/src/online/stop_policy_linux.rs",
            "crates/protocol/src/detection.rs",
        ):
            manifest["sourceSha256"][relative] = sha(ROOT / relative)
        for variable, default in (("VMKEK_A10_GDB", "gdb"), ("VMKEK_A10_LLDB", "lldb")):
            path = tool_path(variable, default)
            if path:
                result = run([path, "--version"], out, default, 5)
                if result["exitCode"] == 0 and not result["reason"]:
                    manifest["tools"][default] = {"path": path, "sha256": sha(Path(path)), **result}
        cargo = shutil.which("cargo")
        if cargo is None:
            cargo = str(Path.home() / ".cargo/bin/cargo")
        target = ROOT / "target/a10-linux"
        build = run([cargo, "+1.95.0", "build", "--locked", "--release", "--target-dir", str(target),
                     "-p", "vmkek-runtime", "--example", "linux_observation_lab"], out, "build", 180)
        manifest["build"].append(build)
        if build["exitCode"] != 0 or build["reason"]:
            raise RuntimeError("fixture-build-failed")
        binary = out.resolve() / "linux_observation_lab"
        shutil.copy2(target / "release/examples/linux_observation_lab", binary)
        manifest["binaries"] = {binary.name: sha(binary)}
        symbols = run(["sh", "-c", "nm --defined-only \"$1\" | awk '$3 == \"vmkek_a10_marker\" {print $1}'",
                       "a10-nm", str(binary)], out, "marker", 10)
        marker = (out / symbols["stdout"]).read_text().strip()
        if not marker or not re.fullmatch(r"[0-9a-f]+", marker):
            raise RuntimeError("integrity-marker-missing")
        config = os.environ.get("VMKEK_A10_ONLINE_CONFIG")
        for case in selected:
            debugger = "gdb" if case in {"gdb", "online-gdb"} else case if case == "lldb" else None
            missing = (f"{debugger}-unavailable" if debugger and debugger not in manifest["tools"] else
                       "isolated-online-config-unavailable" if case.startswith("online-") and not config else None)
            for iteration in range(1, args.repeat + 1):
                row = {"id": case, "iteration": iteration, "profile": args.profile, "required": True,
                       "runtimeProfile": "Online" if case.startswith("online-") else "Offline", "seed": None}
                if missing:
                    row.update(status="not-run", reason=missing, required=case.startswith("online-"))
                    rows.append(row)
                    continue
                directory = out / f"{case}-{iteration}"
                directory.mkdir()
                cmd = [str(binary), case, args.profile, marker]
                if debugger == "gdb":
                    cmd = [manifest["tools"]["gdb"]["path"], "--batch", "--return-child-result", "-nx",
                           "-ex", "set auto-load off", "-ex", "set disable-randomization off",
                           "-ex", "starti", "-ex", "continue", "--args", *cmd]
                elif debugger == "lldb":
                    cmd = [manifest["tools"]["lldb"]["path"], "--batch", "--no-lldbinit",
                           "-o", "settings set target.disable-aslr false", "-o", "process launch --stop-at-entry", "-o", "continue", "--", *cmd]
                env = {key: os.environ[key] for key in ("PATH", "HOME") if key in os.environ}
                env["LC_ALL"] = "C"
                with tempfile.TemporaryDirectory(prefix="vmkek-a10-", dir=Path.home()) as private:
                    if case.startswith("online-"):
                        env.update(VMKEK_A10_PRIVATE=private, VMKEK_A10_ONLINE_CONFIG=config)
                    process = run(cmd, directory, "fixture", 15, env)
                data = (directory / process["stdout"]).read_text(errors="replace")
                reason, evidence = verify(case, args.profile, data, process)
                row.update(status="failed" if reason else "verified", reason=reason, process=process,
                           evidenceDirectory=directory.name, **evidence)
                rows.append(row)
        if sha(binary) != manifest["binaries"][binary.name]:
            raise RuntimeError("fixture-binary-changed")
    except (OSError, RuntimeError) as error:
        manifest["setupError"] = str(error)
    finally:
        completed = {(row["id"], row["iteration"]) for row in rows}
        for case in selected:
            for iteration in range(1, args.repeat + 1):
                if (case, iteration) not in completed:
                    rows.append({"id": case, "iteration": iteration, "profile": args.profile,
                                 "required": True, "status": "not-run", "reason": "setup-unavailable"})
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
        print(out)
    return int(bool(manifest.get("setupError") or any(
        row["status"] == "failed" or (row["required"] and row["status"] == "not-run") for row in rows
    )))


if __name__ == "__main__":
    raise SystemExit(main())