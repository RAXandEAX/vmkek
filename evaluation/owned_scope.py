#!/usr/bin/env python3
"""Bounded systemd execution for owned evaluation fixtures on Linux."""

import ctypes
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

BUDGETS = (60, 600, 3600)
MEMORY = 8 * 1024**3
OUTPUT_LIMIT = 1024 * 1024


def _systemctl(*args):
    return subprocess.run(["systemctl", "--user", *args], capture_output=True, text=True, timeout=10)


def run(argv, *, budget, input_data=b"", isolate_file=None, _limits=None):
    """Run a fixture in a transient user service; return observed process outcome.

    _limits is reserved for resource-control tests. Ordinary callers use the
    public budgets and the fixed 8 GiB limit.
    """
    if budget not in BUDGETS:
        raise ValueError("unsupported budget")
    if not argv or not all(isinstance(x, str) and x for x in argv):
        raise ValueError("argv must contain nonempty strings")
    if not isinstance(input_data, bytes) or len(input_data) > OUTPUT_LIMIT:
        raise ValueError("input must be bytes of at most 1 MiB")
    if sys.platform != "linux" or not shutil.which("systemd-run") or not shutil.which("systemctl"):
        return {"status": "unsupported", "reason": "Linux systemd user manager unavailable"}
    if isolate_file is not None:
        candidate = Path(isolate_file).resolve(strict=True)
        if candidate.is_relative_to("/usr"):
            raise ValueError("candidate must be outside the trusted /usr tree")
        isolate_file = str(candidate)
    wall, memory = _limits if _limits else (budget, MEMORY)
    unit = "vmkek-eval-" + uuid.uuid4().hex + ".service"
    start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="vmkek-scope-") as directory:
        root = Path(directory)
        (root / "stdin").write_bytes(input_data)
        request = {"argv": argv, "directory": directory, "isolate_file": isolate_file}
        request_file = root / "request.json"
        request_file.write_text(json.dumps(request), encoding="utf-8")
        cmd = ["systemd-run", "--user", "--quiet", "--unit=" + unit,
               "--property=Type=exec", "--property=RemainAfterExit=yes",
               "--property=MemoryMax=" + str(memory), "--property=MemorySwapMax=0",
               "--property=RuntimeMaxSec=" + str(wall), "--property=KillMode=control-group",
               "--", sys.executable, str(Path(__file__).resolve()), "--child", str(request_file)]
        try:
            launched = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        except (OSError, subprocess.TimeoutExpired) as error:
            try:
                _systemctl("stop", unit)
                _systemctl("reset-failed", unit)
            except (OSError, subprocess.TimeoutExpired):
                pass
            return {"status": "error", "reason": str(error), "command": cmd}
        if launched.returncode:
            reason = launched.stderr.strip()
            unavailable = ("Failed to connect to bus", "No medium found")
            status = "unsupported" if any(item in reason for item in unavailable) else "error"
            return {"status": status, "reason": reason, "command": cmd}
        properties = {}
        try:
            deadline = time.monotonic() + wall + 15
            while time.monotonic() < deadline:
                result = _systemctl("show", unit, "--property=ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,MemoryPeak")
                if result.returncode:
                    return {"status": "error", "reason": result.stderr.strip(), "command": cmd}
                properties = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
                if properties.get("ActiveState") == "failed" or properties.get("SubState") == "exited":
                    break
                time.sleep(0.05)
            else:
                return {"status": "error", "reason": "systemd did not complete by deadline", "command": cmd}
            unit_result = properties.get("Result")
            code = properties.get("ExecMainStatus")
            status = {"success": "pass", "timeout": "timeout", "oom-kill": "oom"}.get(unit_result, "error")
            if status == "pass" and code != "0":
                status = "error"
            stdout = (root / "stdout").read_bytes() if (root / "stdout").exists() else b""
            stderr = (root / "stderr").read_bytes() if (root / "stderr").exists() else b""
            if len(stdout) >= OUTPUT_LIMIT or len(stderr) >= OUTPUT_LIMIT:
                status = "error"
            return {"status": status, "systemd_result": unit_result, "exit_code": code,
                    "signal_or_exit": properties.get("ExecMainCode"),
                    "memory_peak": properties.get("MemoryPeak"), "elapsed_seconds": time.monotonic()-start,
                    "stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace"),
                    "output_limit_bytes": OUTPUT_LIMIT, "budget_seconds": budget, "memory_limit_bytes": memory,
                    "command": cmd}
        finally:
            try:
                _systemctl("stop", unit)
                _systemctl("reset-failed", unit)
            except (OSError, subprocess.TimeoutExpired):
                pass


def _restrict_file_access(candidate):
    """Permit reads only in /usr, the loader cache and the owned candidate."""
    libc = ctypes.CDLL(None, use_errno=True)
    abi = libc.syscall(444, 0, 0, 1)
    if abi < 1:
        raise OSError(ctypes.get_errno(), "Landlock unavailable")
    # Rights introduced in ABI 1, plus REFER (ABI 2) and TRUNCATE (ABI 3).
    handled = (1 << 13) - 1
    if abi >= 2:
        handled |= 1 << 13
    if abi >= 3:
        handled |= 1 << 14
    class Ruleset(ctypes.Structure):
        _fields_ = [("handled_access_fs", ctypes.c_uint64)]
    class PathBeneath(ctypes.Structure):
        _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]
    ruleset = Ruleset(handled)
    fd = libc.syscall(444, ctypes.byref(ruleset), ctypes.sizeof(ruleset), 0)
    if fd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset")
    try:
        for path, rights in (("/usr", (1 << 0) | (1 << 2) | (1 << 3)),
                             ("/etc/ld.so.cache", 1 << 2), (candidate, 1 << 2)):
            path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
            try:
                rule = PathBeneath(rights, path_fd)
                if libc.syscall(445, fd, 1, ctypes.byref(rule), 0) != 0:
                    raise OSError(ctypes.get_errno(), "landlock_add_rule")
            finally:
                os.close(path_fd)
        if libc.prctl(38, 1, 0, 0, 0) != 0:
            raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS")
        if libc.syscall(446, fd, 0) != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self")
    finally:
        os.close(fd)


def _child(request_path):
    import resource

    request = json.loads(Path(request_path).read_text(encoding="utf-8"))
    root = Path(request["directory"])
    with (root / "stdin").open("rb") as inp, (root / "stdout").open("wb") as out, (root / "stderr").open("wb") as err:
        os.dup2(inp.fileno(), 0)
        os.dup2(out.fileno(), 1)
        os.dup2(err.fileno(), 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (OUTPUT_LIMIT, OUTPUT_LIMIT))
        os.chdir(root)
        if request["isolate_file"] is not None:
            _restrict_file_access(request["isolate_file"])
        os.execvp(request["argv"][0], request["argv"])


if __name__ == "__main__" and len(sys.argv) == 3 and sys.argv[1] == "--child":
    _child(sys.argv[2])
