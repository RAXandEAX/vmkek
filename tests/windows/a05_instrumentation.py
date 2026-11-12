"""A bounded native lab for the bundled A05 fixture and fixed witnesses."""

import ctypes
from ctypes import wintypes
import hashlib
from importlib import metadata, util
import json
import os
from pathlib import Path
import platform
import queue
import re
import shutil
import subprocess
import sys
import time


def digest(path):
    with Path(path).open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


# Official frida-16.6.6-cp37-abi3-win_amd64 wheel member digests.
FRIDA_FILES = {
    "__init__.py": "ce6e1c1090d27e9a8b499b5b4f76efa18b5bc35f09f69c69b2f1346a886a9d44",
    "_frida.pyd": "991cfa8b30c148713933cf82ccd8835220a9d3745dbc1c4cc3eda2aac9eac94a",
    "core.py": "44f78bb302388b101d9cd1e28ba8dba0575d79e689b404326a643a50fb348452",
    "py.typed": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "_frida/__init__.pyi": "b2f27de02b5ed770ba7eba27d262a3c664c0b6402f0d0252caa1d334052b1a39",
    "_frida/py.typed": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
GADGET_SHA256 = "77f6180bf06a93fcd64f3a7f41b4d11d8ab398bfa66c8915ed06505c093202bb"


def stock_frida():
    spec = util.find_spec("frida")
    if spec is None or spec.origin is None:
        raise RuntimeError("the stock Frida wheel is required")
    package = Path(spec.origin).resolve().parent
    for name, expected in FRIDA_FILES.items():
        if digest(package / name) != expected:
            raise RuntimeError(f"stock Frida package member differs: {name}")
    import frida
    return frida


frida = stock_frida()

CASES = {
    "Clean", "CleanRenamed", "MarkerClean", "StalkerClean", "BenignProfiler",
    "OwnedMarkerDuringFridaAttach", "FridaSpawn", "FridaAttach",
    "FridaGadget", "FridaInterceptor", "FridaInterceptorRenamed", "FridaStalker",
}
RECORD = re.compile(
    r"finding=(?P<finding>\w+) reason=(?P<reason>\w+) decision=ReportOnly "
    r"tick_ms=(?P<tick>\d+) elapsed_ns=(?P<elapsed>\d+) policy_epoch=1 "
    r"policy_sha256=(?P<sha>[0-9a-f]{64}) marker=44 abi=0 "
    r"control_ns=(?P<control>\d+) change_tick=(?P<change>\d+) protection=(?P<protection>[0-9a-f]+) "
    r"dynamic=(?P<dynamic>[0-9a-f]+) cfg=(?P<cfg>[0-9a-f]+) shadow=(?P<shadow>[0-9a-f]+)"
)
TIMEOUT = 10
KERNEL = ctypes.WinDLL("kernel32", use_last_error=True)


def bind(name, result, *arguments):
    function = getattr(KERNEL, name)
    function.restype = result
    function.argtypes = arguments
    return function


open_process = bind("OpenProcess", wintypes.HANDLE, wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
image_name = bind("QueryFullProcessImageNameW", wintypes.BOOL, wintypes.HANDLE, wintypes.DWORD,
                  wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD))
in_job = bind("IsProcessInJob", wintypes.BOOL, wintypes.HANDLE, wintypes.HANDLE,
              ctypes.POINTER(wintypes.BOOL))
wait_process = bind("WaitForSingleObject", wintypes.DWORD, wintypes.HANDLE, wintypes.DWORD)
exit_code = bind("GetExitCodeProcess", wintypes.BOOL, wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
close_handle = bind("CloseHandle", wintypes.BOOL, wintypes.HANDLE)


def checked(value):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


class BasicLimits(ctypes.Structure):
    _fields_ = [
        ("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong),
        ("flags", wintypes.DWORD), ("minimum", ctypes.c_size_t), ("maximum", ctypes.c_size_t),
        ("active", wintypes.DWORD), ("affinity", ctypes.c_size_t),
        ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD),
    ]


class JobLimits(ctypes.Structure):
    _fields_ = [
        ("basic", BasicLimits), ("io", ctypes.c_uint64 * 6),
        ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
        ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t),
    ]


create_job = bind("CreateJobObjectW", wintypes.HANDLE, ctypes.c_void_p, wintypes.LPCWSTR)
set_job = bind("SetInformationJobObject", wintypes.BOOL, wintypes.HANDLE, ctypes.c_int,
               ctypes.c_void_p, wintypes.DWORD)
assign_job = bind("AssignProcessToJobObject", wintypes.BOOL, wintypes.HANDLE, wintypes.HANDLE)


class OwnedChild:
    """Attach only after verifying the exact child image and dedicated job."""

    def __init__(self, pid, executable):
        self.pid = pid
        self.job = checked(create_job(None, None))
        self.handle = None
        try:
            limits = JobLimits()
            limits.basic.flags = 0x2000  # Kill on close.
            checked(set_job(self.job, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
            self.handle = checked(open_process(0x00101101, False, pid))
            actual = ctypes.create_unicode_buffer(32768)
            length = wintypes.DWORD(len(actual))
            checked(image_name(self.handle, 0, actual, ctypes.byref(length)))
            if Path(actual.value).resolve() != executable:
                raise RuntimeError("launched image did not match the owned fixture")
            checked(assign_job(self.job, self.handle))
            member = wintypes.BOOL()
            checked(in_job(self.handle, self.job, ctypes.byref(member)))
            if not member.value:
                raise RuntimeError("fixture did not join the dedicated job")
        except BaseException:
            close_handle(self.job)
            if self.handle:
                close_handle(self.handle)
            raise

    def __enter__(self):
        return self

    def __exit__(self, error_type, *_exc):
        active_at_close = wait_process(self.handle, 0) == 258
        try:
            checked(close_handle(self.job))
            if wait_process(self.handle, 1000) != 0:
                raise RuntimeError("owned fixture job did not exit")
            result = wintypes.DWORD()
            checked(exit_code(self.handle, ctypes.byref(result)))
            self.teardown_code = result.value
            if error_type is None and (not active_at_close or result.value != 0):
                raise RuntimeError(f"unexpected owned fixture exit 0x{result.value:08x}")
        finally:
            close_handle(self.handle)

    def wait(self):
        if wait_process(self.handle, TIMEOUT * 1000) != 0:
            raise TimeoutError("owned fixture did not exit")
        result = wintypes.DWORD()
        checked(exit_code(self.handle, ctypes.byref(result)))
        if result.value:
            raise RuntimeError(f"owned fixture exited 0x{result.value:08x}")

def tool_info():
    try:
        tools_version = metadata.version("frida-tools")
    except metadata.PackageNotFoundError:
        tools_version = None
    print(json.dumps({
        "pythonVersion": platform.python_version(),
        "pythonSha256": digest(sys.executable),
        "fridaVersion": frida.__version__,
        "fridaSha256": digest(frida._frida.__file__),
        "fridaToolsVersion": tools_version,
        "packageRoot": str(Path(frida.__file__).resolve().parent.parent),
        "packageFiles": FRIDA_FILES,
    }))


def wait_file(name, child):
    path = Path(name)
    deadline = time.monotonic() + TIMEOUT
    while not path.is_file():
        if wait_process(child.handle, 0) == 0:
            child.wait()
            raise RuntimeError(f"owned fixture exited before {name}")
        if time.monotonic() >= deadline:
            raise TimeoutError(name)
        time.sleep(.004)
    with path.open("rb") as file:
        content = file.read(4097)
    if len(content) > 4096:
        raise RuntimeError(f"lab record limit exceeded: {name}")
    return content.decode("ascii")


def release(name):
    with Path(name).open("x", encoding="ascii") as file:
        file.write("release\n")


def validate_event(event, child, kind, value):
    if (event["kind"], event["pid"], event["value"]) != (kind, child.pid, value):
        raise RuntimeError("tool activity did not match the owned fixture")
    return {"kind": kind, "value": value, "pid": child.pid, "tickMs": int(event["tick"])}


def setup_gadget(source, module, script):
    gadget = Path(os.environ["TEMP"]).resolve() / "frida-gadget.dll"
    shutil.copyfile(source, gadget)
    if digest(gadget) != GADGET_SHA256:
        raise RuntimeError("Gadget copy differs from the pinned artifact")
    gadget.with_suffix(".config").write_text(json.dumps({
        "interaction": {
            "type": "script", "path": str(script),
            "parameters": {"gadget": True, "module": module, "oracle": str(Path("gadget.json").resolve())},
        },
    }), encoding="utf-8")
    return gadget

def injected_agent(device, child, script_path, messages, agents):
    session = device.attach(child.pid)
    script = session.create_script(script_path.read_text(encoding="utf-8"))
    agents.append((session, script))
    script.on("message", lambda message, _data: enqueue(messages, message))
    script.load()
    return script.exports_sync


def enqueue(messages, message):
    try:
        messages.put_nowait(message)
    except queue.Full:
        pass


def tool_event(messages, child, kind, value=17):
    message = messages.get(timeout=TIMEOUT)
    if message["type"] != "send":
        raise RuntimeError(f"owned {kind} callback failed")
    return validate_event(message["payload"], child, kind, value)


def measure(case, device, child, module, script_path, agents):
    api = None
    activity = []
    messages = queue.Queue(maxsize=4)
    if case == "FridaSpawn":
        api = injected_agent(device, child, script_path, messages, agents)
        activity.append(validate_event(api.boot(), child, "spawn", 0xA05))
        device.resume(child.pid)

    pid, thread, ready_tick = map(int, wait_file("ready", child).split())
    if pid != child.pid or thread == 0:
        raise RuntimeError("readiness did not match the owned fixture")
    if activity and activity[0]["tickMs"] > ready_tick:
        raise RuntimeError("spawn witness was after fixture readiness")

    if device and api is None:
        api = injected_agent(device, child, script_path, messages, agents)
    if case == "BenignProfiler":
        api.profile(module)
    if api:
        activity.append(validate_event(api.witness(module), child, "witness", 0xA05))
    if case == "BenignProfiler":
        activity.append(tool_event(messages, child, "profiler", 0xA05))
    if case.startswith("FridaInterceptor"):
        api.intercept(module)
    elif case == "FridaStalker":
        api.trace(module, thread)

    release("measure")
    if case == "FridaGadget":
        wait_file("gadget.json.ready", child)
        payload = json.loads(wait_file("gadget.json", child))
        activity.append(validate_event(payload, child, "gadget", 0xA05))
        release("gadget_measure")
    record = RECORD.fullmatch(wait_file("result", child))
    if not record:
        raise RuntimeError("invalid fixed fixture result")
    if case.startswith("FridaInterceptor"):
        activity.append(tool_event(messages, child, "interceptor"))
    elif case == "FridaStalker":
        activity.append(tool_event(messages, child, "stalker"))

    sample_tick = int(record["tick"])
    if activity and not (ready_tick <= activity[-1]["tickMs"] <= sample_tick):
        raise RuntimeError("tool witness was outside the measurement interval")
    finding = record["finding"]
    active_test = case.startswith("Frida") or case == "OwnedMarkerDuringFridaAttach"
    classification = {
        "SignedMismatch": "detected" if active_test else "false-positive",
        "NotObservedWithinScope": "missed" if active_test else "clean",
        "Inconclusive": "inconclusive",
        "Unsupported": "unsupported",
    }[finding]
    return {
        "activity": activity, "finding": finding, "reason": record["reason"],
        "decision": "ReportOnly", "policyEpoch": 1, "policySha256": record["sha"],
        "readyTickMs": ready_tick, "sampleTickMs": sample_tick,
        "activityToSampleMs": sample_tick - activity[-1]["tickMs"] if activity else None,
        "sampleElapsedNs": int(record["elapsed"]), "classification": classification,
        "effectOrigin": "fixture-owned-marker" if case == "OwnedMarkerDuringFridaAttach"
                        else "stock-tool" if active_test else "control",
        "fixtureMarker": 44, "invokeStatus": 0,
        "profilerElapsedNs": int(record["control"]), "changeTickMs": int(record["change"]),
        "protection": int(record["protection"], 16), "mitigations": {
            kind: int(record[kind], 16) for kind in ("dynamic", "cfg", "shadow")
        },
    }


def run(case, executable, module, gadget_source=None):
    if case not in CASES:
        raise RuntimeError("unsupported laboratory case")
    executable, module = Path(executable).resolve(), Path(module).resolve()
    if executable.name not in {"instrumentation_lab.exe", "instrumentation_lab_renamed.exe", "instrumentation_lab_stalker.exe"}:
        raise RuntimeError("only the bundled fixture may be launched")
    if module.name not in {"a05-owned.dll", "a05-renamed.dll"}:
        raise RuntimeError("only the bundled fixture DLL may be observed")
    script_path = Path(__file__).resolve().with_name("a05_agent.js")
    injected = case in {"BenignProfiler", "OwnedMarkerDuringFridaAttach"} or (
        case.startswith("Frida") and case != "FridaGadget"
    )
    device = frida.get_local_device() if injected else None
    mode = {"BenignProfiler": "profiler", "FridaGadget": "gadget", "MarkerClean": "marker-clean",
            "OwnedMarkerDuringFridaAttach": "marker"}.get(case, "baseline")
    command = [str(executable), str(module), mode]
    if mode == "gadget":
        if not gadget_source:
            raise RuntimeError("pinned stock Gadget is required")
        command.append(str(setup_gadget(gadget_source, module.name, script_path)))
    process = None
    if case == "FridaSpawn":
        pid = device.spawn(command, cwd=str(Path.cwd()), stdio="inherit")
    else:
        process = subprocess.Popen(command, creationflags=subprocess.CREATE_NO_WINDOW)
        pid = process.pid
    agents = []
    try:
        with OwnedChild(pid, executable) as child:
            result = measure(case, device, child, module.name, script_path, agents)
        result["teardown"] = {"method": "owned-job-close", "exitCode": child.teardown_code}
        result["fridaVersion"] = frida.__version__
        result["fridaSha256"] = digest(frida._frida.__file__)
        result["fixtureSha256"] = digest(executable)
        result["moduleSha256"] = digest(module)
        print("a05 " + json.dumps(result), flush=True)
    finally:
        try:
            if process is not None and process.poll() is None:
                # Popen owns the actual handle returned by our CreateProcess.
                process.terminate()
                process.wait(timeout=1)
        finally:
            for filename in ("frida-gadget.dll", "frida-gadget.config"):
                (Path(os.environ["TEMP"]) / filename).unlink(missing_ok=True)


if __name__ == "__main__":
    if sys.argv[1:] == ["--tool-info"]:
        tool_info()
    else:
        try:
            run(*sys.argv[1:])
        except Exception as error:
            print(f"a05-error type={type(error).__name__} detail={str(error)[:500]}", file=sys.stderr)
            sys.exit(1)
