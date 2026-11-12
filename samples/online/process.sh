# Bash helpers for background children started and retained by the calling runner.
declare -A owned_start=()
declare -A owned_parent=()

read_owned_identity() {
    local line
    local -a fields
    { IFS= read -r line < "/proc/$1/stat"; } 2>/dev/null || return 1
    read -ra fields <<< "${line##*) }"
    [[ ${#fields[@]} -ge 20 && ${fields[0]} != Z && ${fields[0]} != X ]] || return 1
    process_parent=${fields[1]}
    process_start=${fields[19]}
}

remember_owned() {
    local pid=$1
    read_owned_identity "$pid" && [[ $process_parent == "$BASHPID" ]] || return 1
    owned_start[$pid]=$process_start
    owned_parent[$pid]=$process_parent
}

owned_alive() {
    local pid=$1
    [[ -v owned_start[$pid] ]] && read_owned_identity "$pid" &&
        [[ $process_start == "${owned_start[$pid]}" && $process_parent == "${owned_parent[$pid]}" ]]
}

signal_owned() {
    local pid=$1 name=$2
    owned_alive "$pid" || return 1
    # Pin the kernel PID before checking the recorded identity again. A later
    # numeric PID reuse cannot redirect a signal sent through this descriptor.
    python3 - "$pid" "${owned_start[$pid]}" "${owned_parent[$pid]}" "$name" <<'PY'
import os
from pathlib import Path
import signal
import sys

pid, start, parent, name = sys.argv[1:]
try:
    fd = os.pidfd_open(int(pid))
    try:
        fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b") ", 1)[1].split()
        if fields[0] in (b"Z", b"X") or fields[1] != parent.encode() or fields[19] != start.encode():
            sys.exit(1)
        signal.pidfd_send_signal(fd, getattr(signal, "SIG" + name))
    finally:
        os.close(fd)
except (FileNotFoundError, ProcessLookupError):
    sys.exit(1)
PY
}

wait_owned_exit() {
    local pid=$1 attempts=$2 attempt
    for ((attempt=0; attempt<attempts; attempt++)); do
        owned_alive "$pid" || return 0
        sleep .05
    done
    ! owned_alive "$pid"
}

terminate_owned() {
    local pid=$1 grace=$2
    [[ -v owned_start[$pid] ]] || return 125
    if ! wait_owned_exit "$pid" "$grace"; then
        signal_owned "$pid" TERM || true
        if ! wait_owned_exit "$pid" 220; then
            signal_owned "$pid" KILL || true
            wait_owned_exit "$pid" 40 || return 125
        fi
    fi
    wait "$pid"
}
