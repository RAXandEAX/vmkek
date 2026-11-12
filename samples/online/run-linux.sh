#!/usr/bin/env bash
set -euo pipefail
umask 077
export LC_ALL=C

if [[ $# != 3 || $1 != /* || $2 != /* || $3 != /* || ! -x $1 || ! -x $2 ]]; then
    printf '%s\n' 'Usage: run-linux.sh /path/to/non-PIE-sample /path/to/r18_fixture /path/to/isolated-pg-home' >&2
    exit 2
fi
client=$1
fixture=$2
pg=$3
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/process.sh"
report=$(mktemp -d "$HOME/.vmkek-r21-report-XXXXXXXX")
header=$(readelf -h "$client")
for assertion in 'Class:.*ELF64' 'Type:.*EXEC' 'Machine:.*X86-64'; do
    grep -Eq "$assertion" <<< "$header"
done
printf '%s\n' 'r21 native ELF64 ET_EXEC x86-64'
lab=''
server=''
held=''

cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT
    trap '' INT TERM
    if [[ -n $lab && -d $lab ]]; then
        : > "$lab/stop" || cleanup_status=1
    fi
    if [[ -n $held ]]; then
        terminate_owned "$held" 0 || {
            local stop_status=$?
            if [[ $stop_status == 125 ]]; then cleanup_status=1; fi
        }
    fi
    if [[ -n $server ]]; then
        terminate_owned "$server" 40 || {
            local stop_status=$?
            if [[ $stop_status != 143 || -z $lab || ! -d $lab ]]; then cleanup_status=1; fi
        }
    fi
    if [[ -n $lab && -d $lab ]]; then
        for name in native foreign wrong-build; do
            rm -f -- "$lab/$name/config.bin" "$lab/$name/device.key" || cleanup_status=1
        done
    fi
    if ((cleanup_status)); then printf '%s\n' 'r21 runner cleanup failed' >&2; fi
    if ((status)); then exit "$status"; fi
    exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

wait_marker() {
    local marker=$1 pid=$2
    for ((attempt=0; attempt<320; attempt++)); do
        [[ -f $marker ]] && return
        owned_alive "$pid" || break
        sleep .025
    done
    printf 'r21 missing marker %s\n' "${marker##*/}" >&2
    return 1
}

start_lab() {
    local name=$1 path_file="$report/$1.lab"
    bash "$script_dir/run-fixture.sh" "$fixture" "$pg" --linux > "$path_file" 2>"$report/$name.fixture.err" &
    server=$!
    remember_owned "$server" || true
    for ((attempt=0; attempt<320; attempt++)); do
        [[ -s $path_file ]] && break
        owned_alive "$server" || break
        sleep .025
    done
    read -r lab < "$path_file"
    [[ $lab == "$HOME"/.vmkek-r21-* ]]
    wait_marker "$lab/ready" "$server" || { cat "$report/$name.fixture.err" >&2; return 1; }
    config="$lab/native/config.bin"
    pin="$lab/receipt-pin.sec1"
    input="$lab/input.bin"
}

stop_lab() {
    : > "$lab/stop"
    terminate_owned "$server" 200
    for name in native foreign wrong-build; do
        [[ ! -e "$lab/$name/config.bin" && ! -e "$lab/$name/device.key" ]]
    done
    server=''
    lab=''
}

expect_denied() {
    local name=$1 expected=$2
    shift 2
    local status=0
    timeout --kill-after=1s 8s "$client" "$@" >"$report/$name.out" 2>"$report/$name.err" || status=$?
    [[ $status == 1 && ! -s "$report/$name.out" ]]
    grep -Fxq "$expected" "$report/$name.err"
}

hold() {
    local name=$1
    control="$report/$name"
    mkdir -- "$control"
    timeout --kill-after=1s 12s "$client" "$config" "$pin" "$input" --hold "$control" >"$report/$name.out" 2>"$report/$name.err" &
    held=$!
    remember_owned "$held" || true
    wait_marker "$control/admitted" "$held"
}

check_held_denial() {
    local name=$1 status=0
    : > "$control/retry"
    wait "$held" || status=$?
    held=''
    [[ $status == 1 && ! -s "$report/$name.out" ]]
    grep -Fxq 'online-vm status=3' "$report/$name.err"
}

summary() {
    grep -E '^online-ok generation=[0-9a-f]{32} bytes=23 sha256=f612a6c9c5b1c79f06676fa20597d13506d33a412b94cfd04589247df9d31c77 scalar=-17 receipt=63$' "$1"
}

generation() {
    local line=${1#online-ok generation=}
    printf '%s\n' "${line%% *}"
}

start_lab matrix
hold old
old_id=$(generation "$(summary "$control/admitted")")
timeout --kill-after=1s 8s "$client" "$config" "$pin" "$input" >"$report/second.out"
new_id=$(generation "$(summary "$report/second.out")")
[[ $old_id != "$new_id" ]]
IFS=$'\t' read -r _ old_form old_desc old_program < <(grep -F "$old_id" "$lab/catalog.tsv")
IFS=$'\t' read -r _ new_form new_desc new_program < <(grep -F "$new_id" "$lab/catalog.tsv")
[[ $old_form == Stack && $new_form == Register && $old_desc != "$new_desc" && $old_program != "$new_program" ]]
printf 'r21 clean forms=%s/%s descriptors=%s/%s bytes=23 scalar=-17 receipt=63\n' "$old_form" "$new_form" "$old_desc" "$new_desc"
check_held_denial old
expect_denied foreign 'online-init status=3' "$lab/foreign/config.bin" "$pin" "$input"
expect_denied wrong_build 'online-init status=3' "$lab/wrong-build/config.bin" "$pin" "$input"
truncate -s 4097 "$report/oversize.bin"
expect_denied oversize 'sample input exceeds its file or size constraint' "$config" "$pin" "$report/oversize.bin"
printf '%s\n' 'r21 stale session/key, foreign proof, wrong build and oversized input denied'
hold revoked
revoked_id=$(generation "$(summary "$control/admitted")")
: > "$lab/revoke"
wait_marker "$lab/revoked" "$server"
check_held_denial revoked
expect_denied revoked_fresh 'online-init status=3' "$config" "$pin" "$input"
: > "$lab/restore"
wait_marker "$lab/restored" "$server"
timeout --kill-after=1s 8s "$client" "$config" "$pin" "$input" >"$report/restored.out"
restored_id=$(generation "$(summary "$report/restored.out")")
[[ $restored_id != "$old_id" && $restored_id != "$new_id" && $restored_id != "$revoked_id" ]]
printf 'r21 revoke stopped live/fresh; restore generation=%s\n' "$restored_id"
stop_lab

start_lab lifecycle
timeout --kill-after=1s 8s "$client" "$config" "$pin" "$input" >"$report/prior.out"
before=$(generation "$(summary "$report/prior.out")")
: > "$lab/pause"
wait_marker "$lab/paused" "$server"
expect_denied offline 'online-init status=1' "$config" "$pin" "$input"
: > "$lab/resume"
wait_marker "$lab/resumed" "$server"
timeout --kill-after=1s 15s "$client" "$config" "$pin" "$input" --fork-exec >"$report/fork.out"
grep -Fxq 'r21 inherited runtime denied before exec' "$report/fork.out"
grep -Fxq 'r21 parent superseded after child exec' "$report/fork.out"
mapfile -t fresh < <(summary "$report/fork.out")
[[ ${#fresh[@]} == 2 ]]
one=$(generation "${fresh[0]}")
two=$(generation "${fresh[1]}")
[[ $one != "$two" && $one != "$before" && $two != "$before" ]]
printf '%s\n' 'r21 offline denied; reconnect fresh; fork child rejected inherited ABI and exec authorized new session'
stop_lab

start_lab signal
control="$report/signal"
mkdir -- "$control"
"$client" "$config" "$pin" "$input" --cancel-signal "$control" >"$report/signal.out" 2>"$report/signal.err" &
held=$!
remember_owned "$held" || true
wait_marker "$control/authorized" "$held"
read -r database < "$lab/database.name"
[[ $database =~ ^vmkek_r21_[0-9a-f]{32}$ ]]
psql="$pg/pkg/usr/lib/postgresql/16/bin/psql"
sql() { timeout --kill-after=1s 5s "$psql" -X -At -v ON_ERROR_STOP=1 -h "$pg/socket" -p 55439 -U r09 -d "$database" "$@"; }
sql -q <<'SQL'
CREATE FUNCTION r21_stall_call() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    PERFORM pg_sleep(8);
    RETURN NEW;
END
$$;
CREATE CONSTRAINT TRIGGER r21_stall_call
AFTER INSERT ON package_fetch_requests DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW EXECUTE FUNCTION r21_stall_call();
SQL
: > "$control/go"
wait_marker "$control/invoking" "$held"
sleeping() {
    sql -c "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event='PgSleep')"
}
for ((attempt=0; attempt<60; attempt++)); do
    [[ $(sleeping) == t ]] && break
    sleep .025
done
[[ $(sleeping) == t ]]
signal_owned "$held" USR1
if ! wait_owned_exit "$held" 100; then
    printf '%s\n' 'r21 cancellation child did not exit within 5s' >&2
    exit 1
fi
wait "$held"
held=''
grep -Fx 'r21 SIGUSR1 cancelled active Online invocation without output' "$report/signal.out"
[[ ! -s "$report/signal.err" ]]
for ((attempt=0; attempt<180; attempt++)); do
    [[ $(sleeping) == f ]] && break
    sleep .05
done
[[ $(sleeping) == f ]]
stop_lab

timeout --kill-after=1s 5s "$client" --observe-tracer | grep -Fx 'r21 tracer=NotObservedWithinScope'
timeout --kill-after=1s 5s strace -qq -e trace=none -o "$report/owned-trace.log" "$client" --observe-tracer | grep -Fx 'r21 tracer=Observed'
printf 'r21 artifact_sha256=%s\n' "$(sha256sum "$client" | cut -d' ' -f1)"
printf 'r21 public_report=%s\n' "$report"
