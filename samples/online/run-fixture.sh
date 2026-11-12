#!/usr/bin/env bash
set -euo pipefail
umask 077
source "$(dirname -- "${BASH_SOURCE[0]}")/process.sh"

if [[ $# -lt 2 || $# -gt 3 || $1 != /* || $2 != /* || ! -x $1 || ${3:-} != "" && ${3:-} != --linux && ${3:-} != --linux-swap ]]; then
    printf '%s\n' 'Usage: run-fixture.sh /path/to/r18_fixture /path/to/isolated-pg-home [--linux|--linux-swap]' >&2
    exit 2
fi
fixture=$1
pg=$2
mode=("${@:3}")
nonce=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
[[ $nonce =~ ^[0-9a-f]{32}$ ]]
tools="$pg/pkg/usr/lib/postgresql/16/bin"
if [[ ${3:-} == --linux* ]]; then
    lab=$(mktemp -d "$HOME/.vmkek-r21-XXXXXXXX")
    db="vmkek_r21_$nonce"
else
    lab=$(mktemp -d /tmp/vmkek-r18-XXXXXXXX)
    db="vmkek_r18_$nonce"
fi
fixture_pid=''
database_owned=false
cleanup() {
    local status=$? cleanup_status=0
    trap - EXIT
    trap '' INT TERM
    if [[ -n $fixture_pid ]]; then
        # GNU timeout forwards TERM to the supervised fixture process group.
        terminate_owned "$fixture_pid" 0 || {
            local stop_status=$?
            if [[ $stop_status == 125 ]]; then cleanup_status=1; fi
        }
    fi
    rm -f -- "$lab/config.bin" "$lab/foreign.bin" \
        "$lab/native/config.bin" "$lab/native/device.key" \
        "$lab/foreign/config.bin" "$lab/foreign/device.key" \
        "$lab/wrong-build/config.bin" "$lab/wrong-build/device.key" || cleanup_status=1
    if "$database_owned"; then
        timeout --kill-after=1s 5s "$tools/dropdb" --if-exists --force -h "$pg/socket" -p 55439 -U r09 "$db" || cleanup_status=1
    fi
    if ((cleanup_status)); then printf '%s\n' 'fixture cleanup failed' >&2; fi
    if ((status)); then exit "$status"; fi
    exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
creation_status=0
timeout --kill-after=1s 5s "$tools/createdb" -h "$pg/socket" -p 55439 -U r09 "$db" || creation_status=$?
if ((creation_status)); then
    printf 'fixture database ownership unconfirmed for %s; no deletion attempted\n' "$db" >&2
    exit "$creation_status"
fi
database_owned=true
if [[ ${3:-} == --linux* ]]; then printf '%s\n' "$db" > "$lab/database.name"; fi
printf '%s\n' "$lab"
timeout --kill-after=2s 185s "$fixture" "$lab" "$pg/socket" "$db" "${mode[@]}" &
fixture_pid=$!
remember_owned "$fixture_pid" || true
status=0
wait "$fixture_pid" || status=$?
fixture_pid=''
exit "$status"
