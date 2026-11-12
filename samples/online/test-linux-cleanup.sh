#!/usr/bin/env bash
set -euo pipefail
umask 077
if [[ $# != 2 || $1 != /* || $2 != /* || ! -x $1 ]]; then
    printf '%s\n' 'Usage: test-linux-cleanup.sh /path/to/non-PIE-sample /path/to/isolated-pg-home' >&2
    exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
proof=$(mktemp -d "$HOME/.vmkek-r21-cleanup-XXXXXXXX")
export VMKEK_R21_CLEANUP_PROOF="$proof"
cat > "$proof/stalled" <<'STUB'
#!/usr/bin/env bash
set -eu
trap '' TERM
mkdir -m700 -- "$1/native" "$1/foreign" "$1/wrong-build"
for name in native foreign wrong-build; do
    : > "$1/$name/config.bin"
    : > "$1/$name/device.key"
done
printf '%s\n' "$1" "$3" "$$" > "$VMKEK_R21_CLEANUP_PROOF/child"
exec sleep 45
STUB
chmod 700 "$proof/stalled"
started=$SECONDS
status=0
bash "$script_dir/run-linux.sh" "$1" "$proof/stalled" "$2" >"$proof/runner.out" 2>"$proof/runner.err" || status=$?
elapsed=$((SECONDS - started))
[[ $status == 1 && $elapsed -lt 20 ]]
grep -Fxq 'r21 missing marker ready' "$proof/runner.err"
mapfile -t child < "$proof/child"
lab=${child[0]}
db=${child[1]}
pid=${child[2]}
[[ $lab == "$HOME"/.vmkek-r21-* && $db =~ ^vmkek_r21_[0-9a-f]{32}$ && $pid =~ ^[0-9]+$ ]]
for name in native foreign wrong-build; do
    [[ ! -e "$lab/$name/config.bin" && ! -e "$lab/$name/device.key" ]]
done
! kill -0 "$pid" 2>/dev/null
psql="$2/pkg/usr/lib/postgresql/16/bin/psql"
present=$("$psql" -X -At -h "$2/socket" -p 55439 -U r09 -d postgres -c "SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname='$db')")
[[ $present == f ]]
printf 'r21 stalled fixture bounded: status=%s elapsed=%ss, child and private state removed\n' "$status" "$elapsed"

source "$script_dir/process.sh"
sleep 3 &
sleeper=$!
remember_owned "$sleeper"
start=${owned_start[$sleeper]}
owned_start[$sleeper]=0
! signal_owned "$sleeper" TERM
kill -0 "$sleeper"
owned_start[$sleeper]=$start
signal_owned "$sleeper" TERM
reaped=0
wait "$sleeper" || reaped=$?
[[ $reaped == 143 ]]
printf '%s\n' 'r21 mismatched process identity left owned sleeper unsignaled'

fake_pg="$proof/pg"
fake_bin="$fake_pg/pkg/usr/lib/postgresql/16/bin"
mkdir -p -- "$fake_bin"
cat > "$fake_bin/createdb" <<'CREATE'
#!/usr/bin/env bash
printf '%s\n' "${@: -1}" > "$VMKEK_R21_CLEANUP_PROOF/collision.name"
exit 42
CREATE
cat > "$fake_bin/dropdb" <<'DROP'
#!/usr/bin/env bash
: > "$VMKEK_R21_CLEANUP_PROOF/collision.drop"
DROP
cat > "$proof/unexpected-fixture" <<'FIXTURE'
#!/usr/bin/env bash
: > "$VMKEK_R21_CLEANUP_PROOF/collision.fixture"
FIXTURE
chmod 700 "$fake_bin/createdb" "$fake_bin/dropdb" "$proof/unexpected-fixture"
status=0
bash "$script_dir/run-fixture.sh" "$proof/unexpected-fixture" "$fake_pg" --linux \
    >"$proof/collision.out" 2>"$proof/collision.err" || status=$?
read -r collision < "$proof/collision.name"
[[ $status == 42 && $collision =~ ^vmkek_r21_[0-9a-f]{32}$ ]]
[[ ! -s "$proof/collision.out" && ! -e "$proof/collision.drop" && ! -e "$proof/collision.fixture" ]]
grep -Fxq "fixture database ownership unconfirmed for $collision; no deletion attempted" "$proof/collision.err"
printf '%s\n' 'r21 database creation collision preserved error, published no readiness and attempted no drop'

bash -c 'trap "" USR1; : > "$1"; exec sleep 15' bash "$proof/ignore.ready" &
sleeper=$!
remember_owned "$sleeper"
for ((attempt=0; attempt<40; attempt++)); do
    [[ -f $proof/ignore.ready ]] && break
    sleep .05
done
[[ -f $proof/ignore.ready ]]
signal_owned "$sleeper" USR1
! wait_owned_exit "$sleeper" 4
status=0
terminate_owned "$sleeper" 0 || status=$?
[[ $status == 143 ]]
printf '%s\n' 'r21 ignored cancellation kept the bounded wait, then reaped the owned child'
