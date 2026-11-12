# R20 PostgreSQL recovery and rollout

## Checked recovery

This drill covers one isolated PostgreSQL 16 deployment and one app/build/history. It uses the same session store and signed admin revocation path as the online service. Checked boot is the explicit operator integration point. Existing unmarked local Lab fixtures retain their startup APIs.

1. Quiesce grants, renewals, publication, and all other database writers. Fence the old primary and its writers using independently managed routing and credentials. Keep the fence in force through capture, archive creation, recovery, and routing cutover. Supply the fence ID issued by that control plane. The database cannot attest that an external primary has stopped.
2. Connect to an authenticated trusted PostgreSQL 16 instance with a dedicated, reviewed role and an effective search path containing only `public`. Configure every pool connection with the same trusted role, effective search path and relation visibility. Preserve independently reviewed schema, role, migrations, server binaries and configuration. Keep the archive and restored state immutable until verification. Authenticate the archive and verify backup provenance before restore. A custom archive can execute database DDL. The snapshot attests specified data, migration rows/checksums and sequence state under this trust boundary. PostgreSQL admin, functions, triggers, DDL, privileges, and binaries remain trusted.
3. Use `vmkek_server::recovery::capture_checkpoint` with the deployment/app/build/history IDs, exact service and policy epochs, increasing external sequence and fence, and the independent checkpoint signing role. Publish the resulting exact signed digest as the latest checkpoint in a separate trusted authority. Keep the signing key and latest pointer outside PostgreSQL and backups. Take the custom-format archive while the writer fence still holds. Backups contain sensitive device and license state and activation-token hashes. Use owner-only storage and encrypted transport/retention.
4. Restore into a new private database from the authenticated archive. Construct `RecoveryProof` from the latest signed checkpoint, exact independently obtained latest digest/scope/fence/sequence, and independently pinned checkpoint verifying key. Provision the fixed or negotiated runtime mode, function, generation and signing key independently of the archive. Call `SessionStore::start_checked_recovery` with that trusted policy and grant signer. Checked boot compares the applied SQLx migration versions, success flags and checksums with the compiled migration set, and performs no migrations or persistent writes before proof acceptance. Bind the listener only after this call returns a store. Fresh trusted host time is required. A checkpoint is accepted for at most 15 minutes. The verifier locks the snapshot tables and checks the signed digest in the epoch-advancing transaction. Each DB lock wait is bounded at five seconds and each statement at 15 seconds. Snapshot version 1 supports up to 100,000 rows and uses the fixed PostgreSQL 16 binary record encoding, table/row ordering, migration checksums and sequence state.
5. If the checkpoint is missing, expired, mismatched or fails verification, keep service and minting disabled and locate the exact current verified archive. A DB marked by checkpoint capture requires checked startup. Ordinary startup is for unmarked Lab databases. The operator must independently protect and consume the latest fence/cutover authorization, because two separately restored copies can otherwise present the same valid proof. A second boot on the already advanced database denies the old checkpoint.
6. Confirm revocation and one-shot/replay outcomes before opening routing. A rollback may use compatible code and an authorized nonrevoked release under a higher policy epoch. Restoring an old epoch, unrevoking rights, or permitting the old primary to write would violate the recovery contract.

## Rotation and rollout

- TLS certificate rotation uses a separately provisioned TLS key. Verify the new trust chain, name, validity and TLS 1.3 connection from a canary client before moving traffic. Roll forward to a valid authorized certificate if the replacement fails. Keep signing role keys separate from the TLS role.
- Release signature rotation uses the root-pinned active/next trust bundle and monotonically increasing trust epoch. Publish newly signed verified releases, switch the trusted role, and revoke the compromised key/version. Rotate session grant and recovery checkpoint signing roles using independently updated pins and a controlled cutover. Keep keys outside the normal database. A managed signer and production certificate orchestration are deployment prerequisites. File-backed example credentials are for local drills.
- AEAD rotation builds a new immutable release using fresh key and nonce material through the existing packager. Provision keys only through the trusted build plane. Revoke the compromised release and verify denied retrieval/renewal. Keep plaintext keys and tokens out of telemetry.
- Canary a higher policy epoch on an isolated app/build before widening rollout. Compare checked readiness, TLS/renew/RPC failures, lease expiry, revocation lag, PostgreSQL lock time and rate-limit counts. Stop rollout on missing checkpoint authority, stale or untrusted state, unexpected grant after revoke, or unexpected sustained error/latency changes. Use a higher-epoch forward correction that retains all revocations.
- The TLS listener admits at most 128 connections. TLS handshake and HTTP handling are separately bounded. Online frame budgets, rates, and lease deadlines remain defined by the existing protocol and store. Track denied capacity, network failure and expiry separately. A network error ends or bounds local authority according to the existing lease and must not trigger a device ban. Physical HA, externally enforced single-writer fencing, managed signing and fleet-level canary/overload alerting are deployment work.

## Reproduce locally

Run against a disposable trusted PostgreSQL 16 socket owned by the test operator. The drill creates four fresh databases under a unique prefix and retains the owner-only archives for inspection. Use a new prefix and directory each time.

```sh
export VMKEK_R20_PG_SOCKET=/path/to/private/postgresql/socket
export VMKEK_R20_PG_BIN=/path/to/postgresql/16/bin
export VMKEK_R20_DUMP_DIR="$(mktemp -d)"
export VMKEK_R20_DB_PREFIX="vmkek_r20_$(date +%s)"
cargo +1.95.0 test --locked -p vmkek-protocol --test recovery
cargo +1.95.0 test --locked -p vmkek-server --test r20_recovery -- --ignored --nocapture
cargo +1.95.0 clippy --locked -p vmkek-server -p vmkek-protocol --all-targets -- -D warnings
```

The private fixture uses PostgreSQL role `r09` and port `55439`. It captures and dumps before and after a real signed admin revoke, restores both archives into separate databases, denies stale/current proof mismatches and data/sequence/migration changes, observes the lock gate before readiness, checks that a lower policy epoch is denied, and checks that a higher-epoch boot of the exact current restore retains revoke and replay denial while allowing a fresh eligible request. It also checks that an alternate Lab schema cannot hide the canonical recovery marker and that checked boot leaves an incomplete migration ledger and its missing table untouched. The independent checkpoint wire test covers exact envelope, signature pin, mutation and version rejection. The drill does not exercise loss of a physical node during renew/RPC, managed-key compromise, fleet load, or canary automation.

## Loopback admission and renewal loss

Run from the workspace root against the same private PostgreSQL 16 instance. The test uses only its own loopback listeners and fresh schemas in the disposable database. The shell removes that database after the tests and checks, including when a command fails.

```sh
(
  set -eu
  pg_home=/path/to/private/postgresql
  pg_socket="$pg_home/socket"
  pg_bin="$pg_home/pkg/usr/lib/postgresql/16/bin"
  db="vmkek_r10_r20_$(date +%s%N)"
  "$pg_bin/createdb" -h "$pg_socket" -p 55439 -U r09 "$db"
  trap '"$pg_bin/dropdb" -h "$pg_socket" -p 55439 -U r09 "$db"' EXIT
  export VMKEK_R10_PG_SOCKET="$pg_socket" VMKEK_R10_PG_DATABASE="$db"
  cargo +1.95.0 test --locked -p vmkek-server --test r10_sessions -- \
    --ignored --nocapture --test-threads=1
  cargo +1.95.0 clippy --locked -p vmkek-server --test r10_sessions -- -D warnings
  cargo +1.95.0 fmt -p vmkek-server -- --check
)
```

The live test held 128 completed TLS handshakes and refused the next one. A signed open succeeded after the held connections drained. For one device, 32 signed challenge requests reached a PostgreSQL license lock and the next received an empty HTTP 429. An independent device renewed during the wait. After releasing the lock, the 32 requests completed and the original device opened a session.

The renewal-loss test stops the owned listener and its connections after a real renew redemption reaches a PostgreSQL advisory barrier. The client loses its local grant and the stored sequence stays at 1. After restarting against the same database, an old renewal receives empty HTTP 410 and a fresh open succeeds with a new session ID. These tests cover local concurrency and listener loss during renew. Sustained rate, physical HA, managed key custody, fleet load, and automated canary remain untested here.


## Loopback typed receipt loss

Use a fresh database on the same private PostgreSQL 16 instance. The R15 fixture creates its own TLS listener and test-only PostgreSQL barrier. The shell drops the disposable database on exit, including after a test failure.

```sh
(
  set -eu
  pg_home=/path/to/private/postgresql
  pg_socket="$pg_home/socket"
  pg_bin="$pg_home/pkg/usr/lib/postgresql/16/bin"
  db="vmkek_r15_r20_$(date +%s%N)"
  "$pg_bin/createdb" -h "$pg_socket" -p 55439 -U r09 "$db"
  trap '"$pg_bin/dropdb" -h "$pg_socket" -p 55439 -U r09 "$db"' EXIT
  export VMKEK_R15_PG_SOCKET="$pg_socket" VMKEK_R15_PG_DATABASE="$db"
  cargo +1.95.0 test --locked -p vmkek-server --test r15_operations -- --ignored --nocapture
  cargo +1.95.0 clippy --locked -p vmkek-server --test r15_operations -- -D warnings
  cargo +1.95.0 fmt -p vmkek-server -- --check
)
```

The valid signed typed request reached the advisory lock in a `BEFORE INSERT` trigger on the receipt ledger. Stopping the listener closed the connection before the client received any HTTP bytes. After the barrier was released and removed, the request had no stored receipt. The restarted listener used the same address and current authority. The exact retry returned a receipt that verified under the independent receipt signer, with value 21. Another exact replay returned byte-identical data, and the single stored receipt matched the response. The scenario exercises interruption before INSERT completes. Loss while COMMIT is in flight and the commit outcome is ambiguous remains untested.
