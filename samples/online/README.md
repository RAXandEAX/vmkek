# Windows Online sample

The Windows x64 PE links the Rust runtime and uses its v2 Online initializer, v1 buffer invocation, and typed receipt API on one handle. It checks the buffer and scalar against a local oracle, then prints a public summary only after the receipt and shutdown succeed. The VM package is fetched from the fixture at runtime. This sample has no detached DLL loading step. The separate R12 tests exercise the signed DLL bootstrap.

The fixture uses disposable PostgreSQL data, a TLS 1.3 loopback listener, independent ephemeral keys, and a synthetic buffer. It publishes equivalent Stack and Register packages and configures the fixed receipt operation. The launcher copies temporary credentials into a private Windows directory and deletes those copies at shutdown. The WSL launcher deletes the private fixture credentials and drops the database it created. Neither launcher installs trust roots or starts a production service.

## Run

Build the fixture in WSL and the client in an x64 MSVC environment on Windows.

~~~sh
cargo +1.95.0 build --locked -p vmkek-online-sample --bin r18_fixture
~~~

~~~powershell
cargo build --locked -p vmkek-online-sample --bin vmkek-online-sample
./samples/online/run.ps1 -ClientExe ./target/debug/vmkek-online-sample.exe -WslWorkspace $wslWorkspace -FixtureExe $wslFixtureExe -PostgresHome $wslPostgresHome
~~~

Supply absolute WSL paths. The PostgreSQL home contains an isolated PostgreSQL 16 instance listening on its Unix socket at port 55439, with the `r09` fixture role and tools under `pkg/usr/lib/postgresql/16/bin`. The launcher creates a fresh `vmkek_r18_*` database. The Windows host must be able to reach the WSL loopback listener through localhost.

The matrix covers equivalent outputs from distinct packages, superseded session/key denial, mismatched foreign device proof, the input limit, revoke, fresh restore, and unavailable server. Negative cases require empty success output. This is a functional integration fixture. It does not measure resistance to analysis or whole-process memory cleanup.

## Linux x64

Build the fixture and a non-PIE ELF in WSL:

~~~sh
cargo +1.95.0 build --locked -p vmkek-online-sample --bin r18_fixture
cargo +1.95.0 rustc --locked -p vmkek-online-sample --bin vmkek-online-sample -- \
  -C relocation-model=static -C link-arg=-no-pie
bash samples/online/run-linux.sh "$PWD/target/debug/vmkek-online-sample" \
  "$PWD/target/debug/r18_fixture" "$r21PostgresHome"
~~~

Use the same isolated PostgreSQL setup as the Windows fixture. The runner verifies ELF64 ET_EXEC x86-64 before starting, keeps its fixture directory under the current user's home, and needs GNU readelf, strace, and Python 3 with Linux pidfd support for the artifact and owned tracer checks. The fixture writes VMKR21 configuration and a separate software device key with owner-only permissions. The runtime rejects symlinked components, group- or other-writable ancestors, shared credential files, and inherited runtime calls after fork. The child test execs the sample to open fresh authority.

The native matrix also checks listener pause and resume on the same address, explicit revoke and restore, and SIGUSR1 cancellation of a call whose key request is waiting in the isolated PostgreSQL transaction. The tracer check observes only the sample process. It does not implement the Windows signed stop policy. PIE, Intel PT, hardware-backed device keys and broader CPU coverage remain outside this sample.
