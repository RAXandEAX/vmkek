#[cfg(target_os = "linux")]
mod linux {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::process::Command;

    use p256::ecdsa::SigningKey;
    use vmkek::crypto::authenticated::{
        BlockPurpose, BlockScope, BootstrapContext, BootstrapSealer, ManufacturerPin, MasterSecret,
        Platform, Profile, BOOTSTRAP_HASH_OFFSET, BOOTSTRAP_NONCE_OFFSET, BOOTSTRAP_SALT_OFFSET,
        BOOTSTRAP_TAG_OFFSET,
    };

    const SAMPLE: &[u8] = b"R02 process test";
    const RESTART_ARG: &str = "--r02-restart-sample";
    type Record = [u8; 72];

    pub(super) fn run() {
        if std::env::args().any(|arg| arg == RESTART_ARG) {
            std::io::stdout().write_all(&fresh_record()).unwrap();
            return;
        }

        let context = context();
        let master = MasterSecret::generate().unwrap();
        let scope = master.scope(context.scope).unwrap();
        let (signing, pin) = signing_material();
        let mut sealer = BootstrapSealer::new(&scope);
        let first = seal_record(&mut sealer, &context, &signing, &pin);
        assert_eq!(sequence(&first), 0);
        let (parent, child) =
            seal_across_fork(|| seal_record(&mut sealer, &context, &signing, &pin));
        assert_eq!(sequence(&parent), 1);
        assert_eq!(sequence(&child), 1);
        assert_distinct(&parent, &child);

        let first = exec_fresh_record();
        let second = exec_fresh_record();
        assert_eq!(sequence(&first), 0);
        assert_eq!(sequence(&second), 0);
        assert_distinct(&first, &second);
        println!("R02 process checks passed: inherited sealer after fork and two fresh executions");
    }

    fn context() -> BootstrapContext {
        BootstrapContext {
            platform: Platform::Pe32Plus,
            profile: Profile::Lab,
            scope: BlockScope {
                app: [1; 16],
                build: [2; 16],
                function: [3; 16],
                generation: [4; 16],
                level: 1,
                purpose: BlockPurpose::Payload,
            },
            payload_offset: 0x1000,
            payload_len: SAMPLE.len() as u32,
            original_entry_rva: 0x2000,
            preferred_base: 0x140000000,
        }
    }

    fn signing_material() -> (SigningKey, ManufacturerPin) {
        let signing = SigningKey::from_slice(&[1; 32]).unwrap();
        let point = signing.verifying_key().to_encoded_point(false);
        let pin = ManufacturerPin::from_sec1(point.as_bytes().try_into().unwrap()).unwrap();
        (signing, pin)
    }

    fn seal_record(
        sealer: &mut BootstrapSealer<'_>,
        context: &BootstrapContext,
        signing: &SigningKey,
        pin: &ManufacturerPin,
    ) -> Record {
        let sealed = sealer.seal(context, pin, signing, SAMPLE).unwrap();
        let mut record = [0; 72];
        record[..40]
            .copy_from_slice(&sealed.manifest[BOOTSTRAP_SALT_OFFSET..BOOTSTRAP_NONCE_OFFSET]);
        record[40..].copy_from_slice(&sealed.manifest[BOOTSTRAP_HASH_OFFSET..BOOTSTRAP_TAG_OFFSET]);
        record
    }

    fn sequence(record: &Record) -> u64 {
        u64::from_le_bytes(record[32..40].try_into().unwrap())
    }

    fn assert_distinct(first: &Record, second: &Record) {
        assert_ne!(first[..32], second[..32], "block salt");
        assert_ne!(first[40..], second[40..], "ciphertext digest");
    }

    fn fresh_record() -> Record {
        let context = context();
        let scope = MasterSecret::generate()
            .unwrap()
            .scope(context.scope)
            .unwrap();
        let (signing, pin) = signing_material();
        seal_record(&mut BootstrapSealer::new(&scope), &context, &signing, &pin)
    }

    fn exec_fresh_record() -> Record {
        let child = Command::new(std::env::current_exe().unwrap())
            .arg(RESTART_ARG)
            .output()
            .unwrap();
        assert!(child.status.success());
        child.stdout.try_into().expect("public manifest record")
    }

    fn seal_across_fork(seal: impl FnOnce() -> Record) -> (Record, Record) {
        let (mut parent_socket, mut child_socket) = UnixStream::pair().unwrap();
        // This harness-free process has no test runner or worker threads. Verify that
        // invariant before forking because the child will use allocating Rust APIs.
        assert_eq!(std::fs::read_dir("/proc/self/task").unwrap().count(), 1);
        // SAFETY: fork has no arguments and the process is single-threaded.
        let pid = unsafe { fork() };
        assert!(pid >= 0, "fork failed");
        if pid == 0 {
            drop(parent_socket);
            let written = child_socket.write_all(&seal()).is_ok();
            // SAFETY: _exit takes a status code and skips parent process teardown.
            unsafe { _exit(i32::from(!written)) }
        }
        drop(child_socket);
        let parent = seal();
        let mut child = [0; 72];
        let read = parent_socket.read_exact(&mut child);
        wait_child(pid);
        read.expect("child public manifest record");
        (parent, child)
    }

    fn wait_child(pid: i32) {
        let mut status = -1;
        loop {
            // SAFETY: pid identifies our child; status points to a writable int.
            let result = unsafe { waitpid(pid, &mut status, 0) };
            if result == pid {
                assert_eq!(status, 0, "child sealer failed");
                return;
            }
            let error = std::io::Error::last_os_error();
            assert_eq!(error.kind(), std::io::ErrorKind::Interrupted, "{error}");
        }
    }

    extern "C" {
        fn fork() -> i32;
        fn waitpid(pid: i32, status: *mut i32, options: i32) -> i32;
        fn _exit(status: i32) -> !;
    }
}

fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
}
