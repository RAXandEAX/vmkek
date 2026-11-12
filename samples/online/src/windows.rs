use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::mem::size_of;
use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use p256::ecdsa::VerifyingKey;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use vmkek_protocol::SampleJob;
use vmkek_runtime::{
    invoke_sample_receipt, vmk_initialize, vmk_invoke, vmk_shutdown, Status, VmkBytes,
    VmkInitializeV2, VmkInvokeResultV1, VmkInvokeV1, VmkOutput, VmkRequestId, VmkRuntime,
    VmkScalar, ABI_VERSION, ONLINE_ABI_VERSION, PROFILE_ONLINE, SCALAR_I64, SCALAR_NONE,
};
use zeroize::Zeroizing;

const INPUT_LIMIT: usize = 4096;

pub fn run() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let (config, pin, input, mode) = match args.as_slice() {
        [config, pin, input] => (config, pin, input, Mode::Run),
        [config, pin, input, flag, directory] if flag == "--hold" => {
            (config, pin, input, Mode::Hold(Path::new(directory)))
        }
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        [config, pin, input, flag] if flag == "--fork-exec" => (config, pin, input, Mode::ForkExec),
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        [config, pin, input, flag, directory] if flag == "--cancel-signal" => {
            (config, pin, input, Mode::CancelSignal(Path::new(directory)))
        }

        _ => {
            eprintln!("Usage: vmkek-online-sample <trusted-config> <receipt-pin.sec1> <sample-input> [--hold <private-control-directory>]");
            return ExitCode::from(2);
        }
    };
    match execute(config, pin, input, mode) {
        Ok(Some(result)) => {
            println!("{}", result.public_line());
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

enum Mode<'a> {
    Run,
    Hold(&'a Path),
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    ForkExec,
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    CancelSignal(&'a Path),
}

struct ResultSummary {
    generation: [u8; 16],
    bytes: usize,
    digest: [u8; 32],
    receipt: u64,
}

impl ResultSummary {
    fn public_line(&self) -> String {
        format!(
            "online-ok generation={} bytes={} sha256={} scalar=-17 receipt={}",
            hex::encode(self.generation),
            self.bytes,
            hex::encode(self.digest),
            self.receipt,
        )
    }
}

fn execute(
    config: &OsStr,
    pin: &OsStr,
    input: &OsStr,
    mode: Mode<'_>,
) -> Result<Option<ResultSummary>, String> {
    let config = config
        .to_str()
        .filter(|value| Path::new(value).is_absolute())
        .ok_or("configuration must be an absolute UTF-8 path")?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let pin_path = pin;
    let pin = read_bounded(pin, 65)?;
    let receipt_pin = VerifyingKey::from_sec1_bytes(&pin)
        .ok()
        .filter(|_| pin.len() == 65 && pin[0] == 4)
        .ok_or("invalid receipt pin")?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    let exec_args = [OsStr::new(config), pin_path, input];
    let input = read_bounded(input, INPUT_LIMIT)?;
    let runtime = Runtime::open(config)?;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    if let Mode::CancelSignal(directory) = mode {
        let request_id = random_id()?;
        crate::linux::cancel_signal(runtime.handle(), request_id, directory, || {
            runtime.invoke_with_id(&input, request_id).map(|_| ())
        })?;
        runtime.close()?;
        println!("r21 SIGUSR1 cancelled active Online invocation without output");
        return Ok(None);
    }

    let output = runtime.invoke(&input)?;
    let job = SampleJob {
        job_id: random_id()?.bytes,
        units: 9,
    };
    let receipt = invoke_sample_receipt(
        runtime.handle(),
        random_id()?,
        job,
        &receipt_pin,
        Duration::from_secs(5),
    )
    .map_err(|status| format!("online-receipt status={}", status as u32))?;
    if receipt.value != job.receipt_value() {
        return Err("receipt oracle mismatch".into());
    }
    let summary = ResultSummary {
        generation: receipt.binding.generation_id,
        bytes: output.len(),
        digest: Sha256::digest(output.as_slice()).into(),
        receipt: receipt.value,
    };
    match mode {
        Mode::Run => {}
        Mode::Hold(directory) => held_retry(directory, &summary, &runtime, &input)?,
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        Mode::CancelSignal(_) => unreachable!("signal mode returned above"),
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        Mode::ForkExec => {
            crate::linux::fork_exec(runtime.handle(), exec_args)?;
            match runtime.invoke(&input) {
                Err(error) if error == "online-vm status=3" => {
                    println!("r21 parent superseded after child exec");
                }
                _ => return Err("parent retained authority after child exec".into()),
            }
        }
    }
    runtime.close()?;
    Ok(Some(summary))
}

fn held_retry(
    directory: &Path,
    summary: &ResultSummary,
    runtime: &Runtime,
    input: &[u8],
) -> Result<(), String> {
    if !directory.is_absolute() || !directory.is_dir() {
        return Err("hold control requires a private absolute directory".into());
    }
    let draft = directory.join("admitted.tmp");
    let mut admitted = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&draft)
        .map_err(|_| "could not write hold marker")?;
    writeln!(admitted, "{}", summary.public_line()).map_err(|_| "could not write hold marker")?;
    drop(admitted);
    std::fs::rename(draft, directory.join("admitted"))
        .map_err(|_| "could not publish hold marker")?;
    let until = Instant::now() + Duration::from_secs(8);
    while !directory.join("retry").is_file() {
        if Instant::now() >= until {
            return Err("hold control timed out".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    runtime.invoke(input)?;
    Ok(())
}

fn read_bounded(path: &OsStr, limit: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = File::open(path).map_err(|_| "could not open sample input")?;
    let metadata = file
        .metadata()
        .map_err(|_| "could not inspect sample input")?;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err("sample input exceeds its file or size constraint".into());
    }
    let mut buffer = Zeroizing::new(Vec::with_capacity(limit + 1));
    file.take(limit as u64 + 1)
        .read_to_end(&mut buffer)
        .map_err(|_| "could not read sample input")?;
    if buffer.len() > limit {
        return Err("sample input exceeds its file or size constraint".into());
    }
    Ok(buffer)
}

fn random_id() -> Result<VmkRequestId, String> {
    let mut bytes = [0; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| "entropy unavailable")?;
    if bytes == [0; 16] {
        return Err("entropy produced an invalid request identifier".into());
    }
    Ok(VmkRequestId { bytes })
}

struct Runtime(Option<VmkRuntime>);

impl Runtime {
    fn open(config: &str) -> Result<Self, String> {
        let init = VmkInitializeV2 {
            size: size_of::<VmkInitializeV2>() as u32,
            abi_version: ONLINE_ABI_VERSION,
            profile: PROFILE_ONLINE,
            reserved: 0,
            config_path: VmkBytes {
                data: config.as_ptr(),
                len: config.len() as u64,
            },
            reserved_tail: [0; 2],
        };
        let mut handle = 0;
        // SAFETY: init and config remain readable and the handle output is disjoint.
        let status = unsafe { vmk_initialize((&raw const init).cast(), &mut handle) };
        check_status("online-init", status)?;
        Ok(Self(Some(handle)))
    }

    fn handle(&self) -> VmkRuntime {
        self.0.expect("an open runtime owns its handle")
    }

    fn invoke(&self, input: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        self.invoke_with_id(input, random_id()?)
    }

    fn invoke_with_id(
        &self,
        input: &[u8],
        request_id: VmkRequestId,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut output = Zeroizing::new(vec![0; input.len()]);
        let scalar = VmkScalar {
            kind: SCALAR_I64,
            reserved: 0,
            bits: (-17_i64) as u64,
        };
        let call = VmkInvokeV1 {
            size: size_of::<VmkInvokeV1>() as u32,
            abi_version: ABI_VERSION,
            request_id,
            scalars: &scalar,
            scalar_count: 1,
            input: VmkBytes {
                data: input.as_ptr(),
                len: input.len() as u64,
            },
            output: VmkOutput {
                data: output.as_mut_ptr(),
                capacity: output.len() as u64,
            },
        };
        let mut result = VmkInvokeResultV1 {
            size: size_of::<VmkInvokeResultV1>() as u32,
            abi_version: ABI_VERSION,
            scalar: VmkScalar {
                kind: SCALAR_NONE,
                reserved: 0,
                bits: 0,
            },
            output_len: 0,
        };
        // SAFETY: all spans are live and output storage is exclusive and disjoint.
        let sentinel = result;
        let status = unsafe { vmk_invoke(self.handle(), &call, &mut result) };
        if status != Status::Ok as u32
            && (result != sentinel || output.iter().any(|byte| *byte != 0))
        {
            return Err("failed invocation modified caller output".into());
        }
        check_status("online-vm", status)?;
        if result.scalar != scalar
            || result.output_len != input.len() as u64
            || output.as_slice() != input
        {
            return Err("buffer oracle mismatch".into());
        }
        Ok(output)
    }

    fn close(mut self) -> Result<(), String> {
        let handle = self.0.take().expect("an open runtime owns its handle");
        check_status("online-shutdown", vmk_shutdown(handle))
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            vmk_shutdown(handle);
        }
    }
}

fn check_status(operation: &str, status: u32) -> Result<(), String> {
    if status == Status::Ok as u32 {
        Ok(())
    } else {
        Err(format!("{operation} status={status}"))
    }
}
