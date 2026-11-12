use super::*;
use std::io::{self, Read};
use vmkek_protocol::lab::{Scalar, ScalarType};
use vmkek_runtime::SCALAR_I64;

const CASES: usize = 128;
struct Activation {
    handle: VmkRuntime,
    digest: Option<vmkek_protocol::Digest>,
    samples: Vec<vmkek_protocol::session_observation::ObservationSample>,
}

pub(super) fn run(profile: &str, seed: u32) {
    let (mode, debugger, integrity) = match profile {
        "baseline" => (None, false, false),
        "observe" => (Some(ObservationMode::Observe), true, true),
        "enforce" => (Some(ObservationMode::Enforce), true, true),
        "debugger-only" => (Some(ObservationMode::Enforce), true, false),
        "integrity-only" => (Some(ObservationMode::Enforce), false, true),
        _ => panic!("unknown assessment profile"),
    };
    assert_ne!(seed, 0);
    let (inputs, input_sha) = read_inputs();
    let build_id = seed_id(b"build", seed);
    let (descriptor, bytecode) = descriptor(seed, build_id);
    let (cpu_start, _) = resources();
    let start = Instant::now();
    let activation = match mode {
        Some(mode) => activate(mode, debugger, integrity, build_id, &descriptor, &bytecode),
        None => Activation {
            handle: plain(&descriptor, &bytecode),
            digest: None,
            samples: Vec::new(),
        },
    };
    let ready_ns = nanos(start.elapsed());
    match activation.digest {
        Some(digest) => println!(
            "policy sha256={:x} epoch=1",
            sha2::digest::generic_array::GenericArray::from(digest)
        ),
        None => println!("policy sha256=none epoch=0"),
    }
    for sample in &activation.samples {
        println!(
            "sample kind={:?} finding={:?} reason={:?}",
            sample.record.kind, sample.record.finding, sample.reason
        );
    }
    println!(
        "fixture seed={seed} profile={profile} bytecode_sha256={:x} input_sha256={input_sha} ready_ns={ready_ns}",
        Sha256::digest(&bytecode)
    );
    println!(
        "artifact descriptor={} program={}",
        hex_bytes(&descriptor),
        hex_bytes(&bytecode)
    );
    for (index, [left, right]) in inputs.into_iter().enumerate() {
        invoke_case(activation.handle, index, left, right);
    }
    close(activation.handle);
    let (cpu_end, private_bytes) = resources();
    println!(
        "done cpu_ns={} private_bytes={private_bytes}",
        (cpu_end - cpu_start) * 100
    );
}

fn read_inputs() -> (Vec<[u64; 2]>, String) {
    let mut text = String::new();
    io::stdin().take(8193).read_to_string(&mut text).unwrap();
    assert!(text.len() <= 8192);
    let inputs: Vec<_> = text
        .lines()
        .map(|line| {
            let (left, right) = line.split_once(' ').unwrap();
            [left.parse().unwrap(), right.parse().unwrap()]
        })
        .collect();
    assert_eq!(inputs.len(), CASES);
    (inputs, format!("{:x}", Sha256::digest(text.as_bytes())))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn seed_id(domain: &[u8], seed: u32) -> vmkek_protocol::Id {
    let mut hash = Sha256::new();
    hash.update(b"vmkek-lab-a09");
    hash.update(domain);
    hash.update(seed.to_le_bytes());
    hash.finalize()[..16].try_into().unwrap()
}

fn descriptor(seed: u32, build_id: vmkek_protocol::Id) -> (Vec<u8>, Vec<u8>) {
    let code = LabProgram {
        arguments: vec![ScalarType::I64; 2],
        result: Some(ScalarType::I64),
        instructions: vec![
            Instruction::Argument(0),
            Instruction::Argument(1),
            Instruction::Add,
            Instruction::Constant(Scalar::I64(i64::from(seed))),
            Instruction::Add,
            Instruction::Return,
        ],
    }
    .encode()
    .unwrap();
    let descriptor = VmDescriptor {
        abi_version: vmkek_protocol::ABI_VERSION,
        app_id: APP,
        build_id,
        function_id: [65; 16],
        generation_id: seed_id(b"generation", seed),
        form: VmForm::Stack,
        depth: 2,
        capabilities: vec![],
        program_sha256: Sha256::digest(&code).into(),
        budgets: Budgets::default(),
        profile: Profile::Lab,
        extensions: vec![],
    };
    (descriptor.encode().unwrap(), code)
}

fn activate(
    mode: ObservationMode,
    debugger: bool,
    integrity: bool,
    build_id: vmkek_protocol::Id,
    descriptor: &[u8],
    bytecode: &[u8],
) -> Activation {
    let anchor = Instant::now();
    let policy = policy_for_signals(mode, debugger, integrity.then_some(true), build_id);
    let verified = policy.verify();
    let digest = Sha256::digest(policy.signed.as_bytes()).into();
    let gate = Arc::new(ObservationGate::new(
        verified.observation_policy().unwrap(),
        anchor,
    ));
    let mut samples = Vec::new();
    if debugger {
        samples.push(debugger_attachment_sample(gate.begin_sample()).unwrap());
    }
    if integrity {
        let own = OwnedModule::from_address(owned_marker as *const () as usize).unwrap();
        let prepared = own
            .prepare_integrity(&verified, policy.context.now_ms)
            .unwrap();
        let (code, _) = prepared
            .observe_samples(&verified, policy.context.now_ms, gate.begin_sample())
            .unwrap();
        samples.extend(code);
    }
    gate.publish(samples.clone()).unwrap();
    let handle = initialize_observed_lab(descriptor, bytecode, gate).unwrap();
    Activation {
        handle,
        digest: Some(digest),
        samples,
    }
}

fn invoke_case(handle: u64, index: usize, left: u64, right: u64) {
    let args = [
        VmkScalar {
            kind: SCALAR_I64,
            reserved: 0,
            bits: left,
        },
        VmkScalar {
            kind: SCALAR_I64,
            reserved: 0,
            bits: right,
        },
    ];
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&((index + 1) as u64).to_le_bytes());
    let invocation = VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id: VmkRequestId { bytes: id },
        scalars: args.as_ptr(),
        scalar_count: args.len() as u64,
        input: VmkBytes {
            data: ptr::null(),
            len: 0,
        },
        output: VmkOutput {
            data: ptr::null_mut(),
            capacity: 0,
        },
    };
    let sentinel = VmkInvokeResultV1 {
        size: size_of::<VmkInvokeResultV1>() as u32,
        abi_version: ABI_VERSION,
        scalar: VmkScalar {
            kind: 0,
            reserved: 0,
            bits: 0,
        },
        output_len: 99,
    };
    let mut result = sentinel;
    let start = Instant::now();
    // SAFETY: argument and result storage are live and disjoint during the call.
    let status = unsafe { vmk_invoke(handle, &invocation, &mut result) };
    let elapsed = nanos(start.elapsed());
    println!(
        "result index={index} status={status} bits={} ns={elapsed} metadata={}",
        result.scalar.bits,
        if status == Status::Ok as u32 {
            result.scalar.kind == SCALAR_I64
                && result.scalar.reserved == 0
                && result.output_len == 0
        } else {
            result == sentinel
        }
    );
}
