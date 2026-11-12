mod common;

use std::mem::size_of;
use std::ptr::{null, null_mut};
use std::thread;
use std::time::{Duration, Instant};

use vmkek_protocol::lab::{Instruction, LabProgram, ScalarType};
use vmkek_protocol::{Budgets, MAX_BODY_BYTES};
use vmkek_runtime::*;

const EMPTY: VmkBytes = VmkBytes {
    data: null(),
    len: 0,
};
const EMPTY_OUTPUT: VmkOutput = VmkOutput {
    data: null_mut(),
    capacity: 0,
};
const UNSIGNED: VmkScalar = VmkScalar {
    kind: SCALAR_U64,
    reserved: 0,
    bits: 1,
};
const SIGNED: VmkScalar = VmkScalar {
    kind: SCALAR_I64,
    reserved: 0,
    bits: u64::MAX - 9,
};

fn bytes(value: &[u8]) -> VmkBytes {
    VmkBytes {
        data: value.as_ptr(),
        len: value.len() as u64,
    }
}

fn writable(value: &mut [u8]) -> VmkOutput {
    VmkOutput {
        data: value.as_mut_ptr(),
        capacity: value.len() as u64,
    }
}

fn init(descriptor: &[u8], program: &[u8]) -> VmkInitializeV1 {
    VmkInitializeV1 {
        size: size_of::<VmkInitializeV1>() as u32,
        abi_version: ABI_VERSION,
        profile: PROFILE_LAB,
        reserved: 0,
        descriptor: bytes(descriptor),
        program: bytes(program),
    }
}

fn request(tag: u8) -> VmkRequestId {
    VmkRequestId { bytes: [tag; 16] }
}

fn invocation(tag: u8, scalars: &[VmkScalar]) -> VmkInvokeV1 {
    VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id: request(tag),
        scalars: scalars.as_ptr(),
        scalar_count: scalars.len() as u64,
        input: EMPTY,
        output: EMPTY_OUTPUT,
    }
}

fn result() -> VmkInvokeResultV1 {
    VmkInvokeResultV1 {
        size: size_of::<VmkInvokeResultV1>() as u32,
        abi_version: ABI_VERSION,
        scalar: UNSIGNED,
        output_len: u64::MAX,
    }
}

fn initialize(call: &VmkInitializeV1, expected: Status) -> VmkRuntime {
    let mut output = u64::MAX;
    assert_eq!(
        unsafe { vmk_initialize(call, &mut output) },
        expected as u32
    );
    if expected != Status::Ok {
        assert_eq!(output, u64::MAX);
    }
    output
}

struct Live(VmkRuntime);

impl Drop for Live {
    fn drop(&mut self) {
        vmk_shutdown(self.0);
    }
}

fn open(program: LabProgram, budgets: Budgets, copy: bool) -> Live {
    let program = program.encode().unwrap();
    let descriptor = common::descriptor(&program, budgets, copy)
        .encode()
        .unwrap();
    Live(initialize(&init(&descriptor, &program), Status::Ok))
}

fn invoke(handle: VmkRuntime, args: &VmkInvokeV1, expected: Status) -> VmkInvokeResultV1 {
    let mut out = result();
    assert_eq!(
        unsafe { vmk_invoke(handle, args, &mut out) },
        expected as u32
    );
    if expected != Status::Ok {
        assert_eq!(out, result());
    }
    out
}

#[test]
fn c_layout_and_copy_semantics() {
    assert_eq!(size_of::<VmkInitializeV1>(), 48);
    assert_eq!(size_of::<VmkInvokeV1>(), 72);
    assert_eq!(size_of::<VmkInvokeResultV1>(), 32);
    assert_eq!(std::mem::offset_of!(VmkInvokeV1, output), 56);

    let runtime = open(common::sample_program(), Budgets::default(), true);
    let input = [0, 1, 127, 255];
    let mut output = [9; 8];
    let scalars = [UNSIGNED, SIGNED];
    let mut call = invocation(1, &scalars);
    call.input = bytes(&input);
    call.output = writable(&mut output);
    let out = invoke(runtime.0, &call, Status::Ok);
    assert_eq!(
        out.scalar,
        VmkScalar {
            kind: SCALAR_I64,
            reserved: 0,
            bits: u64::MAX - 16
        }
    );
    assert_eq!(out.output_len, input.len() as u64);
    assert_eq!(&output[..4], &input);
    assert_eq!(&output[4..], &[9; 4]);
    assert_eq!(
        vmk_cancel(runtime.0, call.request_id),
        Status::NotFound as u32
    );

    let empty = invoke(runtime.0, &invocation(2, &scalars), Status::Ok);
    assert_eq!(empty.output_len, 0);
}

#[test]
fn invalid_initialization_keeps_the_handle_untouched() {
    let program = common::sample_program().encode().unwrap();
    let descriptor = common::descriptor(&program, Budgets::default(), true)
        .encode()
        .unwrap();
    let mut call = init(&descriptor, &program);
    call.abi_version = 99;
    initialize(&call, Status::Incompatible);
    call.abi_version = ABI_VERSION;
    call.size -= 1;
    initialize(&call, Status::Incompatible);
    call.size += 1;
    call.profile = PROFILE_ONLINE;
    initialize(&call, Status::Unavailable);
    call.profile = PROFILE_LAB;
    call.program = EMPTY;
    initialize(&call, Status::InvalidPackage);
    call.program.len = MAX_BODY_BYTES as u64 + 1;
    initialize(&call, Status::ResourceLimit);
    let mut descriptor = descriptor;
    descriptor[0] = 99;
    initialize(&init(&descriptor, &program), Status::Incompatible);
}

#[test]
fn verifier_failures_return_without_publishing_a_handle() {
    let sample = common::sample_program().encode().unwrap();
    let mut bad_code = sample.clone();
    *bad_code.last_mut().unwrap() ^= 0xff;
    let invalid_jump = LabProgram {
        arguments: vec![],
        result: None,
        instructions: vec![Instruction::Jump(1)],
    }
    .encode()
    .unwrap();
    let invalid_stack = LabProgram {
        arguments: vec![],
        result: None,
        instructions: vec![Instruction::Add, Instruction::Return],
    }
    .encode()
    .unwrap();
    let descriptor = common::descriptor(&sample, Budgets::default(), true)
        .encode()
        .unwrap();
    initialize(&init(&descriptor, &bad_code), Status::InvalidPackage);
    for program in [&sample, &bad_code, &invalid_jump, &invalid_stack] {
        let descriptor = common::descriptor(program, Budgets::default(), false)
            .encode()
            .unwrap();
        initialize(&init(&descriptor, program), Status::InvalidPackage);
    }
}

#[test]
fn overlapping_metadata_is_rejected_before_its_prefix_is_read() {
    let alias = std::ptr::dangling_mut::<VmkRuntime>();
    assert_eq!(
        unsafe { vmk_initialize(alias.cast(), alias) },
        Status::InvalidArgument as u32,
    );
    let out = alias.cast::<VmkInvokeResultV1>();
    assert_eq!(
        unsafe { vmk_invoke(0, out.cast(), out) },
        Status::InvalidArgument as u32,
    );
}

#[test]
fn unsigned_results_preserve_all_64_bits() {
    let program = LabProgram {
        arguments: vec![ScalarType::U64],
        result: Some(ScalarType::U64),
        instructions: vec![Instruction::Argument(0), Instruction::Return],
    };
    let runtime = open(program, Budgets::default(), false);
    let scalar = VmkScalar {
        bits: u64::MAX,
        ..UNSIGNED
    };
    let out = invoke(runtime.0, &invocation(1, &[scalar]), Status::Ok);
    assert_eq!(out.scalar, scalar);
}

#[test]
fn invalid_output_ranges_and_capacity_do_not_change_caller_memory() {
    let runtime = open(common::sample_program(), Budgets::default(), true);
    let mut input = [0, 1, 2, 3];
    let mut output = [9; 2];
    let scalars = [UNSIGNED, SIGNED];
    let mut call = invocation(1, &scalars);
    call.input = bytes(&input);
    call.output = writable(&mut output);
    invoke(runtime.0, &call, Status::OutputTooSmall);
    assert_eq!(output, [9; 2]);
    call.output = writable(&mut input);
    invoke(runtime.0, &call, Status::InvalidArgument);
    assert_eq!(input, [0, 1, 2, 3]);
    call.output = VmkOutput {
        data: null_mut(),
        capacity: 1,
    };
    invoke(runtime.0, &call, Status::InvalidArgument);
    call.output = VmkOutput {
        data: usize::MAX as *mut u8,
        capacity: 2,
    };
    invoke(runtime.0, &call, Status::InvalidArgument);
    call.output = EMPTY_OUTPUT;
    call.scalar_count = u64::MAX;
    invoke(runtime.0, &call, Status::ResourceLimit);
}

fn loop_program() -> LabProgram {
    LabProgram {
        arguments: vec![ScalarType::U64],
        result: None,
        instructions: vec![
            Instruction::Argument(0),
            Instruction::JumpIfZero(0),
            Instruction::Return,
        ],
    }
}

#[test]
fn fuel_exhaustion_discards_previously_staged_output() {
    let budgets = Budgets {
        fuel: 8,
        ..Budgets::default()
    };
    let mut program = loop_program();
    program.instructions.insert(0, Instruction::CopyInput);
    program.instructions[2] = Instruction::JumpIfZero(1);
    let runtime = open(program, budgets, true);
    let scalars = [VmkScalar {
        bits: 0,
        ..UNSIGNED
    }];
    let input = [1, 2];
    let mut output = [0xa5; 4];
    let mut call = invocation(1, &scalars);
    call.input = bytes(&input);
    call.output = writable(&mut output);
    invoke(runtime.0, &call, Status::ResourceLimit);
    assert_eq!(output, [0xa5; 4]);

    let scalars = [UNSIGNED];
    call.request_id = request(2);
    call.scalars = scalars.as_ptr();
    let success = invoke(runtime.0, &call, Status::Ok);
    assert_eq!(success.output_len, 2);
    assert_eq!(output, [1, 2, 0xa5, 0xa5]);
}

#[test]
fn cancel_a_live_c_call_and_reuse_the_runtime() {
    let runtime = open(loop_program(), Budgets::default(), false);
    let handle = runtime.0;
    let runner = thread::spawn(move || {
        let scalars = [VmkScalar {
            bits: 0,
            ..UNSIGNED
        }];
        invoke(handle, &invocation(1, &scalars), Status::Cancelled);
    });
    let timeout = Instant::now() + Duration::from_secs(3);
    loop {
        let status = vmk_cancel(handle, request(1));
        if status == Status::Ok as u32 {
            break;
        }
        assert_eq!(status, Status::NotFound as u32);
        assert!(Instant::now() < timeout, "invocation did not register");
        thread::yield_now();
    }
    runner.join().unwrap();
    invoke(handle, &invocation(2, &[UNSIGNED]), Status::Ok);
    assert_eq!(vmk_shutdown(handle), Status::Ok as u32);
    invoke(handle, &invocation(3, &[UNSIGNED]), Status::NotFound);
}

fn open_r06(program: &LabProgram, fuel: u64, enabled: bool, expected: Status) -> Live {
    let program = program.encode().unwrap();
    let budgets = Budgets {
        fuel,
        ..Budgets::default()
    };
    let mut descriptor = common::descriptor(&program, budgets, false);
    if enabled {
        descriptor.capabilities.push(vmkek_protocol::Capability {
            id: vmkek_protocol::R06_FUSION_CAPABILITY,
            required: false,
        });
    }
    let descriptor = descriptor.encode().unwrap();
    Live(initialize(&init(&descriptor, &program), expected))
}

fn fused_pair() -> LabProgram {
    use Instruction::{Add, Argument, Constant, Return};
    LabProgram {
        arguments: vec![ScalarType::I64],
        result: Some(ScalarType::I64),
        instructions: vec![
            Argument(0),
            Constant(vmkek_protocol::Scalar::I64(i64::MAX)),
            Add,
            Constant(vmkek_protocol::Scalar::I64(4)),
            Add,
            Return,
        ],
    }
}

#[test]
fn r06_preserves_signed_results_and_exact_fuel_through_the_abi() {
    let program = fused_pair();
    let baseline = open_r06(&program, 6, false, Status::Ok);
    let mut arg = SIGNED;
    arg.bits = 5;
    let values = [arg];
    let call = invocation(1, &values);
    let expected = (i64::MAX as u64).wrapping_add(9);
    assert_eq!(invoke(baseline.0, &call, Status::Ok).scalar.bits, expected);
    if !vmkek_protocol::lab::r06_fusion_available() {
        open_r06(&program, 6, true, Status::Incompatible);
        return;
    }

    for enabled in [false, true] {
        let exact = open_r06(&program, 6, enabled, Status::Ok);
        let short = open_r06(&program, 5, enabled, Status::Ok);
        assert_eq!(invoke(exact.0, &call, Status::Ok).scalar.bits, expected);
        invoke(short.0, &call, Status::ResourceLimit);
    }
}

#[test]
fn r06_preserves_branch_ingress_and_cancels_a_live_fused_loop() {
    if !vmkek_protocol::lab::r06_fusion_available() {
        return;
    }
    use Instruction::{Argument, JumpIfZero};
    let mut branch = fused_pair();
    branch.arguments.push(ScalarType::U64);
    branch.instructions.insert(1, Argument(1));
    branch.instructions.insert(2, JumpIfZero(5));
    let mut looped = fused_pair();
    looped.arguments.push(ScalarType::U64);
    looped.instructions.insert(5, Argument(1));
    looped.instructions.insert(6, JumpIfZero(1));

    for enabled in [false, true] {
        let branch_handle = open_r06(&branch, 12, enabled, Status::Ok);
        let values = [
            SIGNED,
            VmkScalar {
                bits: 0,
                ..UNSIGNED
            },
        ];
        let result = invoke(branch_handle.0, &invocation(1, &values), Status::Ok);
        assert_eq!(result.scalar.bits, SIGNED.bits.wrapping_add(4));

        let loop_handle = open_r06(&looped, vmkek_protocol::MAX_FUEL, enabled, Status::Ok);
        let handle = loop_handle.0;
        let runner = thread::spawn(move || {
            invoke(handle, &invocation(2, &values), Status::Cancelled);
        });
        let timeout = Instant::now() + Duration::from_secs(3);
        while vmk_cancel(handle, request(2)) == Status::NotFound as u32 {
            assert!(Instant::now() < timeout, "fused loop did not register");
            thread::yield_now();
        }
        runner.join().unwrap();
    }
}

#[test]
#[ignore = "manual baseline/candidate timing on the local C ABI"]
fn r06_ablation() {
    assert!(
        vmkek_protocol::lab::r06_fusion_available(),
        "R06 proof admission required"
    );
    let program = fused_pair();
    let baseline = open_r06(&program, 6, false, Status::Ok);
    let candidate = open_r06(&program, 6, true, Status::Ok);
    let mut baseline_times = Vec::new();
    let mut candidate_times = Vec::new();
    for round in 0..7 {
        let runs = if round % 2 == 0 {
            [(false, baseline.0), (true, candidate.0)]
        } else {
            [(true, candidate.0), (false, baseline.0)]
        };
        for (enabled, handle) in runs {
            let (elapsed, checksum) = timed_fused_calls(handle, round);
            assert_eq!(checksum, 0x2e0bd3baf166c808);
            if enabled {
                candidate_times.push(elapsed);
            } else {
                baseline_times.push(elapsed);
            }
        }
    }
    baseline_times.sort_unstable();
    candidate_times.sort_unstable();
    let baseline = baseline_times[3];
    let candidate = candidate_times[3];
    eprintln!(
        "r06 ablation: 7 pairs, 50000 calls/batch, program bytes {}, checksum matched, baseline median {baseline} ns, candidate median {candidate} ns",
        program.encode().unwrap().len()
    );
}

fn timed_fused_calls(handle: VmkRuntime, round: u64) -> (u128, u64) {
    let start = Instant::now();
    let mut checksum = 0u64;
    for index in 0u64..50_000 {
        let arg = VmkScalar {
            bits: index.wrapping_mul(0x9e37_79b9),
            ..SIGNED
        };
        let args = [arg];
        let mut call = invocation(1, &args);
        call.request_id.bytes[..8].copy_from_slice(&(index + 1).to_le_bytes());
        call.request_id.bytes[8..].copy_from_slice(&round.to_le_bytes());
        let result = invoke(handle, std::hint::black_box(&call), Status::Ok);
        checksum = checksum.wrapping_add(result.scalar.bits);
    }
    (start.elapsed().as_nanos(), checksum)
}
