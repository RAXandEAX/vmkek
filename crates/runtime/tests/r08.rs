mod common;

#[path = "common/r08.rs"]
mod r08;

use std::mem::size_of;
use std::thread;
use std::time::{Duration, Instant};

use vmkek_protocol::lab::ScalarType;
use vmkek_protocol::Budgets;
use vmkek_runtime::*;

struct Handle(VmkRuntime);

impl Drop for Handle {
    fn drop(&mut self) {
        assert_eq!(vmk_shutdown(self.0), Status::Ok as u32);
    }
}

fn bytes(value: &[u8]) -> VmkBytes {
    VmkBytes {
        data: value.as_ptr(),
        len: value.len() as u64,
    }
}

fn open(program: &[u8], depth: u8, budgets: Budgets, copy: bool) -> Result<Handle, u32> {
    let descriptor = r08::descriptor(program, depth, budgets, copy)
        .encode()
        .unwrap();
    let args = VmkInitializeV1 {
        size: size_of::<VmkInitializeV1>() as u32,
        abi_version: ABI_VERSION,
        profile: PROFILE_LAB,
        reserved: 0,
        descriptor: bytes(&descriptor),
        program: bytes(program),
    };
    let mut handle = 0;
    let status = unsafe { vmk_initialize(&args, &mut handle) };
    if status == Status::Ok as u32 {
        Ok(Handle(handle))
    } else {
        assert_eq!(handle, 0);
        Err(status)
    }
}

fn scalar(kind: ScalarType, bits: u64) -> VmkScalar {
    VmkScalar {
        kind: kind as u32,
        reserved: 0,
        bits,
    }
}

fn request(sequence: u64) -> VmkRequestId {
    let mut bytes = [0x08; 16];
    bytes[8..].copy_from_slice(&sequence.to_le_bytes());
    VmkRequestId { bytes }
}

fn invoke(handle: &Handle, args: &[VmkScalar], id: u64) -> (u32, VmkInvokeResultV1, [u8; 4]) {
    let input = [2, 7, 1, 8];
    let mut output = [0x5a; 4];
    let call = VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id: request(id),
        scalars: args.as_ptr(),
        scalar_count: args.len() as u64,
        input: bytes(&input),
        output: VmkOutput {
            data: output.as_mut_ptr(),
            capacity: output.len() as u64,
        },
    };
    let mut result = VmkInvokeResultV1 {
        size: size_of::<VmkInvokeResultV1>() as u32,
        abi_version: ABI_VERSION,
        scalar: scalar(ScalarType::U64, 0xfeed),
        output_len: u64::MAX,
    };
    let status = unsafe { vmk_invoke(handle.0, &call, &mut result) };
    (status, result, output)
}

fn no_output(status: Status, run: (u32, VmkInvokeResultV1, [u8; 4])) {
    assert_eq!(run.0, status as u32);
    assert_eq!(run.1.scalar, scalar(ScalarType::U64, 0xfeed));
    assert_eq!(run.1.output_len, u64::MAX);
    assert_eq!(run.2, [0x5a; 4]);
}

#[test]
fn all_depths_match_the_same_program_and_exact_fuel() {
    for kind in [ScalarType::U64, ScalarType::I64] {
        let program = r08::addition(kind, true).encode().unwrap();
        for (depth, fuel) in [(2, 9), (3, 12), (4, 15)] {
            let budgets = Budgets {
                fuel,
                ..Budgets::default()
            };
            let exact = open(&program, depth, budgets, true).unwrap();
            let short = open(
                &program,
                depth,
                Budgets {
                    fuel: fuel - 1,
                    ..budgets
                },
                true,
            )
            .unwrap();
            for (index, (left, right)) in [
                (0, 0),
                (u64::MAX, 1),
                (0xffff_ffff, 1),
                (i64::MAX as u64, 2),
            ]
            .into_iter()
            .enumerate()
            {
                let args = [scalar(kind, left), scalar(kind, right)];
                let (status, result, output) = invoke(&exact, &args, index as u64);
                let expected = (u128::from(left) + u128::from(right)) as u64;
                assert_eq!(status, Status::Ok as u32);
                assert_eq!(result.scalar, scalar(kind, expected));
                assert_eq!(result.output_len, 4);
                assert_eq!(output, [2, 7, 1, 8]);
                no_output(Status::ResourceLimit, invoke(&short, &args, index as u64));
            }
        }
    }
}

#[test]
fn typed_research_recursion_shares_fuel_and_preserves_old_formats() {
    let v3 = r08::recursive().encode_recursive().unwrap();
    let v2 = r08::recursive().encode().unwrap();
    assert_eq!(&v3[..2], &[3, 0]);
    assert_eq!(&v3[2..], &v2[2..]);
    assert!(
        matches!(open(&v3, 2, Budgets::default(), false), Err(status) if status == Status::Incompatible as u32)
    );
    assert!(
        matches!(open(&v2, 4, Budgets::default(), false), Err(status) if status == Status::InvalidPackage as u32)
    );
    let v1 = common::sample_program().encode().unwrap();
    assert!(
        matches!(open(&v1, 3, Budgets::default(), true), Err(status) if status == Status::Incompatible as u32)
    );

    for (depth, fuel) in [(3, 19), (4, 25)] {
        let budgets = Budgets {
            call_depth: 2,
            fuel,
            ..Budgets::default()
        };
        let exact = open(&v3, depth, budgets, false).unwrap();
        let short = open(
            &v3,
            depth,
            Budgets {
                fuel: fuel - 1,
                ..budgets
            },
            false,
        )
        .unwrap();
        let limited = open(
            &v3,
            depth,
            Budgets {
                call_depth: 1,
                ..budgets
            },
            false,
        )
        .unwrap();
        let args = [scalar(ScalarType::U64, 1)];
        let (status, result, output) = invoke(&exact, &args, 0);
        assert_eq!(status, Status::Ok as u32);
        assert_eq!(result.scalar, scalar(ScalarType::U64, 1));
        assert_eq!(result.output_len, 0);
        assert_eq!(output, [0x5a; 4]);
        no_output(Status::ResourceLimit, invoke(&short, &args, 0));
        no_output(Status::ResourceLimit, invoke(&limited, &args, 0));
        let (status, result, _) = invoke(&limited, &[scalar(ScalarType::U64, 0)], 1);
        assert_eq!(status, Status::Ok as u32);
        assert_eq!(result.scalar.bits, 0);
    }
}

#[test]
fn cancellation_during_a_deep_loop_preserves_the_result_and_allows_reentry() {
    use vmkek_protocol::lab::Instruction::{
        Add, Argument, Constant, CopyInput, Duplicate, Jump, JumpIfZero, Return,
    };
    use vmkek_protocol::lab::{LabModule, LabProgram};
    use vmkek_protocol::Scalar;

    let program = LabModule {
        functions: vec![LabProgram {
            arguments: vec![ScalarType::U64],
            result: Some(ScalarType::U64),
            instructions: vec![
                CopyInput,
                Argument(0),
                Duplicate,
                JumpIfZero(7),
                Constant(Scalar::U64(u64::MAX)),
                Add,
                Jump(2),
                Return,
            ],
        }],
    }
    .encode()
    .unwrap();
    let handle = open(&program, 4, Budgets::default(), true).unwrap();
    thread::scope(|threads| {
        let work = threads.spawn(|| invoke(&handle, &[scalar(ScalarType::U64, u64::MAX)], 0));
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            let status = vmk_cancel(handle.0, request(0));
            if status == Status::Ok as u32 {
                break;
            }
            assert_eq!(status, Status::NotFound as u32);
            assert!(Instant::now() < end);
            thread::yield_now();
        }
        no_output(Status::Cancelled, work.join().unwrap());
    });
    let (status, result, output) = invoke(&handle, &[scalar(ScalarType::U64, 1)], 1);
    assert_eq!(status, Status::Ok as u32);
    assert_eq!(result.scalar, scalar(ScalarType::U64, 0));
    assert_eq!(output, [2, 7, 1, 8]);
}

#[test]
#[ignore = "manual per-call latency ablation on the local ABI"]
fn r08_compare_depths() {
    let program = r08::addition(ScalarType::U64, false).encode().unwrap();
    let budgets = Budgets {
        fuel: 64,
        ..Budgets::default()
    };
    let handles = [2, 3, 4].map(|depth| open(&program, depth, budgets, false).unwrap());
    let mut times = [Vec::new(), Vec::new(), Vec::new()];
    let mut checksums = [0u64; 3];
    for turn in 0u64..10_000 {
        let left = turn.wrapping_mul(0x9e37_79b9);
        let right = u64::MAX.wrapping_sub(turn);
        let args = [
            scalar(ScalarType::U64, left),
            scalar(ScalarType::U64, right),
        ];
        for position in 0..3 {
            let index = (turn as usize + position) % 3;
            let start = Instant::now();
            let (status, result, output) = invoke(&handles[index], &args, turn);
            times[index].push(start.elapsed().as_nanos());
            assert_eq!(status, Status::Ok as u32);
            assert_eq!(
                result.scalar.bits,
                (u128::from(left) + u128::from(right)) as u64
            );
            assert_eq!(result.output_len, 0);
            assert_eq!(output, [0x5a; 4]);
            checksums[index] = checksums[index].wrapping_add(result.scalar.bits);
        }
    }
    assert_eq!(checksums, [checksums[0]; 3]);
    for (index, samples) in times.iter_mut().enumerate() {
        samples.sort_unstable();
        let p95 = (samples.len() * 95).div_ceil(100) - 1;
        eprintln!(
            "r08 depth {}: {} calls, {} bytes, fuel 64, p50 {} ns, p95 {} ns, checksum {}",
            index + 2,
            samples.len(),
            program.len(),
            samples[samples.len() / 2],
            samples[p95],
            checksums[index]
        );
    }
}
