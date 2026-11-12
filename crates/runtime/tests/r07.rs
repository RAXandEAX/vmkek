mod common;

#[path = "common/r07.rs"]
mod r07;

use std::mem::size_of;
use std::sync::Barrier;
use std::thread;
use std::time::{Duration, Instant};

use r07::{module, Form};
use vmkek_protocol::lab::{Instruction, ScalarType};
use vmkek_protocol::{Budgets, MAX_FUEL};
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

fn open(descriptor: &[u8], bytecode: &[u8]) -> Result<Handle, u32> {
    let args = VmkInitializeV1 {
        size: size_of::<VmkInitializeV1>() as u32,
        abi_version: ABI_VERSION,
        profile: PROFILE_LAB,
        reserved: 0,
        descriptor: bytes(descriptor),
        program: bytes(bytecode),
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

fn handle(form: Form, program: &[u8], budgets: Budgets, generation: u8) -> Handle {
    let descriptor = form
        .descriptor(program, budgets, generation)
        .encode()
        .unwrap();
    open(&descriptor, program).unwrap()
}

fn request(worker: u8, sequence: u64) -> VmkRequestId {
    let mut bytes = [worker; 16];
    bytes[8..].copy_from_slice(&sequence.to_le_bytes());
    VmkRequestId { bytes }
}

fn scalar(value: u64) -> VmkScalar {
    VmkScalar {
        kind: SCALAR_U64,
        reserved: 0,
        bits: value,
    }
}

fn call(
    handle: VmkRuntime,
    scalars: &[VmkScalar],
    id: VmkRequestId,
) -> (u32, VmkInvokeResultV1, [u8; 4]) {
    let input = [3, 1, 4, 1];
    let mut output = [0xa5; 4];
    let call = VmkInvokeV1 {
        size: size_of::<VmkInvokeV1>() as u32,
        abi_version: ABI_VERSION,
        request_id: id,
        scalars: scalars.as_ptr(),
        scalar_count: scalars.len() as u64,
        input: bytes(&input),
        output: VmkOutput {
            data: output.as_mut_ptr(),
            capacity: output.len() as u64,
        },
    };
    let mut result = VmkInvokeResultV1 {
        size: size_of::<VmkInvokeResultV1>() as u32,
        abi_version: ABI_VERSION,
        scalar: scalar(u64::MAX),
        output_len: u64::MAX,
    };
    let status = unsafe { vmk_invoke(handle, &call, &mut result) };
    (status, result, output)
}

fn assert_call(handle: VmkRuntime, values: [u64; 3], id: VmkRequestId) -> u64 {
    let (status, result, output) = call(handle, &values.map(scalar), id);
    let addend = if values[2] == 0 { 8 } else { 3 };
    let expected = values[0].wrapping_add(addend).wrapping_add(17);
    assert_eq!(status, Status::Ok as u32);
    assert_eq!(result.scalar, scalar(expected));
    assert_eq!(result.output_len, 4);
    assert_eq!(output, [3, 1, 4, 1]);
    expected
}

#[test]
fn same_v1_and_v2_bytes_execute_across_three_forms() {
    let v1 = common::sample_program().encode().unwrap();
    let v2 = module().encode().unwrap();
    assert_eq!(v1[..2], [1, 0]);
    assert_eq!(v2[..2], [2, 0]);
    assert!(module().functions[0].encode().is_err());

    for form in Form::ALL {
        let old = handle(form, &v1, Budgets::default(), 4);
        let args = [
            scalar(1),
            VmkScalar {
                kind: SCALAR_I64,
                ..scalar(10)
            },
        ];
        let (status, result, output) = call(old.0, &args, request(1, 1));
        assert_eq!(status, Status::Ok as u32);
        assert_eq!(
            result.scalar,
            VmkScalar {
                kind: SCALAR_I64,
                ..scalar(3)
            }
        );
        assert_eq!(output, [3, 1, 4, 1]);

        let runtime = handle(form, &v2, Budgets::default(), 5);
        for (index, values) in [[0, 0, 0], [1, 1, 1], [2, 16, 0], [u64::MAX, 3, 1]]
            .into_iter()
            .enumerate()
        {
            assert_call(runtime.0, values, request(1, index as u64));
        }
    }
}

#[test]
fn same_handle_concurrent_and_repeated_calls_keep_private_frames() {
    let program = module().encode().unwrap();
    for form in Form::ALL {
        let runtime = handle(form, &program, Budgets::default(), 11);
        let barrier = Barrier::new(2);
        thread::scope(|threads| {
            for worker in 1..=2 {
                let barrier = &barrier;
                let handle = runtime.0;
                threads.spawn(move || {
                    barrier.wait();
                    for turn in 0..64 {
                        assert_call(
                            handle,
                            [turn + u64::from(worker), turn % 5, turn % 2],
                            request(worker, turn),
                        );
                    }
                });
            }
        });
    }
}

#[test]
fn invalid_calls_versions_and_depth_never_publish_outputs() {
    for target in [0, 2] {
        let mut invalid = module();
        invalid.functions[0].instructions[14] = Instruction::Call(target);
        let bytes = invalid.encode().unwrap();
        let descriptor = Form::Mixed
            .descriptor(&bytes, Budgets::default(), 6)
            .encode()
            .unwrap();
        assert!(
            matches!(open(&descriptor, &bytes), Err(status) if status == Status::InvalidPackage as u32)
        );
    }
    let mut invalid = module();
    invalid.functions[1].arguments[0] = ScalarType::I64;
    let bytes = invalid.encode().unwrap();
    let descriptor = Form::Register
        .descriptor(&bytes, Budgets::default(), 6)
        .encode()
        .unwrap();
    assert!(
        matches!(open(&descriptor, &bytes), Err(status) if status == Status::InvalidPackage as u32)
    );
    let mut bytes = module().encode().unwrap();
    bytes[0] = 3;
    let descriptor = Form::Mixed
        .descriptor(&bytes, Budgets::default(), 6)
        .encode()
        .unwrap();
    assert!(
        matches!(open(&descriptor, &bytes), Err(status) if status == Status::Incompatible as u32)
    );

    let program = module().encode().unwrap();
    let budgets = Budgets {
        call_depth: 1,
        ..Budgets::default()
    };
    let runtime = handle(Form::Mixed, &program, budgets, 9);
    let (status, result, output) = call(runtime.0, &[scalar(0); 3], request(1, 0));
    assert_eq!(status, Status::ResourceLimit as u32);
    assert_eq!(result.output_len, u64::MAX);
    assert_eq!(result.scalar, scalar(u64::MAX));
    assert_eq!(output, [0xa5; 4]);
}

#[test]
fn parent_failure_discards_output_prepared_by_the_nested_call() {
    let program = module().encode().unwrap();
    let args = [scalar(1), scalar(0), scalar(1)];
    for form in Form::ALL {
        let budgets = Budgets {
            fuel: 21,
            ..Budgets::default()
        };
        let short = handle(form, &program, budgets, 20);
        let (status, result, output) = call(short.0, &args, request(1, 0));
        assert_eq!(status, Status::ResourceLimit as u32);
        assert_eq!(result.output_len, u64::MAX);
        assert_eq!(result.scalar, scalar(u64::MAX));
        assert_eq!(output, [0xa5; 4]);

        let budgets = Budgets {
            fuel: 22,
            ..budgets
        };
        let exact = handle(form, &program, budgets, 20);
        assert_call(exact.0, [1, 0, 1], request(1, 0));
    }
}

#[test]
fn cancellation_cleans_a_mixed_invocation_before_reentry() {
    let program = module().encode().unwrap();
    let budgets = Budgets {
        fuel: MAX_FUEL,
        ..Budgets::default()
    };
    let runtime = handle(Form::Mixed, &program, budgets, 15);
    let handle = runtime.0;
    let id = request(1, 0);
    let worker = thread::spawn(move || call(handle, &[scalar(1), scalar(u64::MAX), scalar(1)], id));
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        let status = vmk_cancel(handle, id);
        if status == Status::Ok as u32 {
            break;
        }
        assert_eq!(status, Status::NotFound as u32);
        assert!(Instant::now() < end);
        thread::yield_now();
    }
    let (status, result, output) = worker.join().unwrap();
    assert_eq!(status, Status::Cancelled as u32);
    assert_eq!(result.output_len, u64::MAX);
    assert_eq!(result.scalar, scalar(u64::MAX));
    assert_eq!(output, [0xa5; 4]);
    assert_call(handle, [4, 2, 1], request(1, 1));
}

#[test]
#[ignore = "manual three-form timing with owned C ABI fixture"]
fn r07_compare_forms() {
    let program = module().encode().unwrap();
    let handles = Form::ALL.map(|form| handle(form, &program, Budgets::default(), 42));
    let mut times = [Vec::new(), Vec::new(), Vec::new()];
    let mut expected = None;
    for round in 0..7 {
        for position in 0..Form::ALL.len() {
            let index = (round + position) % Form::ALL.len();
            let (elapsed, checksum) = timed_calls(handles[index].0, round as u8 + 1);
            if let Some(expected) = expected {
                assert_eq!(checksum, expected);
            }
            expected = Some(checksum);
            times[index].push(elapsed);
        }
    }
    for (form, times) in Form::ALL.into_iter().zip(&mut times) {
        times.sort_unstable();
        eprintln!(
            "r07 {}: 7 batches of 5000 calls, {} bytes, median {} ns, checksum {}",
            form.name(),
            program.len(),
            times[3],
            expected.unwrap()
        );
    }
}

fn timed_calls(handle: VmkRuntime, round: u8) -> (u128, u64) {
    let mut checksum = 0u64;
    let start = Instant::now();
    for index in 0u64..5_000 {
        let values = [index.wrapping_mul(0x9e37_79b9), index % 8, index % 2];
        checksum = checksum.wrapping_add(assert_call(handle, values, request(round, index)));
    }
    (start.elapsed().as_nanos(), checksum)
}
