use std::mem::{align_of, size_of};
use std::ops::Range;

use crate::Status;

pub const ABI_VERSION: u32 = 1;
pub const ONLINE_ABI_VERSION: u32 = 2;
pub const PROFILE_LAB: u32 = 1;
pub const PROFILE_ONLINE: u32 = 2;
pub const SCALAR_NONE: u32 = 0;
pub const SCALAR_U64: u32 = 1;
pub const SCALAR_I64: u32 = 2;

#[repr(C)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct VmkRequestId {
    pub bytes: [u8; 16],
}

impl VmkRequestId {
    pub(crate) fn validate(self) -> Result<Self, Status> {
        if self.bytes == [0; 16] {
            return Err(Status::InvalidArgument);
        }
        Ok(self)
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmkBytes {
    pub data: *const u8,
    pub len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmkOutput {
    pub data: *mut u8,
    pub capacity: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmkScalar {
    pub kind: u32,
    pub reserved: u32,
    pub bits: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmkInitializeV1 {
    pub size: u32,
    pub abi_version: u32,
    pub profile: u32,
    pub reserved: u32,
    pub descriptor: VmkBytes,
    pub program: VmkBytes,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmkInitializeV2 {
    pub size: u32,
    pub abi_version: u32,
    pub profile: u32,
    pub reserved: u32,
    pub config_path: VmkBytes,
    pub reserved_tail: [u64; 2],
}

const _: () = assert!(size_of::<VmkInitializeV1>() == size_of::<VmkInitializeV2>());

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VmkInvokeV1 {
    pub size: u32,
    pub abi_version: u32,
    pub request_id: VmkRequestId,
    pub scalars: *const VmkScalar,
    pub scalar_count: u64,
    pub input: VmkBytes,
    pub output: VmkOutput,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VmkInvokeResultV1 {
    pub size: u32,
    pub abi_version: u32,
    pub scalar: VmkScalar,
    pub output_len: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Header {
    size: u32,
    abi_version: u32,
}

pub(crate) struct Span {
    pub range: Range<usize>,
    pub count: usize,
}

impl Span {
    pub(crate) fn new<T>(ptr: *const T, count: u64, max: usize) -> Result<Self, Status> {
        let count = usize::try_from(count).map_err(|_| Status::ResourceLimit)?;
        if count > max {
            return Err(Status::ResourceLimit);
        }
        if count == 0 {
            return Ok(Self { range: 0..0, count });
        }
        if ptr.is_null() || !ptr.addr().is_multiple_of(align_of::<T>()) {
            return Err(Status::InvalidArgument);
        }
        let size = count
            .checked_mul(size_of::<T>())
            .ok_or(Status::ResourceLimit)?;
        if size > isize::MAX as usize {
            return Err(Status::ResourceLimit);
        }
        let start = ptr.addr();
        let end = start.checked_add(size).ok_or(Status::InvalidArgument)?;
        Ok(Self {
            range: start..end,
            count,
        })
    }

    pub(crate) fn one<T>(ptr: *const T) -> Result<Self, Status> {
        Self::new(ptr, 1, 1)
    }

    pub(crate) fn disjoint(&self, others: &[&Self]) -> Result<(), Status> {
        let start = self.range.start;
        let end = self.range.end;
        if start != end
            && others.iter().any(|other| {
                !other.range.is_empty() && start < other.range.end && other.range.start < end
            })
        {
            return Err(Status::InvalidArgument);
        }
        Ok(())
    }
}

/// Read only the common prefix until the caller declares the complete v1
/// struct. The caller has already checked the typed pointer's shape and range.
pub(crate) unsafe fn validate_version<T>(ptr: *const T) -> Result<(), Status> {
    // SAFETY: ABI metadata types have this prefix and were aligned before
    // this read. The C caller guarantees readable storage for the prefix.
    unsafe { validate_layout(ptr, ABI_VERSION) }
}

pub(crate) unsafe fn initialization_version<T>(ptr: *const T) -> Result<u32, Status> {
    let header = ptr.cast::<Header>();
    Span::one(header)?;
    Ok(unsafe { header.read() }.abi_version)
}

pub(crate) unsafe fn validate_layout<T>(ptr: *const T, version: u32) -> Result<(), Status> {
    let header = unsafe { ptr.cast::<Header>().read() };
    if header.abi_version != version || header.size as usize != size_of::<T>() {
        return Err(Status::Incompatible);
    }
    Ok(())
}

pub(crate) unsafe fn borrow_input<T>(ptr: *const T, span: &Span) -> &[T] {
    if span.count == 0 {
        return &[];
    }
    // SAFETY: Span validated the nonempty extent and the C caller guarantees
    // that the range is initialized, readable and stable for this call.
    unsafe { std::slice::from_raw_parts(ptr, span.count) }
}
