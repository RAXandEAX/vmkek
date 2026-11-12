use super::{env, File, Handle, Instant, OsStrExt, Write};

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(path: *const u16, file: Handle, flags: u32) -> Handle;
    fn GetProcAddress(module: Handle, name: *const u8) -> *mut std::ffi::c_void;
    fn FreeLibrary(module: Handle) -> i32;
    fn QueryThreadCycleTime(thread: Handle, cycles: *mut u64) -> i32;
    fn GetCurrentThread() -> Handle;
    fn GetModuleHandleW(name: *const u16) -> Handle;
}

pub(super) struct Activity<'a> {
    name: &'a str,
    library: Handle,
}

pub(super) fn initialize(scenario: &str) -> Option<Activity<'_>> {
    let path = env::var_os("VMKEK_A08_ACTIVITY_DLL")?;
    let path = std::path::Path::new(&path);
    assert!(path.is_absolute());
    let path: Vec<_> = path.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: The runner provides the absolute path of its own build artifact.
    // Restrict dependencies to the artifact directory and System32.
    let library = unsafe { LoadLibraryExW(path.as_ptr(), std::ptr::null_mut(), 0x0000_0900) };
    assert!(!library.is_null());
    let activity = Activity { name: scenario, library };
    if scenario == "compat_acg" {
        activity.native(5);
    }
    Some(activity)
}

impl Activity<'_> {
    pub(super) fn exercise(self, record: &mut File, calls: impl FnOnce(&mut File)) {
        let mut calls = Some(calls);
        match self.name {
            "compat_accessibility" => self.native(1),
            "compat_capture" => self.native(2),
            "compat_overlay" => self.native(3),
            "compat_seh" => self.native(4),
            "compat_profile" => {
                let start = Instant::now();
                let before = cycles();
                calls.take().unwrap()(record);
                let elapsed = start.elapsed().as_nanos();
                let cycles = cycles().checked_sub(before).unwrap();
                assert!(cycles > 0 && elapsed > 0);
                writeln!(record, "profile_cycles={cycles} profile_ns={elapsed}").unwrap();
            }
            "compat_aslr" => check_aslr(record),
            "cpu_load" => {
                let iterations = super::with_cpu_load(|| calls.take().unwrap()(record));
                writeln!(record, "load_workers=4 load_iterations={iterations}").unwrap();
            }
            "compat_acg" | "compat_reentry" | "compat_clean" | "concurrent" | "ide" => {}
            _ => panic!("unknown compatibility workload"),
        }
        if let Some(calls) = calls {
            calls(record);
        }
        writeln!(record, "compatibility_activity={} output_checks=verified", self.name).unwrap();
    }

    fn native(&self, scenario: u32) {
        // SAFETY: The library handle remains owned until Drop. The named export
        // is part of this exact lab DLL and takes one DWORD and returns a DWORD.
        let result = unsafe {
            let address = GetProcAddress(self.library, c"compatibility_activity".as_ptr().cast());
            assert!(!address.is_null());
            let function: unsafe extern "system" fn(u32) -> u32 = std::mem::transmute(address);
            function(scenario)
        };
        assert_eq!(result, 1);
    }
}

impl Drop for Activity<'_> {
    fn drop(&mut self) {
        // SAFETY: LoadLibraryExW supplied this reference and Activity owns it.
        unsafe { FreeLibrary(self.library) };
    }
}

fn cycles() -> u64 {
    let mut value = 0;
    // SAFETY: The thread pseudo-handle is valid and value is a live u64.
    assert_ne!(unsafe { QueryThreadCycleTime(GetCurrentThread(), &mut value) }, 0);
    value
}

fn check_aslr(record: &mut File) {
    use std::io::{Read, Seek, SeekFrom};

    let mut image = File::open(env::current_exe().unwrap()).unwrap();
    let mut dos = [0; 64];
    image.read_exact(&mut dos).unwrap();
    assert_eq!(&dos[..2], b"MZ");
    let nt_offset = u32::from_le_bytes(dos[60..64].try_into().unwrap());
    assert!((64..=1024).contains(&nt_offset));
    image.seek(SeekFrom::Start(nt_offset.into())).unwrap();
    let mut header = [0; 96];
    image.read_exact(&mut header).unwrap();
    assert_eq!(&header[..4], b"PE\0\0");
    assert_eq!(u16::from_le_bytes(header[24..26].try_into().unwrap()), 0x20b);
    let flags = u16::from_le_bytes(header[94..96].try_into().unwrap());
    assert_ne!(flags & 0x40, 0);
    let preferred = u64::from_le_bytes(header[48..56].try_into().unwrap());
    // SAFETY: NULL selects the currently executing EXE.
    let mapped = unsafe { GetModuleHandleW(std::ptr::null()) } as u64;
    assert_ne!(mapped, 0);
    assert_ne!(mapped, preferred);
    writeln!(record, "aslr_dynamic_base=true aslr_displaced=true").unwrap();
}
