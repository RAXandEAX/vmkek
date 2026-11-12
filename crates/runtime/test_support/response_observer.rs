pub fn wait_for(ready_key: &str, release_key: &str) {
    use std::os::windows::ffi::OsStrExt;
    type Event = *mut std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenEventW(access: u32, inherit: i32, name: *const u16) -> Event;
        fn SetEvent(event: Event) -> i32;
        fn WaitForSingleObject(event: Event, ms: u32) -> u32;
        fn CloseHandle(event: Event) -> i32;
    }
    let open = |key, access| {
        let name: Vec<_> = std::env::var_os(key)
            .unwrap()
            .encode_wide()
            .chain([0])
            .collect();
        // SAFETY: the event name is NUL-terminated and valid for this call.
        let handle = unsafe { OpenEventW(access, 0, name.as_ptr()) };
        assert!(!handle.is_null());
        handle
    };
    let ready = open(ready_key, 2);
    let release = open(release_key, 0x0010_0000);
    // SAFETY: both handles are owned until explicitly closed below.
    unsafe {
        assert_ne!(SetEvent(ready), 0);
        assert_eq!(WaitForSingleObject(release, 5000), 0);
        assert_ne!(CloseHandle(ready), 0);
        assert_ne!(CloseHandle(release), 0);
    }
}
