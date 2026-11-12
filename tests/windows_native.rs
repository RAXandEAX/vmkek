use vmkek::{emu, pe, protect, sample};

#[test]
fn native_pe_keeps_windows_imports_and_runs_in_the_model() {
    let source = sample::build().unwrap();
    let plain = pe::parse(&source.bytes).unwrap();
    let protected = protect::protect_windows_native(&source.bytes, &options()).unwrap();
    let image = pe::parse(&protected.bytes).unwrap();
    assert!(protected.report.windows_native);
    assert_eq!(plain.imports, image.imports);
    assert_eq!(
        (plain.import_rva, plain.import_size),
        (image.import_rva, image.import_size)
    );
    assert_eq!(
        (plain.iat_rva, plain.iat_size),
        (image.iat_rva, image.iat_size)
    );
    for absent in ["import-hash", "direct-syscall", "sealed-maps"] {
        assert!(!protected.report.passes.iter().any(|pass| pass == absent));
    }

    let mut model = emu::load(&image, emu::Policy::default()).unwrap();
    assert_native_tls(&image, &model);
    let teb = model.gs;
    model.run().unwrap();
    assert_eq!(model.exit_code, Some(0));
    assert_eq!(model.stdout, sample::line().as_bytes());
    assert_eq!(model.gs, teb, "VM must leave the Windows GS base intact");
    assert_native_entry_tamper(&protected.bytes, &image, plain.entry_rva);
}

fn assert_native_entry_tamper(bytes: &[u8], image: &pe::PeImage, entry: u32) {
    let section = image
        .sections
        .iter()
        .find(|section| {
            entry >= section.rva && ((entry - section.rva) as usize) < section.bytes.len()
        })
        .unwrap();
    let at =
        pe::section_file_offset(bytes, &section.name).unwrap() + (entry - section.rva) as usize;
    let mut altered = bytes.to_vec();
    altered[at] ^= 1;
    let corrupt = pe::parse(&altered).unwrap();
    let mut model = emu::load(&corrupt, emu::Policy::default()).unwrap();
    assert!(!model
        .drive(|m| m.rip == image.image_base + u64::from(entry))
        .unwrap());
    assert_eq!(model.exit_code, Some(0xDEB6));
    assert!(model.stdout.is_empty());
}

fn assert_native_tls(image: &pe::PeImage, model: &emu::Machine) {
    let directory = pe::read_rva(image, image.tls_rva, 40).unwrap();
    let start = u64::from_le_bytes(directory[..8].try_into().unwrap());
    let end = u64::from_le_bytes(directory[8..16].try_into().unwrap());
    let index = u64::from_le_bytes(directory[16..24].try_into().unwrap());
    let start_rva = (start - image.image_base) as u32;
    let template = pe::read_rva(image, start_rva, (end - start) as usize).unwrap();
    assert!(template.len() > 0x1000);
    assert!(template.iter().all(|&byte| byte == 0));
    assert_eq!(&directory[32..36], &[0; 4], "file-backed TLS template");
    assert_eq!(model.read(index, 4).unwrap(), 3u32.to_le_bytes());
}

#[test]
fn windows_native_rejects_existing_tls_instead_of_replacing_it() {
    let source = sample::build().unwrap();
    let mut image = pe::parse(&source.bytes).unwrap();
    image.tls_rva = 0x2600;
    image.tls_size = 40;
    let input = pe::emit(&image).unwrap();
    let Err(error) = protect::protect_windows_native(&input, &options()) else {
        panic!("native protector unexpectedly accepted existing static TLS");
    };
    assert!(error.to_string().contains("without static TLS"), "{error}");
}

#[test]
fn windows_native_profile_rejects_elf_input() {
    let elf = vmkek::elf::sample::build().unwrap();
    let err = protect::protect_windows_native(&elf, &options()).unwrap_err();
    assert!(err.to_string().contains("requires a PE executable"));
}

#[test]
fn native_vm_reenters_the_same_function_through_a_host_call() {
    use iced_x86::code_asm::*;

    let source = sample::build().unwrap();
    let mut image = pe::parse(&source.bytes).unwrap();
    let text = image
        .sections
        .iter_mut()
        .find(|section| section.name == ".text")
        .unwrap();
    text.bytes.resize(0x400, 0xcc);
    // Host callback clears the second argument and tail-calls the protected entry.
    text.bytes[0x220..0x227].copy_from_slice(&[0x33, 0xd2, 0xe9, 0x0d, 0, 0, 0]);
    // MSVC fixture body at RVA 0x1234, including the call to the callback above.
    let body = [
        0x40, 0x53, 0x48, 0x83, 0xec, 0x20, 0x48, 0x8b, 0xd9, 0x48, 0x85, 0xd2, 0x74, 0x0e, 0x48,
        0x83, 0xc1, 0x05, 0xe8, 0xd5, 0xff, 0xff, 0xff, 0x48, 0x03, 0xc3, 0xeb, 0x08, 0x48, 0x6b,
        0xc3, 0x07, 0x48, 0x83, 0xc0, 0x0b, 0x48, 0x83, 0xc4, 0x20, 0x5b, 0xc3,
    ];
    text.bytes[0x234..0x234 + body.len()].copy_from_slice(&body);
    image.entry_rva = 0x1300;
    let mut entry = CodeAssembler::new(64).unwrap();
    entry.sub(rsp, 0x28i32).unwrap();
    entry.xor(ecx, ecx).unwrap();
    entry.mov(edx, 1u32).unwrap();
    entry.call(image.image_base + 0x1234).unwrap();
    entry.add(rsp, 0x28i32).unwrap();
    entry.ret().unwrap();
    let code = entry.assemble(image.image_base + 0x1300).unwrap();
    text.bytes[0x300..0x300 + code.len()].copy_from_slice(&code);
    let input = pe::emit(&image).unwrap();
    assert_eq!(
        emu::run_pe(&input, emu::Policy::default())
            .unwrap()
            .exit_code,
        46
    );

    let mut options = options();
    options.virtualize_all = false;
    options
        .virtualize
        .insert(format!("rva:1234+{:x}", body.len()));
    options.seed = 7;
    let protected = protect::protect_windows_native(&input, &options).unwrap();
    let result = emu::run_pe(&protected.bytes, emu::Policy::default()).unwrap();
    assert_eq!(result.exit_code, 46);
}

fn options() -> protect::Options {
    protect::Options {
        virtualize: Default::default(),
        mutate: Default::default(),
        virtualize_all: true,
        mutate_all: false,
        seed: 17,
        random_key: false,
        debug_seed: false,
    }
}
