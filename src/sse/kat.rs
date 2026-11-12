//! FIPS-197 and FIPS 180-4 known answers for AES-NI and SHA-NI.
//!
//! The expected digests and ciphertext are the published vectors. The schedule
//! uses the instructions; dword shuffles around them are the documented layout.

use iced_x86::{Code, Encoder, Instruction, OpKind, Register};

use crate::flags::Flags;
use crate::ir::{Sse, X87};

const SHA256_K: [[u32; 4]; 16] = [
    [0x428a_2f98, 0x7137_4491, 0xb5c0_fbcf, 0xe9b5_dba5],
    [0x3956_c25b, 0x59f1_11f1, 0x923f_82a4, 0xab1c_5ed5],
    [0xd807_aa98, 0x1283_5b01, 0x2431_85be, 0x550c_7dc3],
    [0x72be_5d74, 0x80de_b1fe, 0x9bdc_06a7, 0xc19b_f174],
    [0xe49b_69c1, 0xefbe_4786, 0x0fc1_9dc6, 0x240c_a1cc],
    [0x2de9_2c6f, 0x4a74_84aa, 0x5cb0_a9dc, 0x76f9_88da],
    [0x983e_5152, 0xa831_c66d, 0xb003_27c8, 0xbf59_7fc7],
    [0xc6e0_0bf3, 0xd5a7_9147, 0x06ca_6351, 0x1429_2967],
    [0x27b7_0a85, 0x2e1b_2138, 0x4d2c_6dfc, 0x5338_0d13],
    [0x650a_7354, 0x766a_0abb, 0x81c2_c92e, 0x9272_2c85],
    [0xa2bf_e8a1, 0xa81a_664b, 0xc24b_8b70, 0xc76c_51a3],
    [0xd192_e819, 0xd699_0624, 0xf40e_3585, 0x106a_a070],
    [0x19a4_c116, 0x1e37_6c08, 0x2748_774c, 0x34b0_bcb5],
    [0x391c_0cb3, 0x4ed8_aa4a, 0x5b9c_ca4f, 0x682e_6ff3],
    [0x748f_82ee, 0x78a5_636f, 0x84c8_7814, 0x8cc7_0208],
    [0x90be_fffa, 0xa450_6ceb, 0xbef9_a3f7, 0xc671_78f2],
];

const SHA256_MASK: [u8; 16] = [
    0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c,
];

const SHA1_MASK: [u8; 16] = [
    0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
];

struct Round {
    e0: bool,
    msg: u8,
    msg2: u8,
    msg1: u8,
    xor: u8,
    func: u8,
}

const SHA1_FROM_16: &[Round] = &[
    Round {
        e0: true,
        msg: 0,
        msg2: 1,
        msg1: 3,
        xor: 2,
        func: 0,
    },
    Round {
        e0: false,
        msg: 1,
        msg2: 2,
        msg1: 0,
        xor: 3,
        func: 1,
    },
    Round {
        e0: true,
        msg: 2,
        msg2: 3,
        msg1: 1,
        xor: 0,
        func: 1,
    },
    Round {
        e0: false,
        msg: 3,
        msg2: 0,
        msg1: 2,
        xor: 1,
        func: 1,
    },
    Round {
        e0: true,
        msg: 0,
        msg2: 1,
        msg1: 3,
        xor: 2,
        func: 1,
    },
    Round {
        e0: false,
        msg: 1,
        msg2: 2,
        msg1: 0,
        xor: 3,
        func: 1,
    },
    Round {
        e0: true,
        msg: 2,
        msg2: 3,
        msg1: 1,
        xor: 0,
        func: 2,
    },
    Round {
        e0: false,
        msg: 3,
        msg2: 0,
        msg1: 2,
        xor: 1,
        func: 2,
    },
    Round {
        e0: true,
        msg: 0,
        msg2: 1,
        msg1: 3,
        xor: 2,
        func: 2,
    },
    Round {
        e0: false,
        msg: 1,
        msg2: 2,
        msg1: 0,
        xor: 3,
        func: 2,
    },
    Round {
        e0: true,
        msg: 2,
        msg2: 3,
        msg1: 1,
        xor: 0,
        func: 2,
    },
    Round {
        e0: false,
        msg: 3,
        msg2: 0,
        msg1: 2,
        xor: 1,
        func: 3,
    },
    Round {
        e0: true,
        msg: 0,
        msg2: 1,
        msg1: 3,
        xor: 2,
        func: 3,
    },
    Round {
        e0: false,
        msg: 1,
        msg2: 2,
        msg1: 0xff,
        xor: 3,
        func: 3,
    },
    Round {
        e0: true,
        msg: 2,
        msg2: 3,
        msg1: 0xff,
        xor: 0xff,
        func: 3,
    },
];

struct Sha1 {
    abcd: [u8; 16],
    e0: [u8; 16],
    e1: [u8; 16],
    m: [[u8; 16]; 4],
}

#[test]
fn fips197_aes128_matches_the_published_vectors() {
    let plain = hex16("3243f6a8885a308d313198a2e0370734");
    let key = hex16("2b7e151628aed2a6abf7158809cf4f3c");
    let keys = expand128(key);
    assert_eq!(encode_hex(&keys[1]), "a0fafe1788542cb123a339392a6c7605");
    assert_eq!(encode_hex(&keys[10]), "d014f9a8c9ee2589e13f0cc8b6630ca6");
    let cipher = aes128_encrypt(plain, &keys);
    assert_eq!(encode_hex(&cipher), "3925841d02dc09fbdc118597196a0b32");
    assert_eq!(aes128_decrypt(cipher, &keys), plain);
}

#[test]
fn fips180_4_sha256_and_sha1_match_the_published_digests() {
    let empty = empty_block();
    let abc = abc_block();
    assert_eq!(
        words_hex(&sha256_block(&sha256_iv(), &empty)),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        words_hex(&sha256_block(&sha256_iv(), &abc)),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        words_hex(&sha1_block(&sha1_iv(), &empty)),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
    assert_eq!(
        words_hex(&sha1_block(&sha1_iv(), &abc)),
        "a9993e364706816aba3e25717850c26c9cd0d89d"
    );
}

#[test]
fn vex_fma_runs_and_plans_a_host_ymm_save() {
    let bytes = fma132ss();
    let mut decoder =
        iced_x86::Decoder::with_ip(64, &bytes, 0x1000, iced_x86::DecoderOptions::NONE);
    let insn = decoder.decode();
    let replay = super::prepare(&insn, &bytes, None).expect("fma replay");
    assert!(replay.save_ymm, "vfmadd132ss must save host YMM uppers");
    let mut sse = Sse::default();
    sse.xmm[0][0..4].copy_from_slice(&1.0f32.to_le_bytes());
    sse.xmm[1][0..4].copy_from_slice(&3.0f32.to_le_bytes());
    sse.xmm[2][0..4].copy_from_slice(&2.0f32.to_le_bytes());
    run_sse(&mut sse, &bytes);
    assert_eq!(&sse.xmm[0][0..4], &5.0f32.to_le_bytes());
}

#[test]
fn late_sse_stays_out_of_the_integer_ir() {
    let bytes = encode(Code::Pshufb_xmm_xmmm128, 0, 1, None);
    let err = crate::lift::lift("pshufb", &bytes, 0x42, bytes.len() as u32, 0).unwrap_err();
    match err {
        crate::error::Error::Unsupported { rva, text } => {
            assert_eq!(rva, 0x42);
            assert!(text.contains("sse"), "{text}");
        }
        other => panic!("expected Unsupported, got {other}"),
    }
    let program =
        crate::lift::program("pshufb", &bytes, 0x1000, bytes.len() as u32, 0).expect("lift");
    assert!(program.blocks.iter().any(|block| {
        block
            .ops
            .iter()
            .any(|step| matches!(step, crate::ir::Step::Sse(_)))
    }));
}

fn fma132ss() -> Vec<u8> {
    let mut insn = Instruction::default();
    insn.set_code(Code::VEX_Vfmadd132ss_xmm_xmm_xmmm32);
    insn.set_op0_kind(OpKind::Register);
    insn.set_op0_register(Register::XMM0);
    insn.set_op1_kind(OpKind::Register);
    insn.set_op1_register(Register::XMM1);
    insn.set_op2_kind(OpKind::Register);
    insn.set_op2_register(Register::XMM2);
    finish(&insn)
}

fn aes128_encrypt(plain: [u8; 16], keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = xor16(plain, keys[0]);
    for key in &keys[1..10] {
        state = aesenc(state, *key);
    }
    aesenclast(state, keys[10])
}

fn aes128_decrypt(cipher: [u8; 16], keys: &[[u8; 16]; 11]) -> [u8; 16] {
    let mut state = xor16(cipher, keys[10]);
    for key in keys[1..10].iter().rev() {
        state = aesdec(state, aesimc(*key));
    }
    aesdeclast(state, keys[0])
}

fn expand128(key: [u8; 16]) -> [[u8; 16]; 11] {
    let mut out = [[0u8; 16]; 11];
    out[0] = key;
    let rcon = [0x01u8, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
    let mut current = key;
    for (index, rcon) in rcon.iter().enumerate() {
        current = expand_step(current, *rcon);
        out[index + 1] = current;
    }
    out
}

fn expand_step(key: [u8; 16], rcon: u8) -> [u8; 16] {
    let tmp = pshufd(aes_assist(key, rcon), 0xff);
    let mut key = xor16(key, slli16(key, 4));
    key = xor16(key, slli16(key, 4));
    key = xor16(key, slli16(key, 4));
    xor16(key, tmp)
}

fn sha256_block(iv: &[u32; 8], data: &[u8; 64]) -> [u32; 8] {
    let (mut state0, mut state1) = pack_sha256(iv);
    let save0 = state0;
    let save1 = state1;
    let mut msg = load_masked4(data, SHA256_MASK);
    sha256_head(&mut state0, &mut state1, &mut msg);
    sha256_tail(&mut state0, &mut state1, &mut msg);
    unpack_sha256(add32(state0, save0), add32(state1, save1))
}

fn sha256_head(state0: &mut [u8; 16], state1: &mut [u8; 16], msg: &mut [[u8; 16]; 4]) {
    sha256_quad(state0, state1, add32(msg[0], k256(0)));
    sha256_quad(state0, state1, add32(msg[1], k256(1)));
    msg[0] = sha256_msg1(msg[0], msg[1]);
    sha256_quad(state0, state1, add32(msg[2], k256(2)));
    msg[1] = sha256_msg1(msg[1], msg[2]);
    let mut wk = add32(msg[3], k256(3));
    *state1 = sha256_rnds2(*state1, *state0, wk);
    msg[0] = add32(msg[0], alignr(msg[3], msg[2], 4));
    msg[0] = sha256_msg2(msg[0], msg[3]);
    wk = pshufd(wk, 0x0e);
    *state0 = sha256_rnds2(*state0, *state1, wk);
    msg[2] = sha256_msg1(msg[2], msg[3]);
}

fn sha256_tail(state0: &mut [u8; 16], state1: &mut [u8; 16], msg: &mut [[u8; 16]; 4]) {
    let mut index = 0usize;
    for round in 4..13 {
        index = sha256_step(state0, state1, msg, index, round, true);
    }
    for round in 13..15 {
        index = sha256_step(state0, state1, msg, index, round, false);
    }
    let mut wk = add32(msg[index], k256(15));
    *state1 = sha256_rnds2(*state1, *state0, wk);
    wk = pshufd(wk, 0x0e);
    *state0 = sha256_rnds2(*state0, *state1, wk);
}

fn sha256_step(
    state0: &mut [u8; 16],
    state1: &mut [u8; 16],
    msg: &mut [[u8; 16]; 4],
    index: usize,
    round: usize,
    schedule: bool,
) -> usize {
    let mut wk = add32(msg[index], k256(round));
    *state1 = sha256_rnds2(*state1, *state0, wk);
    let prev = msg[(index + 3) % 4];
    let next = (index + 1) % 4;
    msg[next] = add32(msg[next], alignr(msg[index], prev, 4));
    msg[next] = sha256_msg2(msg[next], msg[index]);
    wk = pshufd(wk, 0x0e);
    *state0 = sha256_rnds2(*state0, *state1, wk);
    if schedule {
        let old = (index + 3) % 4;
        msg[old] = sha256_msg1(msg[old], msg[index]);
    }
    next
}

fn sha256_quad(state0: &mut [u8; 16], state1: &mut [u8; 16], wk: [u8; 16]) {
    *state1 = sha256_rnds2(*state1, *state0, wk);
    *state0 = sha256_rnds2(*state0, *state1, pshufd(wk, 0x0e));
}

fn sha1_block(iv: &[u32; 5], data: &[u8; 64]) -> [u32; 5] {
    let mut st = Sha1::load(iv, data);
    let save_a = st.abcd;
    let save_e = st.e0;
    sha1_head(&mut st);
    for round in SHA1_FROM_16 {
        sha1_round(&mut st, round);
    }
    st.e1 = sha1_nexte(st.e1, st.m[3]);
    st.e0 = st.abcd;
    st.abcd = sha1_rnds4(st.abcd, st.e1, 3);
    st.e0 = sha1_nexte(st.e0, save_e);
    st.abcd = add32(st.abcd, save_a);
    st.export()
}

fn sha1_head(st: &mut Sha1) {
    st.e0 = add32(st.e0, st.m[0]);
    st.e1 = st.abcd;
    st.abcd = sha1_rnds4(st.abcd, st.e0, 0);
    st.e1 = sha1_nexte(st.e1, st.m[1]);
    st.e0 = st.abcd;
    st.abcd = sha1_rnds4(st.abcd, st.e1, 0);
    st.m[0] = sha1_msg1(st.m[0], st.m[1]);
    st.e0 = sha1_nexte(st.e0, st.m[2]);
    st.e1 = st.abcd;
    st.abcd = sha1_rnds4(st.abcd, st.e0, 0);
    st.m[1] = sha1_msg1(st.m[1], st.m[2]);
    st.m[0] = xor16(st.m[0], st.m[2]);
    st.e1 = sha1_nexte(st.e1, st.m[3]);
    st.e0 = st.abcd;
    st.m[0] = sha1_msg2(st.m[0], st.m[3]);
    st.abcd = sha1_rnds4(st.abcd, st.e1, 0);
    st.m[2] = sha1_msg1(st.m[2], st.m[3]);
    st.m[1] = xor16(st.m[1], st.m[3]);
}

fn sha1_round(st: &mut Sha1, round: &Round) {
    let message = st.m[round.msg as usize];
    if round.e0 {
        st.e0 = sha1_nexte(st.e0, message);
        st.e1 = st.abcd;
        st.m[round.msg2 as usize] = sha1_msg2(st.m[round.msg2 as usize], message);
        st.abcd = sha1_rnds4(st.abcd, st.e0, round.func);
    } else {
        st.e1 = sha1_nexte(st.e1, message);
        st.e0 = st.abcd;
        st.m[round.msg2 as usize] = sha1_msg2(st.m[round.msg2 as usize], message);
        st.abcd = sha1_rnds4(st.abcd, st.e1, round.func);
    }
    if round.msg1 != 0xff {
        let index = round.msg1 as usize;
        st.m[index] = sha1_msg1(st.m[index], message);
    }
    if round.xor != 0xff {
        let index = round.xor as usize;
        st.m[index] = xor16(st.m[index], message);
    }
}

impl Sha1 {
    fn load(iv: &[u32; 5], data: &[u8; 64]) -> Self {
        Self {
            abcd: pshufd(words_of(&iv[..4]), 0x1b),
            e0: set4(iv[4], 0, 0, 0),
            e1: [0; 16],
            m: load_masked4(data, SHA1_MASK),
        }
    }

    fn export(&self) -> [u32; 5] {
        let mut out = [0u32; 5];
        write_words(&mut out[..4], pshufd(self.abcd, 0x1b));
        out[4] = dwords(self.e0)[3];
        out
    }
}

fn pack_sha256(state: &[u32; 8]) -> ([u8; 16], [u8; 16]) {
    let tmp = pshufd(words_of(&state[..4]), 0xb1);
    let high = pshufd(words_of(&state[4..]), 0x1b);
    (alignr(tmp, high, 8), blend16(high, tmp, 0xf0))
}

fn unpack_sha256(state0: [u8; 16], state1: [u8; 16]) -> [u32; 8] {
    let tmp = pshufd(state0, 0x1b);
    let state1 = pshufd(state1, 0xb1);
    let mut out = [0u32; 8];
    write_words(&mut out[..4], blend16(tmp, state1, 0xf0));
    write_words(&mut out[4..], alignr(state1, tmp, 8));
    out
}

fn sha256_iv() -> [u32; 8] {
    [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ]
}

fn sha1_iv() -> [u32; 5] {
    [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ]
}

fn empty_block() -> [u8; 64] {
    let mut block = [0u8; 64];
    block[0] = 0x80;
    block
}

fn abc_block() -> [u8; 64] {
    let mut block = [0u8; 64];
    block[0] = b'a';
    block[1] = b'b';
    block[2] = b'c';
    block[3] = 0x80;
    block[63] = 24;
    block
}

fn k256(index: usize) -> [u8; 16] {
    let lane = SHA256_K[index];
    set4(lane[3], lane[2], lane[1], lane[0])
}

fn load_masked4(data: &[u8; 64], mask: [u8; 16]) -> [[u8; 16]; 4] {
    let mut out = [[0u8; 16]; 4];
    for (index, lane) in out.iter_mut().enumerate() {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&data[index * 16..index * 16 + 16]);
        *lane = pshufb(raw, mask);
    }
    out
}

fn aesenc(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    exec2(Code::Aesenc_xmm_xmmm128, state, key, None)
}

fn aesenclast(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    exec2(Code::Aesenclast_xmm_xmmm128, state, key, None)
}

fn aesdec(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    exec2(Code::Aesdec_xmm_xmmm128, state, key, None)
}

fn aesdeclast(state: [u8; 16], key: [u8; 16]) -> [u8; 16] {
    exec2(Code::Aesdeclast_xmm_xmmm128, state, key, None)
}

fn aesimc(value: [u8; 16]) -> [u8; 16] {
    exec2(Code::Aesimc_xmm_xmmm128, value, value, None)
}

fn aes_assist(src: [u8; 16], rcon: u8) -> [u8; 16] {
    let mut file = [[0u8; 16]; 4];
    file[1] = src;
    run(
        &mut file,
        &encode(Code::Aeskeygenassist_xmm_xmmm128_imm8, 0, 1, Some(rcon)),
    );
    file[0]
}

fn sha256_rnds2(cdgh: [u8; 16], abef: [u8; 16], wk: [u8; 16]) -> [u8; 16] {
    let mut file = [[0u8; 16]; 4];
    file[0] = wk;
    file[1] = cdgh;
    file[2] = abef;
    run(
        &mut file,
        &encode(Code::Sha256rnds2_xmm_xmmm128, 1, 2, None),
    );
    file[1]
}

fn sha256_msg1(dst: [u8; 16], src: [u8; 16]) -> [u8; 16] {
    exec2(Code::Sha256msg1_xmm_xmmm128, dst, src, None)
}

fn sha256_msg2(dst: [u8; 16], src: [u8; 16]) -> [u8; 16] {
    exec2(Code::Sha256msg2_xmm_xmmm128, dst, src, None)
}

fn sha1_rnds4(abcd: [u8; 16], schedule: [u8; 16], func: u8) -> [u8; 16] {
    exec2(Code::Sha1rnds4_xmm_xmmm128_imm8, abcd, schedule, Some(func))
}

fn sha1_nexte(acc: [u8; 16], msg: [u8; 16]) -> [u8; 16] {
    exec2(Code::Sha1nexte_xmm_xmmm128, acc, msg, None)
}

fn sha1_msg1(dst: [u8; 16], src: [u8; 16]) -> [u8; 16] {
    exec2(Code::Sha1msg1_xmm_xmmm128, dst, src, None)
}

fn sha1_msg2(dst: [u8; 16], src: [u8; 16]) -> [u8; 16] {
    exec2(Code::Sha1msg2_xmm_xmmm128, dst, src, None)
}

fn exec2(code: Code, dst: [u8; 16], src: [u8; 16], imm: Option<u8>) -> [u8; 16] {
    let mut file = [[0u8; 16]; 4];
    file[0] = dst;
    file[1] = src;
    run(&mut file, &encode(code, 0, 1, imm));
    file[0]
}

fn run(file: &mut [[u8; 16]; 4], bytes: &[u8]) {
    let mut sse = Sse::default();
    sse.xmm[..4].copy_from_slice(file);
    run_sse(&mut sse, bytes);
    file.copy_from_slice(&sse.xmm[..4]);
}

fn run_sse(sse: &mut Sse, bytes: &[u8]) {
    let mut x87 = X87::default();
    let mut regs = [0u64; 16];
    let mut flags = Flags::default();
    let mut af = false;
    let mut mem = crate::ir::MapMem::default();
    super::execute(
        sse, &mut x87, &mut regs, &mut flags, &mut af, false, &mut mem, bytes, 0x1000, 0,
    )
    .unwrap_or_else(|err| panic!("kat {err}"));
}

fn encode(code: Code, dst: u32, src: u32, imm: Option<u8>) -> Vec<u8> {
    let mut insn = Instruction::default();
    insn.set_code(code);
    insn.set_op0_kind(OpKind::Register);
    insn.set_op0_register(xmm_reg(dst));
    insn.set_op1_kind(OpKind::Register);
    insn.set_op1_register(xmm_reg(src));
    if let Some(imm) = imm {
        insn.set_op2_kind(OpKind::Immediate8);
        insn.set_immediate8(imm);
    }
    finish(&insn)
}

fn finish(insn: &Instruction) -> Vec<u8> {
    let mut encoder = Encoder::new(64);
    encoder
        .encode(insn, 0x1000)
        .unwrap_or_else(|err| panic!("{err}"));
    encoder.take_buffer()
}

fn xmm_reg(index: u32) -> Register {
    match index {
        0 => Register::XMM0,
        1 => Register::XMM1,
        2 => Register::XMM2,
        _ => Register::XMM3,
    }
}

fn add32(left: [u8; 16], right: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for index in 0..4 {
        let sum = lane(left, index).wrapping_add(lane(right, index));
        out[index * 4..index * 4 + 4].copy_from_slice(&sum.to_le_bytes());
    }
    out
}

fn xor16(left: [u8; 16], right: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for index in 0..16 {
        out[index] = left[index] ^ right[index];
    }
    out
}

fn pshufd(value: [u8; 16], imm: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    for dest in 0..4 {
        let src = usize::from((imm >> (dest * 2)) & 3);
        out[dest * 4..dest * 4 + 4].copy_from_slice(&value[src * 4..src * 4 + 4]);
    }
    out
}

fn pshufb(value: [u8; 16], mask: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, sel) in mask.iter().enumerate() {
        if sel & 0x80 == 0 {
            out[index] = value[usize::from(sel & 15)];
        }
    }
    out
}

fn alignr(first: [u8; 16], second: [u8; 16], shift: usize) -> [u8; 16] {
    let mut cat = [0u8; 32];
    cat[..16].copy_from_slice(&second);
    cat[16..].copy_from_slice(&first);
    let mut out = [0u8; 16];
    out.copy_from_slice(&cat[shift..shift + 16]);
    out
}

fn blend16(left: [u8; 16], right: [u8; 16], mask: u8) -> [u8; 16] {
    let mut out = [0u8; 16];
    for index in 0..8 {
        let src = if mask & (1 << index) == 0 {
            left
        } else {
            right
        };
        let off = index * 2;
        out[off] = src[off];
        out[off + 1] = src[off + 1];
    }
    out
}

fn slli16(value: [u8; 16], shift: usize) -> [u8; 16] {
    let mut out = [0u8; 16];
    if shift < 16 {
        out[shift..].copy_from_slice(&value[..16 - shift]);
    }
    out
}

fn set4(d3: u32, d2: u32, d1: u32, d0: u32) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, word) in [d0, d1, d2, d3].iter().enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn lane(value: [u8; 16], index: usize) -> u32 {
    let start = index * 4;
    u32::from_le_bytes(value[start..start + 4].try_into().expect("lane"))
}

fn dwords(value: [u8; 16]) -> [u32; 4] {
    [
        lane(value, 0),
        lane(value, 1),
        lane(value, 2),
        lane(value, 3),
    ]
}

fn words_of(words: &[u32]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, word) in words.iter().take(4).enumerate() {
        out[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

fn write_words(out: &mut [u32], value: [u8; 16]) {
    let lanes = dwords(value);
    out[..4].copy_from_slice(&lanes);
}

fn hex16(text: &str) -> [u8; 16] {
    let bytes = hex::decode(text).expect("hex");
    bytes.try_into().expect("16 bytes")
}

fn encode_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

fn words_hex(words: &[u32]) -> String {
    words.iter().map(|word| format!("{word:08x}")).collect()
}
