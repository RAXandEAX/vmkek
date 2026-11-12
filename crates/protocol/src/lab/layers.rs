//! Private, fixed Lab arithmetic programs. The C caller supplies no layer code.

use std::mem::size_of;

use chacha20poly1305::{
    aead::{AeadInPlace, KeyInit},
    ChaCha20Poly1305,
};
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use super::execute::charge;
use super::{ExecutionControl, Scalar, VmError};
use crate::{Digest, VmDescriptor};

type Result<T> = std::result::Result<T, VmError>;

const KEY_DOMAIN: &[u8] = b"vmkek.r08.lab.level-key.v1";
const AAD_DOMAIN: &[u8] = b"vmkek.r08.lab.arithmetic-code.v1";
const CODE_BYTES: usize = 7;
const WORD_HEADER: [u8; 4] = [b'W', 3, 1, 3];
const LIMB_HEADER: [u8; 4] = [b'L', 4, 1, 3];
const LEFT: u8 = 0x11;
const RIGHT: u8 = 0x12;
const WORD_SUM: u8 = 0x13;
const LOW_SUM: u8 = 0x41;
const HIGH_SUM: u8 = 0x42;
const JOIN: u8 = 0x43;
const WORD_CODE: [u8; CODE_BYTES] = [b'W', 3, 1, 3, LEFT, RIGHT, WORD_SUM];
const LIMB_CODE: [u8; CODE_BYTES] = [b'L', 4, 1, 3, LOW_SUM, HIGH_SUM, JOIN];

pub(super) struct Layers {
    word: Layer,
    limb: Option<Layer>,
}

struct Layer {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
    aad: Digest,
    ciphertext: [u8; CODE_BYTES],
    tag: [u8; 16],
}

impl Layers {
    pub(super) fn generate(descriptor: &VmDescriptor) -> Result<Self> {
        let mut master = Zeroizing::new([0; 32]);
        getrandom::getrandom(master.as_mut()).map_err(|_| VmError::Unavailable)?;
        Self::from_master(descriptor, &master)
    }

    fn from_master(descriptor: &VmDescriptor, master: &[u8; 32]) -> Result<Self> {
        let hkdf = Hkdf::<Sha256>::new(Some(KEY_DOMAIN), master);
        let word = Layer::seal(&hkdf, scope(descriptor, &WORD_HEADER), WORD_CODE)?;
        let limb = if descriptor.depth == 4 {
            Some(Layer::seal(
                &hkdf,
                scope(descriptor, &LIMB_HEADER),
                LIMB_CODE,
            )?)
        } else {
            None
        };
        Ok(Self { word, limb })
    }

    pub(super) const fn memory_bytes() -> usize {
        size_of::<Self>()
    }

    pub(super) const fn call_memory_bytes() -> usize {
        2 * CODE_BYTES + 2 * size_of::<[u64; 2]>() + size_of::<WordResult>() + size_of::<[u32; 3]>()
    }

    pub(super) fn add(
        &self,
        left: Scalar,
        right: Scalar,
        fuel: &mut u64,
        control: &ExecutionControl<'_>,
    ) -> Result<Scalar> {
        let signed = match (left, right) {
            (Scalar::U64(_), Scalar::U64(_)) => false,
            (Scalar::I64(_), Scalar::I64(_)) => true,
            _ => return Err(VmError::InvalidProgram),
        };
        let input = Zeroizing::new([bits(left), bits(right)]);
        check_open(*fuel, control)?;
        let word = {
            let code = self.word.open()?;
            word_ops(&code, &input, self.limb.is_some(), fuel, control)?
        };
        let result = match word {
            WordResult::Direct(value) => value,
            WordResult::Limb(operands) => {
                check_open(*fuel, control)?;
                let code = self.limb.as_ref().ok_or(VmError::InvalidProgram)?.open()?;
                limb_ops(&code, &operands, fuel, control)?
            }
        };
        Ok(if signed {
            Scalar::I64(i64::from_ne_bytes(result.to_ne_bytes()))
        } else {
            Scalar::U64(*result)
        })
    }
}

impl Layer {
    fn seal(hkdf: &Hkdf<Sha256>, aad: Digest, program: [u8; CODE_BYTES]) -> Result<Self> {
        let mut info = [0u8; 33];
        info[1..].copy_from_slice(&aad);
        let mut key = Zeroizing::new([0; 32]);
        let mut nonce = [0; 12];
        info[0] = b'K';
        hkdf.expand(&info, key.as_mut())
            .map_err(|_| VmError::InvalidProgram)?;
        info[0] = b'N';
        hkdf.expand(&info, &mut nonce)
            .map_err(|_| VmError::InvalidProgram)?;
        let mut code = Zeroizing::new(program);
        let cipher = ChaCha20Poly1305::new((&*key).into());
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), &aad, code.as_mut())
            .map_err(|_| VmError::InvalidProgram)?
            .into();
        Ok(Self {
            key,
            nonce,
            aad,
            ciphertext: *code,
            tag,
        })
    }

    fn open(&self) -> Result<Zeroizing<[u8; CODE_BYTES]>> {
        let mut code = Zeroizing::new(self.ciphertext);
        let cipher = ChaCha20Poly1305::new((&*self.key).into());
        cipher
            .decrypt_in_place_detached(
                (&self.nonce).into(),
                &self.aad,
                code.as_mut(),
                (&self.tag).into(),
            )
            .map_err(|_| VmError::InvalidProgram)?;
        Ok(code)
    }
}

fn check_open(fuel: u64, control: &ExecutionControl<'_>) -> Result<()> {
    control.check()?;
    if fuel == 0 {
        return Err(VmError::FuelExhausted);
    }
    Ok(())
}

fn scope(descriptor: &VmDescriptor, format: &[u8; 4]) -> Digest {
    let mut hash = Sha256::new();
    hash.update(AAD_DOMAIN);
    hash.update(descriptor.abi_version.to_le_bytes());
    for id in [
        descriptor.app_id,
        descriptor.build_id,
        descriptor.function_id,
        descriptor.generation_id,
    ] {
        hash.update(id);
    }
    hash.update(descriptor.program_sha256);
    hash.update([
        descriptor.depth,
        descriptor.form as u8,
        descriptor.profile as u8,
    ]);
    hash.update(format);
    hash.finalize().into()
}

enum WordResult {
    Direct(Zeroizing<u64>),
    Limb(Zeroizing<[u64; 2]>),
}

fn word_ops(
    program: &[u8; CODE_BYTES],
    input: &[u64; 2],
    delegated: bool,
    fuel: &mut u64,
    control: &ExecutionControl<'_>,
) -> Result<WordResult> {
    let code = program
        .strip_prefix(&WORD_HEADER)
        .ok_or(VmError::InvalidProgram)?;
    let mut slots = Zeroizing::new([0u64; 2]);
    let mut loaded = 0;
    for (at, op) in code.iter().copied().enumerate() {
        control.check()?;
        charge(fuel, 1)?;
        match op {
            LEFT if loaded & 1 == 0 => {
                slots[0] = input[0];
                loaded |= 1;
            }
            RIGHT if loaded & 2 == 0 => {
                slots[1] = input[1];
                loaded |= 2;
            }
            WORD_SUM if loaded == 3 && at + 1 == code.len() => {
                return if delegated {
                    Ok(WordResult::Limb(slots))
                } else {
                    Ok(WordResult::Direct(Zeroizing::new(
                        slots[0].wrapping_add(slots[1]),
                    )))
                };
            }
            _ => return Err(VmError::InvalidProgram),
        }
    }
    Err(VmError::InvalidProgram)
}

fn limb_ops(
    program: &[u8; CODE_BYTES],
    input: &[u64; 2],
    fuel: &mut u64,
    control: &ExecutionControl<'_>,
) -> Result<Zeroizing<u64>> {
    let code = program
        .strip_prefix(&LIMB_HEADER)
        .ok_or(VmError::InvalidProgram)?;
    let mut limbs = Zeroizing::new([0u32; 3]);
    for (at, op) in code.iter().copied().enumerate() {
        control.check()?;
        charge(fuel, 1)?;
        match (at, op) {
            (0, LOW_SUM) => {
                let (sum, carry) = (input[0] as u32).overflowing_add(input[1] as u32);
                limbs[0] = sum;
                limbs[2] = u32::from(carry);
            }
            (1, HIGH_SUM) => {
                limbs[1] = ((input[0] >> 32) as u32)
                    .wrapping_add((input[1] >> 32) as u32)
                    .wrapping_add(limbs[2]);
            }
            (2, JOIN) => {
                return Ok(Zeroizing::new(
                    (u64::from(limbs[1]) << 32) | u64::from(limbs[0]),
                ))
            }
            _ => return Err(VmError::InvalidProgram),
        }
    }
    Err(VmError::InvalidProgram)
}

fn bits(value: Scalar) -> u64 {
    match value {
        Scalar::U64(value) => value,
        Scalar::I64(value) => u64::from_ne_bytes(value.to_ne_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicBool;
    use std::time::{Duration, Instant};

    use crate::{Budgets, Profile, VmForm};

    use super::*;

    fn descriptor(depth: u8) -> VmDescriptor {
        VmDescriptor {
            abi_version: crate::ABI_VERSION,
            app_id: [1; 16],
            build_id: [2; 16],
            function_id: [3; 16],
            generation_id: [4; 16],
            form: VmForm::Stack,
            depth,
            capabilities: vec![],
            program_sha256: [5; 32],
            budgets: Budgets::default(),
            profile: Profile::Lab,
            extensions: vec![],
        }
    }

    fn control(cancelled: &AtomicBool) -> ExecutionControl<'_> {
        ExecutionControl {
            deadline: Instant::now() + Duration::from_secs(2),
            cancelled,
        }
    }

    #[test]
    fn authenticated_word_and_limb_programs_match_a_widened_oracle() {
        let flag = AtomicBool::new(false);
        let control = control(&flag);
        let edges = [
            0,
            1,
            u64::MAX,
            u32::MAX as u64,
            1 << 32,
            (1 << 63) - 1,
            1 << 63,
        ];
        for (depth, cost) in [(3, 3), (4, 6)] {
            let layers = Layers::from_master(&descriptor(depth), &[depth; 32]).unwrap();
            for left in edges {
                for right in edges {
                    let expected = (u128::from(left) + u128::from(right)) as u64;
                    let mut fuel = cost;
                    assert_eq!(
                        layers.add(Scalar::U64(left), Scalar::U64(right), &mut fuel, &control),
                        Ok(Scalar::U64(expected))
                    );
                    assert_eq!(fuel, 0);
                    let signed = |value: u64| Scalar::I64(i64::from_ne_bytes(value.to_ne_bytes()));
                    let mut fuel = cost;
                    assert_eq!(
                        layers.add(signed(left), signed(right), &mut fuel, &control),
                        Ok(signed(expected))
                    );
                    assert_eq!(fuel, 0);
                }
            }
        }
    }

    #[test]
    fn ciphertext_scope_and_inner_format_fail_before_a_result() {
        let flag = AtomicBool::new(false);
        let control = control(&flag);
        let descriptor = descriptor(4);
        let mut layers = Layers::from_master(&descriptor, &[5; 32]).unwrap();
        let child = layers.limb.as_ref().unwrap();
        assert!(*layers.word.key != *child.key);
        assert_ne!(layers.word.nonce, child.nonce);
        assert_ne!(layers.word.aad, child.aad);
        layers.word.ciphertext = child.ciphertext;
        layers.word.tag = child.tag;
        let mut fuel = 10;
        assert_eq!(
            layers.add(Scalar::U64(5), Scalar::U64(7), &mut fuel, &control),
            Err(VmError::InvalidProgram)
        );
        assert_eq!(fuel, 10);

        let mut moved = Layers::from_master(&descriptor, &[6; 32]).unwrap();
        let mut other = descriptor.clone();
        other.generation_id[0] ^= 1;
        moved.word.aad = scope(&other, &WORD_HEADER);
        assert!(matches!(moved.word.open(), Err(VmError::InvalidProgram)));

        let mut word = WORD_CODE;
        word[5] = 0xff;
        let hkdf = Hkdf::<Sha256>::new(Some(KEY_DOMAIN), &[7; 32]);
        let authenticated = Layer::seal(&hkdf, scope(&descriptor, &WORD_HEADER), word).unwrap();
        let opened = authenticated.open().unwrap();
        assert!(matches!(
            word_ops(&opened, &[5, 7], false, &mut fuel, &control),
            Err(VmError::InvalidProgram)
        ));
        assert_eq!(fuel, 8);
        drop(opened);

        let mut limb = LIMB_CODE;
        limb.swap(4, 5);
        let authenticated = Layer::seal(&hkdf, scope(&descriptor, &LIMB_HEADER), limb).unwrap();
        let opened = authenticated.open().unwrap();
        assert_eq!(
            limb_ops(&opened, &[5, 7], &mut fuel, &control),
            Err(VmError::InvalidProgram)
        );
    }

    #[test]
    fn os_generated_handles_have_independent_private_keys() {
        let descriptor = descriptor(4);
        let left = Layers::generate(&descriptor).unwrap();
        let right = Layers::generate(&descriptor).unwrap();
        assert!(*left.word.key != *right.word.key);
        assert!(left.word.nonce != right.word.nonce);
    }
}
