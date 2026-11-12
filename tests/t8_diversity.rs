//! Cross-build integrity and watermark verification on protected PE fixtures.

use p256::ecdsa::SigningKey;
use vmkek::{crypto, emu, protect, sample, watermark};

#[test]
fn a_payload_edit_at_another_build_offset_does_not_verify_or_run() {
    let plain = sample::build().unwrap();
    let a = build(&plain.bytes, 31);
    let mut b = build(&plain.bytes, 32);
    let (a_start, a_end) = signed_payload(&a.bytes);
    let (b_start, b_end) = signed_payload(&b.bytes);
    let start = a_start.max(b_start);
    let end = start + 16;
    assert!(end <= a_end.min(b_end));
    assert_ne!(a.bytes[start..end], b.bytes[start..end]);
    let key = hex::decode(&b.report.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    protect::inspect(&b.bytes, &key).unwrap();
    let clean = emu::run_pe(&b.bytes, emu::Policy::default()).unwrap();
    assert_eq!(clean.exit_code, 0);
    assert_eq!(clean.stdout, sample::line().into_bytes());
    b.bytes[start..end].copy_from_slice(&a.bytes[start..end]);
    assert!(protect::inspect(&b.bytes, &key).is_err());
    let rejected = emu::run_pe(&b.bytes, emu::Policy::default()).unwrap();
    assert_eq!(rejected.exit_code, 0xbad1);
    assert!(rejected.stdout.is_empty());
}

#[test]
fn protected_artifact_watermark_verifies_with_external_manufacturer_key() {
    let plain = sample::build().unwrap();
    let own_build = build(&plain.bytes, 31);
    let foreign_build = build(&plain.bytes, 32);
    let manufacturer = SigningKey::from_slice(&crypto::sha256(b"t8 fixture manufacturer")).unwrap();
    let foreign_manufacturer =
        SigningKey::from_slice(&crypto::sha256(b"t8 foreign fixture manufacturer")).unwrap();
    let customer = [5; 32];
    let foreign_customer = [6; 32];

    let mut marked = own_build.bytes.clone();
    watermark::append(&mut marked, customer, &manufacturer).unwrap();
    assert_eq!(&marked[..own_build.bytes.len()], own_build.bytes);
    let trailer = &marked[own_build.bytes.len()..];
    assert_eq!(trailer.len(), 8 + customer.len() + 64);
    let signing_bytes = manufacturer.to_bytes();
    let verifying_point = manufacturer.verifying_key().to_encoded_point(false);
    assert!(marked
        .windows(signing_bytes.len())
        .all(|window| window != signing_bytes.as_slice()));
    assert!(marked
        .windows(verifying_point.as_bytes().len())
        .all(|window| window != verifying_point.as_bytes()));
    assert_eq!(
        watermark::verify(&marked, manufacturer.verifying_key()).unwrap(),
        customer
    );

    let mut foreign_marked = foreign_build.bytes;
    watermark::append(&mut foreign_marked, foreign_customer, &foreign_manufacturer).unwrap();
    assert_eq!(
        watermark::verify(&foreign_marked, foreign_manufacturer.verifying_key()).unwrap(),
        foreign_customer
    );
    assert!(watermark::verify(&foreign_marked, manufacturer.verifying_key()).is_err());

    let payload_key = hex::decode(&own_build.report.public_key)
        .unwrap()
        .try_into()
        .unwrap();
    protect::inspect(&marked, &payload_key).unwrap();
    let ran = emu::run_pe(&marked, emu::Policy::default()).unwrap();
    assert_eq!(ran.exit_code, 0);
    assert_eq!(ran.stdout, sample::line().into_bytes());
}

fn build(input: &[u8], seed: u64) -> protect::Protected {
    protect::protect(
        input,
        &protect::Options {
            virtualize: Default::default(),
            mutate: Default::default(),
            virtualize_all: true,
            mutate_all: false,
            seed,
            random_key: false,
            debug_seed: false,
        },
    )
    .unwrap()
}

fn signed_payload(bytes: &[u8]) -> (usize, usize) {
    let offset = crypto::find_header(bytes).unwrap();
    let header = crypto::Header::parse(&bytes[offset..]).unwrap();
    let start = offset + header.payload_off as usize;
    (start, start + header.payload_len as usize)
}
