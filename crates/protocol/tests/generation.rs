use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use vmkek_protocol::{
    public_key_id, GenerationChoice, GenerationOffer, GrantBinding, ProtocolError,
    SignedGenerationChoice, VmForm, ABI_VERSION, GENERATION_CHOICE_BYTES, GENERATION_OFFER_BYTES,
    GENERATION_REGISTER, GENERATION_STACK, SCHEMA_VERSION,
};

#[test]
fn negotiation_wire_and_signature_domains_are_fixed() {
    let offer = GenerationOffer {
        app_id: [1; 16],
        build_id: [2; 16],
        device_id: [3; 16],
        function_id: [4; 16],
        request_id: [5; 16],
        descriptor_schema: SCHEMA_VERSION,
        descriptor_abi: ABI_VERSION,
        forms: GENERATION_STACK | GENERATION_REGISTER,
        capabilities: 0,
    };
    let encoded = offer.encode().unwrap();
    assert_eq!(encoded.len(), GENERATION_OFFER_BYTES);
    assert_eq!(&encoded[..8], &[1, 0, 13, 0, 123, 0, 0, 0]);
    assert_eq!(GenerationOffer::decode(&encoded), Ok(offer));
    let mut invalid = encoded.clone();
    invalid[0] = 2;
    assert_eq!(
        GenerationOffer::decode(&invalid),
        Err(ProtocolError::Version)
    );
    let mut invalid = encoded;
    invalid[124] = 0x80;
    assert_eq!(
        GenerationOffer::decode(&invalid),
        Err(ProtocolError::Invalid)
    );

    let device = SigningKey::from_slice(&[6; 32]).unwrap();
    let publisher = SigningKey::from_slice(&[7; 32]).unwrap();
    let choice = GenerationChoice {
        offer_digest: offer.digest().unwrap(),
        binding: GrantBinding {
            app_id: offer.app_id,
            build_id: offer.build_id,
            device_id: offer.device_id,
            license_id: [8; 16],
            session_id: [9; 16],
            generation_id: [10; 16],
        },
        function_id: offer.function_id,
        descriptor_sha256: [11; 32],
        manifest_sha256: [12; 32],
        module_id: [13; 16],
        module_version: 1,
        form: VmForm::Register,
        policy_epoch: 1,
        challenge_id: [14; 16],
        nonce: [15; 32],
        signing_key_id: public_key_id(publisher.verifying_key()),
    };
    let signed = SignedGenerationChoice::sign(choice, &publisher).unwrap();
    assert_eq!(signed.as_bytes().len(), GENERATION_CHOICE_BYTES);
    assert_eq!(&signed.as_bytes()[..8], &[1, 0, 14, 0, 133, 1, 0, 0]);
    let signed = SignedGenerationChoice::decode(signed.as_bytes()).unwrap();
    assert_eq!(signed.verify_for(publisher.verifying_key()), Ok(&choice));
    assert_eq!(
        signed.verify_for(device.verifying_key()),
        Err(ProtocolError::Signature)
    );
    let original: Signature = device
        .sign_prehash(&offer.signature_digest().unwrap())
        .unwrap();
    assert_eq!(
        offer.verify(device.verifying_key(), &original.to_bytes().into()),
        Ok(())
    );
    assert_eq!(
        signed.verify_completion(device.verifying_key(), &original.to_bytes().into()),
        Err(ProtocolError::Signature)
    );
    let completion: Signature = device.sign_prehash(&signed.completion_digest()).unwrap();
    assert_eq!(
        signed.verify_completion(device.verifying_key(), &completion.to_bytes().into()),
        Ok(())
    );
}
