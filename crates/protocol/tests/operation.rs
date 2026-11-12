use p256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};
use vmkek_protocol::{
    public_key_id, GrantBinding, OperationReceipt, ProtocolError, SampleJob,
    SampleOperationRequest, SignedOperationReceipt, SAMPLE_JOB_RECEIPT_OPERATION,
    SAMPLE_OPERATION_RECEIPT_BYTES, SAMPLE_OPERATION_REQUEST_BYTES,
};

#[test]
fn typed_operation_receipt_is_canonical_and_bound() {
    let device = SigningKey::from_slice(&[1; 32]).unwrap();
    let publisher = SigningKey::from_slice(&[2; 32]).unwrap();
    let request = SampleOperationRequest {
        app_id: [3; 16],
        build_id: [4; 16],
        device_id: [5; 16],
        session_id: [6; 16],
        generation_id: [7; 16],
        function_id: [8; 16],
        operation_id: SAMPLE_JOB_RECEIPT_OPERATION,
        request_id: [9; 16],
        sequence: 1,
        job: SampleJob {
            job_id: [10; 16],
            units: 128,
        },
    };
    let encoded = request.encode().unwrap();
    assert_eq!(encoded.len(), SAMPLE_OPERATION_REQUEST_BYTES);
    assert_eq!(&encoded[..8], &[1, 0, 18, 0, 198, 0, 0, 0]);
    assert_eq!(SampleOperationRequest::decode(&encoded), Ok(request));
    assert_eq!(
        SampleOperationRequest::decode(&encoded[..205]),
        Err(ProtocolError::Invalid)
    );
    let signed: Signature = device
        .sign_prehash(&request.signature_digest().unwrap())
        .unwrap();
    assert_eq!(
        request.verify(device.verifying_key(), &signed.to_bytes().into()),
        Ok(())
    );
    let binding = GrantBinding {
        app_id: request.app_id,
        build_id: request.build_id,
        device_id: request.device_id,
        session_id: request.session_id,
        generation_id: request.generation_id,
        license_id: [11; 16],
    };
    let receipt = OperationReceipt {
        binding,
        function_id: request.function_id,
        operation_id: request.operation_id,
        request_id: request.request_id,
        request_digest: request.digest().unwrap(),
        sequence: request.sequence,
        policy_epoch: 1,
        job: request.job,
        value: 896,
        signing_key_id: public_key_id(publisher.verifying_key()),
    };
    let signed = SignedOperationReceipt::sign(receipt, &publisher).unwrap();
    assert_eq!(signed.as_bytes().len(), SAMPLE_OPERATION_RECEIPT_BYTES);
    assert_eq!(&signed.as_bytes()[..8], &[1, 0, 19, 0, 63, 1, 0, 0]);
    let decoded = SignedOperationReceipt::decode(signed.as_bytes()).unwrap();
    assert_eq!(
        decoded.verify_for(publisher.verifying_key(), &request, binding, 1),
        Ok(&receipt)
    );
    assert_eq!(
        decoded.verify_for(device.verifying_key(), &request, binding, 1),
        Err(ProtocolError::Signature)
    );
    let other = SampleOperationRequest {
        job: SampleJob {
            units: 127,
            ..request.job
        },
        ..request
    };
    assert_eq!(
        decoded.verify_for(publisher.verifying_key(), &other, binding, 1),
        Err(ProtocolError::Binding)
    );
    let mut wrong_purpose = signed.as_bytes().to_vec();
    wrong_purpose[290] = 2;
    assert!(matches!(
        SignedOperationReceipt::decode(&wrong_purpose),
        Err(ProtocolError::Invalid)
    ));
    assert!(matches!(
        SignedOperationReceipt::sign(
            OperationReceipt {
                value: 42,
                ..receipt
            },
            &publisher
        ),
        Err(ProtocolError::Invalid)
    ));
}
