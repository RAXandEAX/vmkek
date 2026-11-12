use tokio::time::Instant;
use vmkek_protocol::{
    Digest, GenerationOffer, Id, PermissionKind, SessionGrant, SessionGrantExpectation,
    SignedGenerationChoice, VmForm, ABI_VERSION, GENERATION_COPY_INPUT, GENERATION_REGISTER,
    GENERATION_STACK, SCHEMA_VERSION,
};

use crate::{
    complete_renewal, module::request_id, ClientError, DeviceSigner, Lease, ModuleSelection,
    SessionClient,
};

const SELECT_PATH: &str = "/v1/generation/select";
const COMPLETE_PATH: &str = "/v1/generation/complete";

#[derive(Clone, Copy)]
pub struct GenerationCapabilities {
    pub forms: u8,
    pub capabilities: u16,
}

impl GenerationCapabilities {
    pub const STACK: u8 = GENERATION_STACK;
    pub const REGISTER: u8 = GENERATION_REGISTER;
    pub const COPY_INPUT: u16 = GENERATION_COPY_INPUT;

    pub fn supports(self, form: VmForm) -> bool {
        let bit = match form {
            VmForm::Stack => Self::STACK,
            VmForm::Register => Self::REGISTER,
        };
        self.forms & bit != 0
    }
}

#[derive(Clone, Copy)]
pub struct GenerationSelection {
    pub generation_id: Id,
    pub form: VmForm,
    pub descriptor_sha256: Digest,
    pub module: ModuleSelection,
}

impl<S: DeviceSigner> SessionClient<S> {
    /// The first permitted renewal point under the current monotonic lease.
    pub fn heartbeat_due(&self) -> Option<std::time::Instant> {
        self.active
            .as_ref()
            .filter(|lease| Instant::now() < lease.expires)
            .map(|lease| lease.heartbeat.into_std())
    }

    /// Negotiate one prepublished generation. An authenticated no-choice reply
    /// preserves an unexpired prior lease. Any error or cancellation clears it.
    pub async fn negotiate_generation(
        &mut self,
        supported: GenerationCapabilities,
    ) -> Result<Option<GenerationSelection>, ClientError> {
        let previous = self.active.take();
        let exchange = self.exchange_generation(supported);
        let result = match &previous {
            Some(lease) => {
                if Instant::now() >= lease.expires {
                    return Err(ClientError::Expired);
                }
                complete_renewal(lease.expires, exchange).await?
            }
            None => exchange.await?,
        };
        let Some((selection, lease)) = result else {
            self.active = previous;
            return Ok(None);
        };
        self.identity.generation_id = selection.generation_id;
        self.active = Some(lease);
        Ok(Some(selection))
    }

    async fn exchange_generation(
        &self,
        supported: GenerationCapabilities,
    ) -> Result<Option<(GenerationSelection, Lease)>, ClientError> {
        let started = Instant::now();
        let offer = self.generation_offer(supported)?;
        let request = self.signed(offer.encode(), offer.signature_digest())?;
        let Some(reply) = self
            .endpoint
            .post_generation_choice(SELECT_PATH, request)
            .await?
        else {
            return Ok(None);
        };
        let signed =
            SignedGenerationChoice::decode(&reply).map_err(|_| ClientError::Verification)?;
        let choice = signed
            .verify_for(&self.grant_key)
            .map_err(|_| ClientError::Verification)?;
        if choice.offer_digest != offer.digest().map_err(|_| ClientError::Verification)?
            || choice.binding.app_id != offer.app_id
            || choice.binding.build_id != offer.build_id
            || choice.binding.device_id != offer.device_id
            || choice.binding.license_id != self.identity.license_id
            || choice.binding.generation_id == [0; 16]
            || choice.binding.generation_id == self.identity.generation_id
            || choice.binding.session_id == [0; 16]
            || choice.function_id != offer.function_id
            || choice.policy_epoch != self.identity.policy_epoch
            || !supported.supports(choice.form)
        {
            return Err(ClientError::Verification);
        }
        let selection = GenerationSelection {
            generation_id: choice.binding.generation_id,
            form: choice.form,
            descriptor_sha256: choice.descriptor_sha256,
            module: ModuleSelection {
                module_id: choice.module_id,
                module_version: choice.module_version,
                manifest_sha256: choice.manifest_sha256,
            },
        };
        let expected = SessionGrantExpectation {
            binding: choice.binding,
            policy_epoch: choice.policy_epoch,
            sequence: 1,
            permission: self.identity.permission,
            challenge_digest: signed.digest(),
        };
        let completion = self.signed(
            Ok(signed.as_bytes().to_vec()),
            Ok(signed.completion_digest()),
        )?;
        let bytes = self.endpoint.post(COMPLETE_PATH, completion).await?;
        let grant = SessionGrant::decode(&bytes).map_err(|_| ClientError::Verification)?;
        let payload = grant
            .verify_session(&self.grant_key, &expected)
            .map_err(|_| ClientError::Verification)?
            .clone();
        let lease = Lease::new(payload, started, Instant::now())?;
        Ok(Some((selection, lease)))
    }

    fn generation_offer(
        &self,
        supported: GenerationCapabilities,
    ) -> Result<GenerationOffer, ClientError> {
        if self.identity.permission.kind != PermissionKind::Function {
            return Err(ClientError::Denied);
        }
        Ok(GenerationOffer {
            app_id: self.identity.app_id,
            build_id: self.identity.build_id,
            device_id: self.identity.device_id,
            function_id: self.identity.permission.id,
            request_id: request_id()?,
            descriptor_schema: SCHEMA_VERSION,
            descriptor_abi: ABI_VERSION,
            forms: supported.forms,
            capabilities: supported.capabilities,
        })
    }
}
