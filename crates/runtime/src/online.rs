//! Online initialization and authorization worker.

use std::mem::size_of;
use std::net::SocketAddr;
use std::ops::Deref;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Tag};
use p256::ecdsa::{SigningKey, VerifyingKey};
use rustls::pki_types::CertificateDer;
use sha2::{Digest as _, Sha256};
use tokio::sync::{mpsc as async_mpsc, oneshot, Notify};
use vmkek_client::{
    ClientError, GenerationCapabilities, GenerationSelection, LeaseToken, ModuleCiphertext,
    ModuleSelection, SampleReceiptCall, SessionClient, SessionIdentity, TlsEndpoint,
};
use vmkek_protocol::{
    Digest, GrantPayload, ModuleExpectation, ModulePurpose, OperationReceipt, PackageFrame,
    Permission, PermissionKind, Profile, SampleJob, SignedModuleManifest, SignedTrustBundle,
    VerifiedProgram, VmDescriptor, VmForm, COPY_INPUT_CAPABILITY, MAX_ACTIVE_CONTEXTS,
    MAX_BODY_BYTES, MAX_DEADLINE_MS, SCHEMA_VERSION,
};
use zeroize::Zeroize;

use crate::{
    state::{Call, Generation, LeaseAuthority, Reservation, Runtime},
    Status,
};

mod platform;
#[cfg(windows)]
mod stop_policy;

#[cfg(windows)]
use stop_policy::{Observer, StopNotice, StopPolicy};

const CONFIG_MAX: usize = 128 * 1024;
const CONFIG_WORKING_BYTES: usize = 4 * CONFIG_MAX;
const MODULE_WORKING_BYTES: usize = 2 * MAX_BODY_BYTES;
const REQUEST_DEADLINE: Duration = Duration::from_millis(MAX_DEADLINE_MS as u64);

pub(crate) struct Worker {
    keys: async_mpsc::Sender<WorkerRequest>,
    stop: Option<oneshot::Sender<()>>,
    join: Option<JoinHandle<()>>,
    #[cfg(windows)]
    observer: Option<Observer>,
}

impl Worker {
    pub(crate) fn send_key_request(&self, request: KeyRequest) -> Result<(), Status> {
        self.send(WorkerRequest::Key(request))
    }

    pub(crate) fn send_receipt_request(&self, request: ReceiptRequest) -> Result<(), Status> {
        self.send(WorkerRequest::Receipt(request))
    }

    fn send(&self, request: WorkerRequest) -> Result<(), Status> {
        self.keys.try_send(request).map_err(|error| match error {
            async_mpsc::error::TrySendError::Full(_) => Status::ResourceLimit,
            async_mpsc::error::TrySendError::Closed(_) => Status::Unavailable,
        })
    }
}

struct OwnedKey(Box<[u8; 32]>);

impl Drop for OwnedKey {
    fn drop(&mut self) {
        self.0.as_mut().zeroize();
        #[cfg(test)]
        tests::observe_wipe(0, self.0.as_slice());
    }
}

struct Plaintext(Vec<u8>);

impl Deref for Plaintext {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for Plaintext {
    fn drop(&mut self) {
        self.0.zeroize();
        #[cfg(test)]
        {
            let spare = self.0.spare_capacity_mut();
            // SAFETY: Vec::zeroize wiped every spare byte of this live allocation.
            let wiped =
                unsafe { std::slice::from_raw_parts(spare.as_ptr().cast::<u8>(), spare.len()) };
            tests::observe_wipe(1, wiped);
        }
    }
}

enum WorkerRequest {
    Key(KeyRequest),
    Receipt(ReceiptRequest),
}

pub(crate) struct ReceiptRequest {
    job: SampleJob,
    request_id: [u8; 16],
    receipt_pin: VerifyingKey,
    token: LeaseToken,
    deadline: Instant,
    network_deadline: Instant,
    attempted: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    signal: Arc<Notify>,
    reply: mpsc::SyncSender<Result<OperationReceipt, Status>>,
    _reservation: Arc<Reservation>,
}

pub(crate) struct KeyRequest {
    selection: ModuleSelection,
    token: LeaseToken,
    deadline: Instant,
    network_deadline: Instant,
    attempted: Arc<AtomicBool>,
    cancelled: Arc<AtomicBool>,
    signal: Arc<Notify>,
    reply: mpsc::SyncSender<Result<OwnedKey, Status>>,
}

impl Drop for Worker {
    fn drop(&mut self) {
        #[cfg(windows)]
        drop(self.observer.take());
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(join) = self.join.take() {
            if join.thread().id() != thread::current().id() {
                let _ = join.join();
            }
        }
    }
}

struct Configuration {
    client: SessionClient<SigningKey>,
    launch: Launch,
    active_key: VerifyingKey,
    #[cfg(windows)]
    stop_policy: Option<StopPolicy>,
}

#[derive(Clone, Copy)]
enum Launch {
    Fixed(ModuleSelection),
    Negotiated {
        capabilities: GenerationCapabilities,
        swap_once: bool,
    },
}

#[derive(Clone, Copy)]
enum Selection {
    Fixed(ModuleSelection),
    Negotiated(GenerationSelection, GenerationCapabilities),
}

impl Selection {
    fn module(self) -> ModuleSelection {
        match self {
            Self::Fixed(module) => module,
            Self::Negotiated(selection, _) => selection.module,
        }
    }
}

#[derive(Clone, Copy)]
struct Admitted {
    selection: Selection,
    identity: ModuleIdentity,
}

pub(crate) fn initialize(path: &str) -> Result<Arc<Runtime>, Status> {
    let working = Reservation::new(CONFIG_WORKING_BYTES + MODULE_WORKING_BYTES, true)?;
    // The launcher supplies the config path from a trusted installation
    // directory. Its ancestors and write access are part of that trust.
    let config = Configuration::read(Path::new(path))?;
    #[cfg(windows)]
    let (config, observer) = {
        let mut config = config;
        let observer = config.stop_policy.take().map(|policy| {
            let (priority, observations) = async_mpsc::channel(1);
            (policy, priority, observations)
        });
        (config, observer)
    };
    #[cfg(windows)]
    let (observer, observations) = match observer {
        Some((policy, priority, observations)) => (Some((policy, priority)), Some(observations)),
        None => (None, None),
    };
    let (ready, result) = mpsc::sync_channel(1);
    let (stop, stopped) = oneshot::channel();
    let (keys, requests) = async_mpsc::channel(MAX_ACTIVE_CONTEXTS);
    let join = thread::Builder::new()
        .name("vmkek-online".to_owned())
        .spawn(move || {
            worker(
                config,
                working,
                ready,
                stopped,
                requests,
                #[cfg(windows)]
                observations,
            )
        })
        .map_err(|_| Status::ResourceLimit)?;
    let worker = Worker {
        keys,
        stop: Some(stop),
        join: Some(join),
        #[cfg(windows)]
        observer: None,
    };
    let runtime = result.recv().map_err(|_| Status::Internal)??;
    #[cfg(windows)]
    let worker = {
        let mut worker = worker;
        if let Some((policy, priority)) = observer {
            worker.observer = Some(Observer::start(policy, Arc::downgrade(&runtime), priority)?);
        }
        worker
    };
    runtime.attach_worker(worker);
    Ok(runtime)
}

fn worker(
    mut config: Configuration,
    working: Reservation,
    ready: mpsc::SyncSender<Result<Arc<Runtime>, Status>>,
    stopped: oneshot::Receiver<()>,
    requests: async_mpsc::Receiver<WorkerRequest>,
    #[cfg(windows)] mut observations: Option<async_mpsc::Receiver<StopNotice>>,
) {
    let mut stopped = stopped;
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build();
    let Ok(executor) = executor else {
        let _ = ready.send(Err(Status::Unavailable));
        return;
    };
    let prepared = executor.block_on(async {
        tokio::time::timeout(REQUEST_DEADLINE, config.prepare(working))
            .await
            .map_err(|_| Status::Unavailable)?
    });
    let refresh = prepared
        .as_ref()
        .ok()
        .map(|(runtime, admitted)| (Arc::downgrade(runtime), *admitted));
    if ready.send(prepared.map(|(runtime, _)| runtime)).is_ok() {
        if let Some((runtime, admitted)) = refresh {
            let heartbeat = catch_unwind(AssertUnwindSafe(|| {
                #[cfg(windows)]
                executor.block_on(async {
                    let notice = tokio::select! {
                        biased;
                        notice = wait_observation(&mut observations) => Some(notice),
                        _ = config.heartbeat(runtime.clone(), admitted, &mut stopped, requests) => None,
                    };
                    if let Some(notice) = notice {
                        tokio::select! {
                            biased;
                            _ = &mut stopped => {},
                            _ = config.client.report_local_stop(notice.token, notice.epoch, notice.record) => {},
                        }
                    }
                });
                #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
                executor.block_on(config.heartbeat(
                    runtime.clone(),
                    admitted,
                    &mut stopped,
                    requests,
                ));
            }));
            if heartbeat.is_err() {
                if let Some(runtime) = runtime.upgrade() {
                    runtime.invalidate(Status::Internal);
                }
            }
        }
    }
}

#[cfg(windows)]
async fn wait_observation(receiver: &mut Option<async_mpsc::Receiver<StopNotice>>) -> StopNotice {
    if let Some(receiver) = receiver {
        if let Some(notice) = receiver.recv().await {
            return notice;
        }
    }
    std::future::pending().await
}

impl Configuration {
    fn read(path: &Path) -> Result<Self, Status> {
        let (bytes, signer) = platform::read(path)?;
        Self::decode(&bytes, signer)
    }

    fn decode(input: &[u8], platform_signer: Option<SigningKey>) -> Result<Self, Status> {
        let mut input = ConfigReader(input);
        let (negotiated, observed) = match (&input.fixed::<8>()?, platform_signer.is_some()) {
            (b"VMKR12\0\0", false) => (false, false),
            (b"VMKR13\0\0", false) => (true, false),
            (b"VMKR17\0\0", false) => (true, true),
            (b"VMKR21\0\0", true) => (true, false),
            _ => return Err(Status::Incompatible),
        };
        let identity = SessionIdentity {
            app_id: input.fixed()?,
            build_id: input.fixed()?,
            device_id: input.fixed()?,
            generation_id: input.fixed()?,
            license_id: input.fixed()?,
            policy_epoch: u64::from_le_bytes(input.fixed()?),
            permission: Permission {
                kind: PermissionKind::Function,
                id: input.fixed()?,
            },
        };
        let grant_key = input.public_key()?;
        let root = input.public_key()?;
        let minimum_epoch = u64::from_le_bytes(input.fixed()?);
        let launch = if negotiated {
            let forms = input.fixed::<1>()?[0];
            let capabilities = u16::from_le_bytes(input.fixed()?);
            let flags = input.fixed::<1>()?[0];
            if identity.generation_id != [0; 16]
                || forms == 0
                || forms & !(GenerationCapabilities::STACK | GenerationCapabilities::REGISTER) != 0
                || capabilities & !GenerationCapabilities::COPY_INPUT != 0
                || flags & !1 != 0
            {
                return Err(Status::Incompatible);
            }
            Launch::Negotiated {
                capabilities: GenerationCapabilities {
                    forms,
                    capabilities,
                },
                swap_once: flags == 1,
            }
        } else {
            Launch::Fixed(ModuleSelection {
                module_id: input.fixed()?,
                module_version: u64::from_le_bytes(input.fixed()?),
                manifest_sha256: input.fixed()?,
            })
        };
        let signer = match platform_signer {
            Some(signer) => signer,
            None => SigningKey::from_slice(input.take(32)?).map_err(|_| Status::InvalidArgument)?,
        };
        let socket: SocketAddr = input
            .text(64)?
            .parse()
            .map_err(|_| Status::InvalidArgument)?;
        let dns = input.text(253)?;
        let root_cert = CertificateDer::from(input.field(16 * 1024)?.to_vec());
        let trust = SignedTrustBundle::decode(input.field(CONFIG_MAX)?)
            .map_err(|_| Status::InvalidPackage)?;
        let bundle = trust
            .verify_for(&root, identity.app_id, minimum_epoch)
            .map_err(|_| Status::InvalidPackage)?;
        let active_key = bundle.active_key().map_err(|_| Status::InvalidPackage)?;
        #[cfg(windows)]
        let stop_policy = if observed {
            let flags = input.fixed::<1>()?[0];
            let pin = input.public_key()?;
            let floor = u64::from_le_bytes(input.fixed()?);
            let consent = input.fixed()?;
            let policy = input.field(CONFIG_MAX)?;
            if pin == grant_key
                || pin == root
                || pin == active_key
                || bundle
                    .next
                    .as_ref()
                    .is_some_and(|next| next.as_slice() == pin.to_encoded_point(false).as_bytes())
                || bundle
                    .revoked
                    .binary_search(&vmkek_protocol::public_key_id(&pin))
                    .is_ok()
                || &pin == signer.verifying_key()
            {
                return Err(Status::InvalidArgument);
            }
            Some(StopPolicy::new(
                policy,
                pin,
                consent,
                flags,
                identity.app_id,
                identity.build_id,
                floor,
            )?)
        } else {
            None
        };
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        if observed {
            return Err(Status::Incompatible);
        }
        if !input.0.is_empty() || minimum_epoch == 0 {
            return Err(Status::InvalidArgument);
        }
        let endpoint = TlsEndpoint::new(socket, dns, [root_cert]).map_err(client_error)?;
        let client = SessionClient::new(endpoint, identity, signer, grant_key);
        Ok(Self {
            client,
            launch,
            active_key,
            #[cfg(windows)]
            stop_policy,
        })
    }

    async fn prepare(&mut self, _working: Reservation) -> Result<(Arc<Runtime>, Admitted), Status> {
        let selection = match self.launch {
            Launch::Fixed(module) => {
                self.client.open().await.map_err(client_error)?;
                Selection::Fixed(module)
            }
            Launch::Negotiated { capabilities, .. } => self
                .negotiate(capabilities)
                .await?
                .ok_or(Status::Unavailable)?,
        };
        let (module, ciphertext, authority) = self.open(selection).await?;
        let admitted = Admitted {
            selection,
            identity: module.identity,
        };
        let generation = ciphertext_generation(module, ciphertext, selection)?;
        if Instant::now() >= authority.expires() {
            return Err(Status::Expired);
        }
        Ok((
            Arc::new(Runtime::from_generation(generation, Some(authority.into()))),
            admitted,
        ))
    }

    async fn negotiate(
        &mut self,
        capabilities: GenerationCapabilities,
    ) -> Result<Option<Selection>, Status> {
        self.client
            .negotiate_generation(capabilities)
            .await
            .map(|choice| choice.map(|choice| Selection::Negotiated(choice, capabilities)))
            .map_err(client_error)
    }

    async fn open(
        &mut self,
        selection: Selection,
    ) -> Result<(AuthenticatedModule, ModuleCiphertext, LeaseToken), Status> {
        let package = self
            .client
            .open_module(selection.module())
            .await
            .map_err(client_error)?;
        let grant = self.client.current_grant().ok_or(Status::Expired)?;
        let module = authenticate_module(
            package.frame_bytes(),
            package.key(),
            grant,
            selection,
            &self.active_key,
        )?;
        let authority = self.client.lease_token().ok_or(Status::Expired)?;
        Ok((module, package.into_ciphertext(), authority))
    }

    async fn heartbeat(
        &mut self,
        runtime: Weak<Runtime>,
        mut admitted: Admitted,
        stopped: &mut oneshot::Receiver<()>,
        mut requests: async_mpsc::Receiver<WorkerRequest>,
    ) {
        loop {
            let Some(due) = self.client.heartbeat_due() else {
                if let Some(runtime) = runtime.upgrade() {
                    runtime.invalidate(Status::Expired);
                }
                return;
            };
            let result = tokio::select! {
                biased;
                _ = &mut *stopped => return,
                _ = tokio::time::sleep_until(due.into()) => {
                    tokio::select! {
                        _ = &mut *stopped => return,
                        result = self.maintain(&runtime, &mut admitted) => result,
                    }
                },
                request = requests.recv() => {
                    let Some(request) = request else { return };
                    tokio::select! {
                        _ = &mut *stopped => return,
                        result = async { match request {
                            WorkerRequest::Key(request) => self.serve_key(&runtime, request).await,
                            WorkerRequest::Receipt(request) => self.serve_receipt(&runtime, request).await,
                        }} => result,
                    }
                }
            };
            if let Err(status) = result {
                if let Some(runtime) = runtime.upgrade() {
                    runtime.invalidate(status);
                }
                return;
            }
        }
    }

    async fn serve_key(&self, runtime: &Weak<Runtime>, request: KeyRequest) -> Result<(), Status> {
        if request.cancelled.load(Ordering::Acquire)
            || self.client.lease_token() != Some(request.token)
        {
            let _ = request.reply.send(Err(Status::Cancelled));
            return Ok(());
        }
        let result = tokio::select! {
            biased;
            _ = request.signal.notified() => {
                let _ = request.reply.send(Err(Status::Cancelled));
                return Ok(());
            }
            result = self.client.request_artifact_key(
                request.token, request.selection, request.deadline, request.network_deadline,
                &request.attempted,
            ) => result,
        };
        match result {
            Ok(key) => {
                let _ = request.reply.send(Ok(OwnedKey(Box::new(*key))));
            }
            Err(ClientError::Expired) => {
                let status = deadline_status(request.token);
                let _ = request.reply.send(Err(status));
            }
            Err(error) => {
                let status = client_error(error);
                if let Some(runtime) = runtime.upgrade() {
                    runtime.invalidate(status);
                }
                let _ = request.reply.send(Err(status));
                return Err(status);
            }
        }
        Ok(())
    }

    async fn serve_receipt(
        &self,
        runtime: &Weak<Runtime>,
        request: ReceiptRequest,
    ) -> Result<(), Status> {
        if request.cancelled.load(Ordering::Acquire)
            || self.client.lease_token() != Some(request.token)
        {
            let _ = request.reply.send(Err(Status::Cancelled));
            return Ok(());
        }
        let result = tokio::select! {
            biased;
            _ = request.signal.notified() => {
                let _ = request.reply.send(Err(Status::Cancelled));
                return Ok(());
            }
            result = self.client.request_sample_receipt(SampleReceiptCall {
                token: request.token,
                request_id: request.request_id,
                job: request.job,
                receipt_pin: &request.receipt_pin,
                call_deadline: request.deadline,
                network_deadline: request.network_deadline,
                attempted: &request.attempted,
            }) => result,
        };
        match result {
            Ok(receipt) => {
                let _ = request.reply.send(Ok(receipt));
            }
            Err(ClientError::Expired) => {
                let _ = request.reply.send(Err(deadline_status(request.token)));
            }
            Err(error) => {
                let status = client_error(error);
                let invalidated = request.attempted.load(Ordering::Acquire)
                    && runtime.upgrade().is_some_and(|runtime| {
                        runtime.invalidate_receipt_authority(request.token, status)
                    });
                let _ = request.reply.send(Err(status));
                if invalidated {
                    return Err(status);
                }
            }
        }
        Ok(())
    }

    async fn maintain(
        &mut self,
        runtime: &Weak<Runtime>,
        admitted: &mut Admitted,
    ) -> Result<(), Status> {
        if let Launch::Negotiated {
            capabilities,
            swap_once: true,
        } = self.launch
        {
            self.launch = Launch::Negotiated {
                capabilities,
                swap_once: false,
            };
            return self.rotate(runtime, admitted, capabilities).await;
        }
        let result = self.refresh(admitted.selection).await;
        let runtime = runtime.upgrade().ok_or(Status::Cancelled)?;
        publish_refresh(&runtime, admitted.identity, result)
    }

    async fn rotate(
        &mut self,
        runtime: &Weak<Runtime>,
        admitted: &mut Admitted,
        capabilities: GenerationCapabilities,
    ) -> Result<(), Status> {
        let ticket = runtime.upgrade().ok_or(Status::Cancelled)?.start_swap()?;
        let working = Reservation::new(MODULE_WORKING_BYTES, true)?;
        if let Some(selection) = self.negotiate(capabilities).await? {
            let (module, ciphertext, authority) = self.open(selection).await?;
            let identity = module.identity;
            let generation = ciphertext_generation(module, ciphertext, selection)?;
            let runtime = runtime.upgrade().ok_or(Status::Cancelled)?;
            runtime.install_generation(ticket, generation, authority)?;
            *admitted = Admitted {
                selection,
                identity,
            };
            return Ok(());
        }
        drop(working);
        let (identity, expires) = self.refresh(admitted.selection).await?;
        if identity != admitted.identity {
            return Err(Status::InvalidPackage);
        }
        runtime
            .upgrade()
            .ok_or(Status::Cancelled)?
            .continue_generation(ticket, expires)
    }

    async fn refresh(
        &mut self,
        selection: Selection,
    ) -> Result<(ModuleIdentity, LeaseToken), Status> {
        let _working = Reservation::new(MODULE_WORKING_BYTES, true)?;
        self.client.renew().await.map_err(client_error)?;
        let (module, _, authority) = self.open(selection).await?;
        drop(verify_program(&module.descriptor, &module.plaintext)?);
        Ok((module.identity, authority))
    }
}

fn publish_refresh(
    runtime: &Runtime,
    admitted: ModuleIdentity,
    refresh: Result<(ModuleIdentity, impl Into<LeaseAuthority>), Status>,
) -> Result<(), Status> {
    let result = refresh.and_then(|(identity, expires)| {
        if identity != admitted {
            return Err(Status::InvalidPackage);
        }
        runtime.set_lease(expires)
    });
    if let Err(status) = result {
        runtime.invalidate(status);
    }
    result
}

struct ConfigReader<'a>(&'a [u8]);

impl<'a> ConfigReader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], Status> {
        let (field, remaining) = self
            .0
            .split_at_checked(size)
            .ok_or(Status::InvalidArgument)?;
        self.0 = remaining;
        Ok(field)
    }

    fn fixed<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], Status> {
        self.take(SIZE)?
            .try_into()
            .map_err(|_| Status::InvalidArgument)
    }

    fn field(&mut self, limit: usize) -> Result<&'a [u8], Status> {
        let size = u32::from_le_bytes(self.fixed()?) as usize;
        if size == 0 || size > limit {
            return Err(Status::InvalidArgument);
        }
        self.take(size)
    }

    fn text(&mut self, limit: usize) -> Result<&'a str, Status> {
        std::str::from_utf8(self.field(limit)?).map_err(|_| Status::InvalidArgument)
    }

    fn public_key(&mut self) -> Result<VerifyingKey, Status> {
        VerifyingKey::from_sec1_bytes(self.take(65)?).map_err(|_| Status::InvalidArgument)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ModuleIdentity {
    descriptor: Digest,
    program: Digest,
}

struct AuthenticatedModule {
    descriptor: VmDescriptor,
    plaintext: Plaintext,
    identity: ModuleIdentity,
    seal: Seal,
}

struct Seal {
    aad: Vec<u8>,
    nonce: [u8; 12],
    tag: [u8; 16],
}

impl Seal {
    fn open(&self, ciphertext: &[u8], key: &[u8; 32]) -> Result<Plaintext, Status> {
        let mut plaintext = Plaintext(ciphertext.to_vec());
        ChaCha20Poly1305::new(key.into())
            .decrypt_in_place_detached(
                (&self.nonce).into(),
                &self.aad,
                &mut plaintext.0,
                Tag::from_slice(&self.tag),
            )
            .map_err(|_| Status::InvalidPackage)?;
        Ok(plaintext)
    }
}

fn authenticate_module(
    frame_bytes: &[u8],
    key: &[u8; 32],
    grant: &GrantPayload,
    selection: Selection,
    active_key: &VerifyingKey,
) -> Result<AuthenticatedModule, Status> {
    let frame = PackageFrame::decode(frame_bytes).map_err(|_| Status::InvalidPackage)?;
    let module = selection.module();
    if <[u8; 32]>::from(Sha256::digest(frame.manifest)) != module.manifest_sha256 {
        return Err(Status::InvalidPackage);
    }
    let descriptor = VmDescriptor::decode(frame.descriptor).map_err(crate::descriptor_error)?;
    check_scope(&descriptor, grant, selection)?;
    let signed = SignedModuleManifest::decode(frame.manifest).map_err(crate::descriptor_error)?;
    let expected = ModuleExpectation {
        descriptor: &descriptor,
        module_id: module.module_id,
        module_version: module.module_version,
        purpose: ModulePurpose::Bytecode,
        now_ms: grant.issued_at_ms,
    };
    let manifest = signed
        .verify_for(active_key, &expected, frame.ciphertext)
        .map_err(crate::descriptor_error)?;
    let seal = Seal {
        aad: manifest
            .authentication_data()
            .map_err(crate::descriptor_error)?,
        nonce: manifest.nonce,
        tag: manifest.tag,
    };
    let plaintext = seal.open(frame.ciphertext, key)?;
    let program = Sha256::digest(plaintext.as_ref()).into();
    if descriptor.program_sha256 != program {
        return Err(Status::InvalidPackage);
    }
    let identity = ModuleIdentity {
        descriptor: manifest.descriptor_sha256,
        program,
    };
    Ok(AuthenticatedModule {
        descriptor,
        plaintext,
        identity,
        seal,
    })
}

fn check_scope(
    descriptor: &VmDescriptor,
    grant: &GrantPayload,
    selection: Selection,
) -> Result<(), Status> {
    match selection {
        Selection::Fixed(_) if descriptor.form != VmForm::Stack => {
            return Err(Status::Incompatible)
        }
        Selection::Negotiated(choice, supported) => {
            if descriptor.generation_id != choice.generation_id
                || descriptor.form != choice.form
                || !supported.supports(descriptor.form)
                || descriptor.sha256().map_err(crate::descriptor_error)? != choice.descriptor_sha256
                || (descriptor.permits_copy_input()
                    && supported.capabilities & GenerationCapabilities::COPY_INPUT == 0)
            {
                return Err(Status::InvalidPackage);
            }
        }
        Selection::Fixed(_) => {}
    }
    if descriptor.profile != Profile::Online
        || descriptor.depth != 2
        || descriptor
            .capabilities
            .iter()
            .any(|cap| cap.id != COPY_INPUT_CAPABILITY)
    {
        return Err(Status::Incompatible);
    }
    if descriptor.app_id != grant.binding.app_id
        || descriptor.build_id != grant.binding.build_id
        || descriptor.generation_id != grant.binding.generation_id
        || grant.permissions.as_slice()
            != [Permission {
                kind: PermissionKind::Function,
                id: descriptor.function_id,
            }]
    {
        return Err(Status::InvalidPackage);
    }
    Ok(())
}

fn verify_program(
    descriptor: &VmDescriptor,
    plaintext: &[u8],
) -> Result<(VerifiedProgram, Reservation), Status> {
    if !plaintext.starts_with(&SCHEMA_VERSION.to_le_bytes()) {
        return Err(Status::Incompatible);
    }
    let mut verification = descriptor.clone();
    verification.profile = Profile::Lab;
    let estimate = VerifiedProgram::verification_bytes_for(&verification, plaintext)?;
    let mut reservation = Reservation::new(estimate, false)?;
    let verified = VerifiedProgram::verify(&verification, plaintext)?;
    reservation.shrink(verified.memory_bytes())?;
    Ok((verified, reservation))
}

const MAX_PREFETCH_FRAMES: usize = 4;
static PREFETCH: Mutex<(usize, usize)> = Mutex::new((0, 0));

struct FramePermit {
    bytes: usize,
    _memory: Reservation,
}

impl FramePermit {
    fn new(bytes: usize) -> Result<Self, Status> {
        let memory = Reservation::new(bytes, false)?;
        let mut quota = PREFETCH
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if quota.0 >= MAX_PREFETCH_FRAMES || bytes > MAX_BODY_BYTES - quota.1 {
            return Err(Status::ResourceLimit);
        }
        quota.0 += 1;
        quota.1 += bytes;
        Ok(Self {
            bytes,
            _memory: memory,
        })
    }
}

impl Drop for FramePermit {
    fn drop(&mut self) {
        let mut quota = PREFETCH
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        quota.0 -= 1;
        quota.1 -= self.bytes;
    }
}

pub(crate) struct CiphertextFrame {
    frame: Box<[u8]>,
    descriptor: VmDescriptor,
    seal: Seal,
    selection: ModuleSelection,
    _permit: FramePermit,
}

fn ciphertext_generation(
    module: AuthenticatedModule,
    frame: ModuleCiphertext,
    selection: Selection,
) -> Result<Generation, Status> {
    drop(verify_program(&module.descriptor, &module.plaintext)?);
    let AuthenticatedModule {
        descriptor,
        plaintext,
        seal,
        ..
    } = module;
    drop(plaintext);
    let permit = FramePermit::new(frame.as_bytes().len())?;
    let (id, form, budgets) = (
        descriptor.generation_id,
        descriptor.form,
        descriptor.budgets,
    );
    let frame = CiphertextFrame {
        frame: frame.as_bytes().into(),
        descriptor,
        seal,
        selection: selection.module(),
        _permit: permit,
    };
    let reservation = Reservation::new(
        size_of::<Runtime>()
            + size_of::<Generation>()
            + size_of::<CiphertextFrame>()
            + CONFIG_WORKING_BYTES,
        false,
    )?;
    Ok(Generation::online(
        id,
        form,
        frame,
        budgets.deadline_ms,
        usize::from(budgets.active_contexts),
        reservation,
    ))
}

impl CiphertextFrame {
    pub(crate) fn load(
        &self,
        runtime: &Runtime,
        call: &Call,
        deadline: Instant,
        network_deadline: Instant,
    ) -> Result<(VerifiedProgram, Reservation, Reservation), Status> {
        let token = call.key_token.ok_or(Status::Internal)?;
        let frame = PackageFrame::decode(&self.frame).map_err(|_| Status::InvalidPackage)?;
        let working =
            Reservation::new(frame.ciphertext.len() + frame.descriptor.len() + 4096, true)?;
        let key = acquire_key(
            runtime,
            call,
            self.selection,
            token,
            deadline,
            network_deadline,
        )?;
        if call.cancelled.load(Ordering::Acquire) {
            return Err(Status::Cancelled);
        }
        if Instant::now() >= deadline {
            return Err(deadline_status(token));
        }
        let plaintext = self
            .seal
            .open(frame.ciphertext, &key.0)
            .inspect_err(|status| runtime.invalidate(*status))?;
        #[cfg(test)]
        tests::lifecycle::pause(tests::lifecycle::Checkpoint::Decrypted, call);
        drop(key);
        if <[u8; 32]>::from(Sha256::digest(plaintext.as_ref())) != self.descriptor.program_sha256 {
            runtime.invalidate(Status::InvalidPackage);
            return Err(Status::InvalidPackage);
        }
        let (verified, retained) = verify_program(&self.descriptor, &plaintext)?;
        drop(plaintext);
        #[cfg(test)]
        tests::lifecycle::pause(tests::lifecycle::Checkpoint::Verified, call);
        Ok((verified, retained, working))
    }
}

fn acquire_key(
    runtime: &Runtime,
    call: &Call,
    selection: ModuleSelection,
    token: LeaseToken,
    deadline: Instant,
    network_deadline: Instant,
) -> Result<OwnedKey, Status> {
    let (reply, result) = mpsc::sync_channel(1);
    let attempted = Arc::new(AtomicBool::new(false));
    runtime.send_key_request(KeyRequest {
        selection,
        token,
        deadline,
        network_deadline,
        attempted: attempted.clone(),
        cancelled: call.cancelled.clone(),
        signal: call.signal.clone(),
        reply,
    })?;
    loop {
        if call.cancelled.load(Ordering::Acquire) {
            return Err(Status::Cancelled);
        }
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
        else {
            if deadline == network_deadline
                && deadline < token.expires()
                && attempted.load(Ordering::Acquire)
            {
                runtime.invalidate(Status::Unavailable);
                return Err(Status::Unavailable);
            }
            return Err(deadline_status(token));
        };
        match result.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Status::Unavailable),
        }
    }
}

pub(crate) fn acquire_receipt(
    runtime: &Runtime,
    call: &Call,
    request_id: [u8; 16],
    job: SampleJob,
    receipt_pin: VerifyingKey,
    deadline: Instant,
    network_deadline: Instant,
) -> Result<(OperationReceipt, Arc<Reservation>), Status> {
    let token = call.key_token.ok_or(Status::Incompatible)?;
    let reservation = Arc::new(Reservation::new(64 * 1024, true)?);
    let (reply, result) = mpsc::sync_channel(1);
    let attempted = Arc::new(AtomicBool::new(false));
    runtime.send_receipt_request(ReceiptRequest {
        job,
        request_id,
        receipt_pin,
        token,
        deadline,
        network_deadline,
        attempted: attempted.clone(),
        cancelled: call.cancelled.clone(),
        signal: call.signal.clone(),
        reply,
        _reservation: reservation.clone(),
    })?;
    let cutoff = || {
        if Instant::now() >= token.expires() {
            runtime.invalidate_receipt_authority(token, Status::Expired);
            Status::Expired
        } else if deadline == network_deadline && attempted.load(Ordering::Acquire) {
            runtime.invalidate_receipt_authority(token, Status::Unavailable);
            Status::Unavailable
        } else {
            Status::ResourceLimit
        }
    };
    loop {
        if call.cancelled.load(Ordering::Acquire) {
            return Err(Status::Cancelled);
        }
        let Some(remaining) = deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
        else {
            return Err(cutoff());
        };
        match result.recv_timeout(remaining.min(Duration::from_millis(10))) {
            Ok(_) if Instant::now() >= deadline => return Err(cutoff()),
            Ok(result) => return result.map(|receipt| (receipt, reservation)),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(Status::Unavailable),
        }
    }
}

fn deadline_status(token: LeaseToken) -> Status {
    if Instant::now() >= token.expires() {
        Status::Expired
    } else {
        Status::ResourceLimit
    }
}

fn client_error(error: ClientError) -> Status {
    match error {
        ClientError::Expired | ClientError::NoSession => Status::Expired,
        ClientError::Denied => Status::Denied,
        ClientError::BodyLimit => Status::ResourceLimit,
        ClientError::Configuration => Status::InvalidArgument,
        ClientError::InvalidResponse | ClientError::Verification => Status::InvalidPackage,
        _ => Status::Unavailable,
    }
}

#[cfg(test)]
mod tests;
