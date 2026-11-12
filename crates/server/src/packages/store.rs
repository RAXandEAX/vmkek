use p256::ecdsa::VerifyingKey;
use sha2::{Digest as _, Sha256};
use sqlx::{Postgres, Row, Transaction};
use vmkek_packager::{SealedPackage, SealedRelease};
use vmkek_protocol::{
    encode_module_key, public_key_id, Digest, Id, ModuleExpectation, ModuleFetch, ModuleManifest,
    ModuleOpen, ModulePurpose, PackageFrame, Profile, ProtocolError, SignedModuleManifest,
    SignedTrustBundle, TrustBundle, VmDescriptor,
};
use zeroize::Zeroizing;

use super::keys::{verify_key, ModuleKeyStore};
use crate::session::{SessionError, SessionStore};

type Tx<'a> = Transaction<'a, Postgres>;
type Result<T> = std::result::Result<T, PackageError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackageError {
    #[error("invalid package or trust bundle")]
    Invalid,
    #[error("package or trust operation denied")]
    Denied,
    #[error("package version or request conflicts with prior state")]
    Conflict,
    #[error("package store unavailable")]
    Unavailable,
    #[error(transparent)]
    Session(#[from] SessionError),
}

impl From<sqlx::Error> for PackageError {
    fn from(_: sqlx::Error) -> Self {
        Self::Unavailable
    }
}

impl From<ProtocolError> for PackageError {
    fn from(error: ProtocolError) -> Self {
        match error {
            ProtocolError::Signature | ProtocolError::Binding | ProtocolError::Expired => {
                Self::Denied
            }
            _ => Self::Invalid,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseScope {
    pub build_id: Id,
    pub generation_id: Id,
    pub function_id: Id,
    pub module_id: Id,
    pub version: u64,
}

#[derive(Clone)]
pub struct PackageStore {
    session: SessionStore,
    root: VerifyingKey,
    minimum_epoch: u64,
}

impl PackageStore {
    pub fn new(session: SessionStore, root: VerifyingKey, minimum_epoch: u64) -> Result<Self> {
        if minimum_epoch == 0
            || minimum_epoch > i64::MAX as u64
            || public_key_id(&root) == session.grant_signer_id()
        {
            return Err(PackageError::Invalid);
        }
        Ok(Self {
            session,
            root,
            minimum_epoch,
        })
    }

    pub(crate) fn shares_authority(&self, other: &Self) -> bool {
        self.session.shares_authority(&other.session)
            && self.root == other.root
            && self.minimum_epoch == other.minimum_epoch
    }

    pub(crate) fn session(&self) -> &SessionStore {
        &self.session
    }

    /// Trusted build-plane administration. The independently configured root authenticates bundles.
    pub async fn install_trust(&self, actor: Id, signed: &SignedTrustBundle) -> Result<()> {
        let app = self.session.package_app();
        let bundle = self.verify_bundle(signed)?;
        let epoch = version(bundle.epoch)?;
        let mut tx = self.session.begin_package().await?;
        let now = version(self.session.package_time()?)?;
        let inserted = sqlx::query(
            "INSERT INTO package_trust (app_id,epoch,wall_floor_ms,bundle) VALUES ($1,$2,$3,$4)
             ON CONFLICT (app_id) DO NOTHING",
        )
        .bind(app.as_slice())
        .bind(epoch)
        .bind(now)
        .bind(signed.as_bytes())
        .execute(&mut *tx)
        .await?
        .rows_affected()
            == 1;
        let previous = if inserted {
            None
        } else {
            Some(self.lock_trust(&mut tx).await?)
        };
        let durable: Vec<Vec<u8>> =
            sqlx::query_scalar("SELECT key_id FROM package_revoked_keys WHERE app_id=$1")
                .bind(app.as_slice())
                .fetch_all(&mut *tx)
                .await?;
        for key in durable {
            let key = key.try_into().map_err(|_| PackageError::Unavailable)?;
            if bundle.revoked.binary_search(&key).is_err() {
                return Err(PackageError::Denied);
            }
        }
        if let Some(previous) = previous {
            if previous.signed.as_bytes() == signed.as_bytes() {
                tx.commit().await?;
                return Ok(());
            }
            // Verify the prior signature even when the independent checkpoint has advanced.
            bundle.check_successor(previous.signed.verify_for(&self.root, app, 1)?)?;
            sqlx::query("UPDATE package_trust SET epoch=$2,bundle=$3 WHERE app_id=$1")
                .bind(app.as_slice())
                .bind(epoch)
                .bind(signed.as_bytes())
                .execute(&mut *tx)
                .await?;
        }
        for revoked in &bundle.revoked {
            sqlx::query("INSERT INTO package_revoked_keys (app_id,key_id) VALUES ($1,$2) ON CONFLICT DO NOTHING")
                .bind(app.as_slice()).bind(revoked.as_slice()).execute(&mut *tx).await?;
        }
        audit(&mut tx, app, actor, "trust_installed", epoch, None).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Accept only an opaque package constructed by the offline typed build verifier.
    pub async fn publish(
        &self,
        actor: Id,
        scope: ReleaseScope,
        package: &SealedPackage,
    ) -> Result<()> {
        let app = self.session.package_app();
        let release_version = version(scope.version)?;
        let frame = PackageFrame {
            descriptor: package.descriptor_bytes(),
            manifest: package.manifest_bytes(),
            ciphertext: package.ciphertext(),
        };
        let encoded = frame.encode()?;
        let mut tx = self.session.begin_package().await?;
        let trust = self.lock_trust(&mut tx).await?;
        let bundle = self.verify_bundle(&trust.signed)?;
        let now = self.time(&trust)?;
        verify_frame(frame, app, scope, &bundle.active_key()?, now)?;
        let latest: Option<i64> = sqlx::query_scalar(
            "SELECT max(version) FROM package_releases WHERE app_id=$1 AND module_id=$2",
        )
        .bind(app.as_slice())
        .bind(scope.module_id.as_slice())
        .fetch_one(&mut *tx)
        .await?;
        if latest.is_some_and(|latest| release_version <= latest) {
            return Err(PackageError::Conflict);
        }
        sqlx::query(
            "INSERT INTO package_releases (app_id,module_id,version,frame) VALUES ($1,$2,$3,$4)",
        )
        .bind(app.as_slice())
        .bind(scope.module_id.as_slice())
        .bind(release_version)
        .bind(encoded)
        .execute(&mut *tx)
        .await?;
        touch_time(&mut tx, app, now).await?;
        audit(
            &mut tx,
            app,
            actor,
            "release_published",
            trust.epoch,
            Some((scope.module_id, release_version)),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn revoke_release(&self, actor: Id, module: Id, release_version: u64) -> Result<()> {
        let app = self.session.package_app();
        let release_version = version(release_version)?;
        let mut tx = self.session.begin_package().await?;
        let trust = self.lock_trust(&mut tx).await?;
        self.verify_bundle(&trust.signed)?;
        let changed = sqlx::query(
            "UPDATE package_releases SET revoked=true WHERE app_id=$1 AND module_id=$2 AND version=$3 AND NOT revoked",
        ).bind(app.as_slice()).bind(module.as_slice()).bind(release_version).execute(&mut *tx).await?;
        if changed.rows_affected() != 1 {
            return Err(PackageError::Denied);
        }
        audit(
            &mut tx,
            app,
            actor,
            "release_revoked",
            trust.epoch,
            Some((module, release_version)),
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    fn verify_bundle<'a>(&self, signed: &'a SignedTrustBundle) -> Result<&'a TrustBundle> {
        let bundle =
            signed.verify_for(&self.root, self.session.package_app(), self.minimum_epoch)?;
        let grant_signer = self.session.grant_signer_id();
        if public_key_id(&bundle.active_key()?) == grant_signer
            || bundle
                .next
                .as_ref()
                .and_then(|next| VerifyingKey::from_sec1_bytes(next).ok())
                .is_some_and(|next| public_key_id(&next) == grant_signer)
        {
            return Err(PackageError::Denied);
        }
        Ok(bundle)
    }

    async fn lock_trust(&self, tx: &mut Tx<'_>) -> Result<LockedTrust> {
        let app = self.session.package_app();
        let row = sqlx::query(
            "SELECT epoch,bundle,wall_floor_ms FROM package_trust WHERE app_id=$1 FOR UPDATE",
        )
        .bind(app.as_slice())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(PackageError::Denied)?;
        let signed = SignedTrustBundle::decode(row.try_get::<&[u8], _>("bundle")?)?;
        let epoch: i64 = row.try_get("epoch")?;
        if version(signed.verify_for(&self.root, app, 1)?.epoch)? != epoch {
            return Err(PackageError::Unavailable);
        }
        Ok(LockedTrust {
            signed,
            epoch,
            wall_floor: row.try_get("wall_floor_ms")?,
        })
    }

    fn time(&self, trust: &LockedTrust) -> Result<u64> {
        let now = self.session.package_time()?;
        if version(now)? < trust.wall_floor {
            return Err(PackageError::Unavailable);
        }
        Ok(now)
    }
}

struct LockedTrust {
    signed: SignedTrustBundle,
    epoch: i64,
    wall_floor: i64,
}

fn verify_frame(
    frame: PackageFrame<'_>,
    app: Id,
    scope: ReleaseScope,
    key: &VerifyingKey,
    now: u64,
) -> Result<ModuleManifest> {
    let descriptor = VmDescriptor::decode(frame.descriptor)?;
    if descriptor.profile != Profile::Online
        || (
            descriptor.app_id,
            descriptor.build_id,
            descriptor.function_id,
            descriptor.generation_id,
        ) != (app, scope.build_id, scope.function_id, scope.generation_id)
    {
        return Err(PackageError::Denied);
    }
    let manifest = SignedModuleManifest::decode(frame.manifest)?;
    let verified = manifest.verify_for(
        key,
        &ModuleExpectation {
            descriptor: &descriptor,
            module_id: scope.module_id,
            module_version: scope.version,
            purpose: ModulePurpose::Bytecode,
            now_ms: now,
        },
        frame.ciphertext,
    )?;
    Ok(verified.clone())
}

fn version(value: u64) -> Result<i64> {
    i64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or(PackageError::Invalid)
}

async fn touch_time(tx: &mut Tx<'_>, app: Id, time: u64) -> Result<()> {
    sqlx::query(
        "UPDATE package_trust SET wall_floor_ms=GREATEST(wall_floor_ms,$2) WHERE app_id=$1",
    )
    .bind(app.as_slice())
    .bind(version(time)?)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

async fn audit(
    tx: &mut Tx<'_>,
    app: Id,
    actor: Id,
    action: &'static str,
    epoch: i64,
    release: Option<(Id, i64)>,
) -> Result<()> {
    sqlx::query("INSERT INTO package_audit (app_id,actor_id,action,epoch,module_id,version) VALUES ($1,$2,$3,$4,$5,$6)")
        .bind(app.as_slice()).bind(actor.as_slice()).bind(action).bind(epoch)
        .bind(release.as_ref().map(|(module,_)| module.as_slice())).bind(release.map(|(_,v)| v))
        .execute(&mut **tx).await?;
    Ok(())
}

impl PackageStore {
    pub(crate) async fn fetch(&self, request: ModuleFetch, proof: [u8; 64]) -> Result<Vec<u8>> {
        if request.purpose != ModulePurpose::Bytecode {
            return Err(PackageError::Denied);
        }
        let mut authorization = self
            .session
            .authorize_package(&request, |key| request.verify(key, &proof))
            .await?;
        let result = self
            .issue(&mut authorization.tx, request, None, authorization.selected)
            .await;
        match result {
            Err(PackageError::Unavailable | PackageError::Session(SessionError::Unavailable)) => {
                result.map(|(frame, _)| frame)
            }
            Ok((frame, _)) => {
                authorization.ensure_live()?;
                authorization.tx.commit().await?;
                Ok(frame)
            }
            Err(error) => {
                authorization.tx.commit().await?;
                Err(error)
            }
        }
    }

    async fn issue(
        &self,
        tx: &mut Tx<'_>,
        request: ModuleFetch,
        open: Option<&ModuleOpen>,
        selected: Option<(Digest, Digest)>,
    ) -> Result<(Vec<u8>, u64)> {
        let duplicate: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM session_requests WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM generation_offers WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM operation_requests WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM session_observation_reports WHERE device_id=$1 AND request_id=$2)",
        )
        .bind(request.device_id.as_slice())
        .bind(request.request_id.as_slice())
        .fetch_one(&mut **tx)
        .await?;
        if duplicate {
            return Err(PackageError::Conflict);
        }
        let digest = match open {
            Some(open) => open.digest()?,
            None => request.digest()?,
        };
        let inserted = sqlx::query(
            "INSERT INTO package_fetch_requests (device_id,request_id,request_digest)
             VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
        )
        .bind(request.device_id.as_slice())
        .bind(request.request_id.as_slice())
        .bind(digest.as_slice())
        .execute(&mut **tx)
        .await?
        .rows_affected()
            == 1;
        if !inserted {
            if open.is_some() {
                return Err(PackageError::Conflict);
            }
            let row = sqlx::query(
                "SELECT request_digest,delivered FROM package_fetch_requests WHERE device_id=$1 AND request_id=$2",
            ).bind(request.device_id.as_slice()).bind(request.request_id.as_slice()).fetch_one(&mut **tx).await?;
            if row.try_get::<&[u8], _>("request_digest")? != digest {
                return Err(PackageError::Conflict);
            }
            if !row.try_get::<bool, _>("delivered")? {
                return Err(PackageError::Denied);
            }
        }

        let scope = ReleaseScope {
            build_id: request.build_id,
            generation_id: request.generation_id,
            function_id: request.function_id,
            module_id: request.module_id,
            version: request.module_version,
        };
        let expected_manifest = open.map(|open| open.manifest_sha256);
        if selected.is_some_and(|(_, manifest)| {
            expected_manifest.is_some_and(|expected| manifest != expected)
        }) {
            return Err(PackageError::Denied);
        }
        let (bytes, manifest) = self
            .load_active_release(
                tx,
                request.app_id,
                scope,
                selected.map(|(descriptor, _)| descriptor),
                expected_manifest.or(selected.map(|(_, manifest)| manifest)),
            )
            .await?;
        if inserted {
            sqlx::query("UPDATE package_fetch_requests SET delivered=true WHERE device_id=$1 AND request_id=$2")
                .bind(request.device_id.as_slice()).bind(request.request_id.as_slice()).execute(&mut **tx).await?;
        }
        Ok((bytes, manifest.expires_at_ms))
    }
}

impl PackageStore {
    pub(crate) async fn check_operation_signer(
        &self,
        tx: &mut Tx<'_>,
        operation_key: Digest,
    ) -> Result<()> {
        let trust = self.lock_trust(tx).await?;
        let bundle = self.verify_bundle(&trust.signed)?;
        let next_matches = bundle
            .next
            .as_ref()
            .and_then(|key| VerifyingKey::from_sec1_bytes(key).ok())
            .is_some_and(|key| public_key_id(&key) == operation_key);
        if bundle.root_key_id == operation_key
            || public_key_id(&bundle.active_key()?) == operation_key
            || next_matches
            || bundle.revoked.binary_search(&operation_key).is_ok()
        {
            return Err(PackageError::Denied);
        }
        Ok(())
    }

    pub(crate) async fn active_release_signer(&self, tx: &mut Tx<'_>) -> Result<Digest> {
        let trust = self.lock_trust(tx).await?;
        let bundle = self.verify_bundle(&trust.signed)?;
        Ok(public_key_id(&bundle.active_key()?))
    }

    pub(crate) async fn load_active_release(
        &self,
        tx: &mut Tx<'_>,
        app: Id,
        scope: ReleaseScope,
        expected_descriptor: Option<Digest>,
        expected_manifest: Option<Digest>,
    ) -> Result<(Vec<u8>, ModuleManifest)> {
        let trust = self.lock_trust(tx).await?;
        let bundle = self.verify_bundle(&trust.signed)?;
        let row = sqlx::query(
            "SELECT version,revoked,frame FROM package_releases WHERE app_id=$1 AND module_id=$2
             ORDER BY version DESC LIMIT 1",
        )
        .bind(app.as_slice())
        .bind(scope.module_id.as_slice())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(PackageError::Denied)?;
        if row.try_get::<bool, _>("revoked")?
            || row.try_get::<i64, _>("version")? != version(scope.version)?
        {
            return Err(PackageError::Denied);
        }
        let now = self.time(&trust)?;
        touch_time(tx, app, now).await?;
        let bytes: Vec<u8> = row.try_get("frame")?;
        let frame = PackageFrame::decode(&bytes)?;
        if expected_manifest
            .is_some_and(|digest| Sha256::digest(frame.manifest).as_slice() != digest)
            || expected_descriptor
                .is_some_and(|digest| Sha256::digest(frame.descriptor).as_slice() != digest)
        {
            return Err(PackageError::Denied);
        }
        let manifest = verify_frame(frame, app, scope, &bundle.active_key()?, now)?;
        let finished = self.time(&trust)?;
        if finished >= manifest.expires_at_ms {
            touch_time(tx, app, finished).await?;
            return Err(PackageError::Denied);
        }
        Ok((bytes, manifest))
    }

    pub(super) async fn provision_key(
        &self,
        keys: &ModuleKeyStore,
        scope: ReleaseScope,
        sealed: SealedRelease,
    ) -> Result<()> {
        if self.session.is_negotiated() {
            return Err(PackageError::Denied);
        }
        let mut tx = self.session.begin_package().await?;
        let (manifest, _) = self.validate_key(&mut tx, scope, &sealed).await?;
        tx.commit().await?;
        keys.insert_fixed(manifest, &sealed.key)
    }

    pub(crate) async fn validate_key(
        &self,
        tx: &mut Tx<'_>,
        scope: ReleaseScope,
        sealed: &SealedRelease,
    ) -> Result<(Digest, ModuleManifest)> {
        let app = self.session.package_app();
        let frame = PackageFrame {
            descriptor: sealed.package.descriptor_bytes(),
            manifest: sealed.package.manifest_bytes(),
            ciphertext: sealed.package.ciphertext(),
        };
        let encoded = frame.encode()?;
        let trust = self.lock_trust(tx).await?;
        let bundle = self.verify_bundle(&trust.signed)?;
        let row = sqlx::query(
            "SELECT version,revoked,frame FROM package_releases WHERE app_id=$1 AND module_id=$2
             ORDER BY version DESC LIMIT 1",
        )
        .bind(app.as_slice())
        .bind(scope.module_id.as_slice())
        .fetch_optional(&mut **tx)
        .await?
        .ok_or(PackageError::Denied)?;
        if row.try_get::<bool, _>("revoked")?
            || row.try_get::<i64, _>("version")? != version(scope.version)?
            || row.try_get::<&[u8], _>("frame")? != encoded
        {
            return Err(PackageError::Denied);
        }
        let manifest = verify_frame(frame, app, scope, &bundle.active_key()?, self.time(&trust)?)?;
        verify_key(frame, &manifest, &sealed.key)?;
        let manifest_hash = Sha256::digest(frame.manifest).into();
        Ok((manifest_hash, manifest))
    }

    pub(crate) async fn retired_generation_keys(
        &self,
        tx: &mut Tx<'_>,
        keys: &ModuleKeyStore,
        manifest: &ModuleManifest,
    ) -> Result<Vec<Vec<u8>>> {
        let app = self.session.package_app();
        let retired = if let Some((epoch, tick)) = self.session.generation_clock()? {
            let now = version(self.session.package_time()?)?;
            sqlx::query_scalar(
                "SELECT c.manifest_sha256 FROM generation_catalog c JOIN package_releases p
                   ON (p.app_id,p.module_id,p.version)=(c.app_id,c.module_id,c.module_version)
                 WHERE c.app_id=$1 AND c.manifest_sha256=ANY($2::bytea[])
                   AND (p.revoked OR c.release_expires_ms<=$3 OR c.signing_key_id<>$4
                     OR EXISTS (SELECT 1 FROM package_releases newer
                         WHERE newer.app_id=c.app_id AND newer.module_id=c.module_id
                           AND newer.version>c.module_version)
                     OR (c.allocated AND NOT EXISTS (SELECT 1 FROM generation_selections s
                         WHERE s.generation_id=c.generation_id AND s.service_epoch=$5
                           AND ((NOT s.consumed AND s.expires_tick_ms>$6)
                             OR EXISTS (SELECT 1 FROM sessions active WHERE active.id=s.session_id
                               AND active.service_epoch=$5 AND NOT active.stopped AND active.expires_tick_ms>$6)))))",
            ).bind(app.as_slice()).bind(keys.manifest_ids()?).bind(now).bind(manifest.signing_key_id.as_slice())
             .bind(epoch).bind(tick).fetch_all(&mut **tx).await?
        } else {
            Vec::new()
        };
        Ok(retired)
    }

    pub(super) async fn open_key(
        &self,
        keys: &ModuleKeyStore,
        request: ModuleOpen,
        proof: [u8; 64],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if request.fetch.purpose != ModulePurpose::Bytecode {
            return Err(PackageError::Denied);
        }
        let mut auth = self
            .session
            .authorize_package(&request.fetch, |key| request.verify(key, &proof))
            .await?;
        let opened = async {
            let (_, manifest_expiry) = self
                .issue(&mut auth.tx, request.fetch, Some(&request), auth.selected)
                .await?;
            let key = keys.lookup(&request.manifest_sha256)?;
            let digest = request.digest()?;
            Ok::<_, PackageError>((key, digest, manifest_expiry))
        }
        .await;
        match opened {
            Err(
                error @ (PackageError::Unavailable
                | PackageError::Session(SessionError::Unavailable)),
            ) => Err(error),
            Ok((key, digest, manifest_expiry)) => {
                auth.commit_live().await?;
                if self.session.package_time()? >= manifest_expiry {
                    return Err(PackageError::Denied);
                }
                Ok(encode_module_key(&digest, &request.manifest_sha256, &key))
            }
            Err(error) => {
                auth.tx.commit().await?;
                Err(error)
            }
        }
    }
}
