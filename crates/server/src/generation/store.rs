use rand::{rngs::OsRng, RngCore};
use sha2::{Digest as _, Sha256};
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use vmkek_packager::SealedRelease;
use vmkek_protocol::{
    GenerationChoice, GenerationOffer, GrantBinding, SessionGrant, SignedGenerationChoice,
    VmDescriptor, VmForm, ABI_VERSION, COPY_INPUT_CAPABILITY, GENERATION_COPY_INPUT,
    GENERATION_REGISTER, GENERATION_STACK, MAX_DEADLINE_MS, SCHEMA_VERSION,
};

use crate::{
    packages::{ModuleKeyStore, PackageError, ReleaseScope},
    session::SessionError,
};

const MAX_CATALOG: i64 = 64;
type Tx<'a> = Transaction<'a, Postgres>;
type Result<T> = std::result::Result<T, PackageError>;

#[derive(Clone)]
pub struct GenerationStore {
    pub(crate) keys: ModuleKeyStore,
}

impl GenerationStore {
    pub fn new(keys: ModuleKeyStore) -> Self {
        Self { keys }
    }

    /// Register and provision a live, prepublished release as one trusted handoff.
    pub async fn prepare(&self, scope: ReleaseScope, sealed: &SealedRelease) -> Result<()> {
        let packages = &self.keys.packages;
        let session = packages.session();
        let app = session.package_app();
        session.check_generation_scope(app, scope.build_id, scope.function_id)?;
        let mut tx = session.begin_package().await?;
        let (manifest, release) = packages.validate_key(&mut tx, scope, sealed).await?;
        let descriptor_bytes = sealed.package.descriptor_bytes();
        let descriptor = VmDescriptor::decode(descriptor_bytes)?;
        if descriptor.depth != 2
            || descriptor
                .capabilities
                .iter()
                .any(|cap| cap.id != COPY_INPUT_CAPABILITY)
        {
            return Err(PackageError::Denied);
        }
        if scope.generation_id == [0; 16] {
            return Err(PackageError::Denied);
        }
        let descriptor_hash = Sha256::digest(descriptor_bytes);
        let existing: Option<bool> = sqlx::query_scalar(
            "SELECT NOT allocated AND manifest_sha256=$2 FROM generation_catalog WHERE generation_id=$1",
        ).bind(scope.generation_id.as_slice()).bind(manifest.as_slice())
         .fetch_optional(&mut *tx).await?;
        if existing == Some(false) {
            return Err(PackageError::Conflict);
        }
        if existing.is_none() {
            let now = millis(session.package_time()?);
            let total: i64 = sqlx::query_scalar(
                "SELECT count(*) FROM generation_catalog c JOIN package_releases p
               ON (p.app_id,p.module_id,p.version)=(c.app_id,c.module_id,c.module_version)
             WHERE c.app_id=$1 AND NOT c.allocated AND NOT p.revoked
               AND c.release_expires_ms>$2 AND c.signing_key_id=$3
               AND NOT EXISTS (SELECT 1 FROM package_releases newer
                   WHERE newer.app_id=c.app_id AND newer.module_id=c.module_id
                     AND newer.version>c.module_version)",
            )
            .bind(app.as_slice())
            .bind(now)
            .bind(release.signing_key_id.as_slice())
            .fetch_one(&mut *tx)
            .await?;
            if total >= MAX_CATALOG {
                return Err(PackageError::Session(SessionError::Limit));
            }
            let capabilities = if descriptor.permits_copy_input() {
                GENERATION_COPY_INPUT
            } else {
                0
            };
            let row = sqlx::query(
            "INSERT INTO generation_catalog (generation_id,app_id,build_id,function_id,module_id,
             module_version,descriptor_sha256,manifest_sha256,signing_key_id,release_expires_ms,form,capabilities)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT DO NOTHING",
        )
        .bind(scope.generation_id.as_slice())
        .bind(app.as_slice())
        .bind(scope.build_id.as_slice())
        .bind(scope.function_id.as_slice())
        .bind(scope.module_id.as_slice())
        .bind(version(scope.version)?)
        .bind(descriptor_hash.as_slice())
        .bind(manifest.as_slice()).bind(release.signing_key_id.as_slice()).bind(millis(release.expires_at_ms))
        .bind(descriptor.form as i16)
        .bind(capabilities as i16)
        .execute(&mut *tx)
        .await?;
            if row.rows_affected() != 1 {
                return Err(PackageError::Conflict);
            }
        }
        let retired = packages
            .retired_generation_keys(&mut tx, &self.keys, &release)
            .await?;
        let pending = self.keys.stage_negotiated(manifest, &sealed.key, retired)?;
        tx.commit().await?;
        pending.commit()?;
        Ok(())
    }

    pub(crate) async fn select(
        &self,
        offer: GenerationOffer,
        proof: [u8; 64],
    ) -> Result<Option<SignedGenerationChoice>> {
        if (offer.descriptor_schema, offer.descriptor_abi) != (SCHEMA_VERSION, ABI_VERSION) {
            return Err(PackageError::Invalid);
        }
        let packages = &self.keys.packages;
        let mut auth = packages
            .session()
            .begin_generation(
                offer.app_id,
                offer.build_id,
                offer.function_id,
                offer.device_id,
                |key| offer.verify(key, &proof),
            )
            .await?;
        if !record_offer(&mut auth.tx, &offer).await? {
            auth.tx.commit().await?;
            return Err(PackageError::Conflict);
        }
        let epoch = auth.epoch();
        let tick = auth.tick()?;
        let pending: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM generation_selections WHERE device_id=$1
             AND service_epoch=$2 AND NOT consumed AND expires_tick_ms>$3)",
        )
        .bind(offer.device_id.as_slice())
        .bind(epoch)
        .bind(tick)
        .fetch_one(&mut *auth.tx)
        .await?;
        if pending {
            auth.tx.commit().await?;
            return Err(PackageError::Session(SessionError::Limit));
        }
        // Lock order matches trusted publication/revocation: service, license, trust, catalog.
        let trust: Option<i32> =
            sqlx::query_scalar("SELECT 1 FROM package_trust WHERE app_id=$1 FOR UPDATE")
                .bind(offer.app_id.as_slice())
                .fetch_optional(&mut *auth.tx)
                .await?;
        if trust.is_none() {
            auth.tx.commit().await?;
            return Ok(None);
        }
        let signer = packages.active_release_signer(&mut auth.tx).await?;
        let now = millis(packages.session().package_time()?);
        let rows = sqlx::query(
            "SELECT c.generation_id,c.module_id,c.module_version,c.descriptor_sha256,
                    c.manifest_sha256,c.form,c.capabilities
             FROM generation_catalog c JOIN package_releases p
               ON (p.app_id,p.module_id,p.version)=(c.app_id,c.module_id,c.module_version)
             WHERE c.app_id=$1 AND c.build_id=$2 AND c.function_id=$3 AND NOT c.allocated
               AND NOT p.revoked AND c.release_expires_ms>$4 AND c.signing_key_id=$5
               AND NOT EXISTS (SELECT 1 FROM package_releases newer
                   WHERE newer.app_id=c.app_id AND newer.module_id=c.module_id
                     AND newer.version>c.module_version)
             ORDER BY c.ordinal LIMIT $6",
        )
        .bind(offer.app_id.as_slice())
        .bind(offer.build_id.as_slice())
        .bind(offer.function_id.as_slice())
        .bind(now)
        .bind(signer.as_slice())
        .bind(MAX_CATALOG)
        .fetch_all(&mut *auth.tx)
        .await?;
        for row in rows {
            let form = form(&row)?;
            let mask = match form {
                VmForm::Stack => GENERATION_STACK,
                VmForm::Register => GENERATION_REGISTER,
            };
            let caps = u16::try_from(row.try_get::<i16, _>("capabilities")?)
                .map_err(|_| PackageError::Unavailable)?;
            if offer.forms & mask == 0 || caps & !offer.capabilities != 0 {
                continue;
            }
            let manifest_sha256 = field(&row, "manifest_sha256")?;
            if !self.keys.has_manifest(&manifest_sha256)? {
                continue;
            }
            let descriptor_sha256 = field(&row, "descriptor_sha256")?;
            let scope = ReleaseScope {
                build_id: offer.build_id,
                function_id: offer.function_id,
                generation_id: field(&row, "generation_id")?,
                module_id: field(&row, "module_id")?,
                version: row
                    .try_get::<i64, _>("module_version")?
                    .try_into()
                    .map_err(|_| PackageError::Unavailable)?,
            };
            let release_expiry = match packages
                .load_active_release(
                    &mut auth.tx,
                    offer.app_id,
                    scope,
                    Some(descriptor_sha256),
                    Some(manifest_sha256),
                )
                .await
            {
                Ok((_, manifest)) => manifest.expires_at_ms,
                Err(PackageError::Denied) => continue,
                Err(error) => return Err(error),
            };
            let choice = GenerationChoice {
                offer_digest: offer.digest()?,
                binding: GrantBinding {
                    app_id: offer.app_id,
                    build_id: offer.build_id,
                    device_id: offer.device_id,
                    license_id: auth.license_id,
                    session_id: random()?,
                    generation_id: scope.generation_id,
                },
                function_id: offer.function_id,
                descriptor_sha256,
                manifest_sha256,
                module_id: scope.module_id,
                module_version: scope.version,
                form,
                policy_epoch: auth.policy_epoch(),
                challenge_id: random()?,
                nonce: random()?,
                signing_key_id: auth.signer_id(),
            };
            let signed = auth.sign_choice(choice)?;
            let deadline = auth
                .tick()?
                .checked_add(i64::from(MAX_DEADLINE_MS))
                .ok_or(PackageError::Unavailable)?;
            sqlx::query("UPDATE generation_catalog SET allocated=true WHERE generation_id=$1")
                .bind(scope.generation_id.as_slice())
                .execute(&mut *auth.tx)
                .await?;
            sqlx::query(
                "INSERT INTO generation_selections (device_id,request_id,session_id,generation_id,
                 challenge_id,choice,service_epoch,expires_tick_ms) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
            ).bind(offer.device_id.as_slice()).bind(offer.request_id.as_slice())
             .bind(choice.binding.session_id.as_slice()).bind(scope.generation_id.as_slice())
             .bind(choice.challenge_id.as_slice()).bind(signed.as_bytes()).bind(epoch).bind(deadline)
             .execute(&mut *auth.tx).await?;
            auth.commit_before(deadline).await?;
            ensure_release_live(packages.session(), release_expiry)?;
            return Ok(Some(signed));
        }
        auth.tx.commit().await?;
        Ok(None)
    }

    pub(crate) async fn complete(
        &self,
        signed: SignedGenerationChoice,
        proof: [u8; 64],
    ) -> Result<SessionGrant> {
        let packages = &self.keys.packages;
        let session = packages.session();
        let choice = *session.verify_generation_choice(&signed)?;
        let binding = choice.binding;
        let mut auth = session
            .begin_generation(
                binding.app_id,
                binding.build_id,
                choice.function_id,
                binding.device_id,
                |key| signed.verify_completion(key, &proof),
            )
            .await?;
        if binding.license_id != auth.license_id {
            return Err(PackageError::Denied);
        }
        let row = sqlx::query(
            "SELECT choice,service_epoch,expires_tick_ms,consumed FROM generation_selections
             WHERE challenge_id=$1 AND device_id=$2 AND session_id=$3",
        )
        .bind(choice.challenge_id.as_slice())
        .bind(binding.device_id.as_slice())
        .bind(binding.session_id.as_slice())
        .fetch_optional(&mut *auth.tx)
        .await?
        .ok_or(PackageError::Denied)?;
        if row.try_get::<&[u8], _>("choice")? != signed.as_bytes()
            || row.try_get::<i64, _>("service_epoch")? != auth.epoch()
        {
            return Err(PackageError::Denied);
        }
        if row.try_get::<bool, _>("consumed")? {
            auth.tx.commit().await?;
            return Err(PackageError::Conflict);
        }
        let deadline = row.try_get("expires_tick_ms")?;
        sqlx::query("UPDATE generation_selections SET consumed=true WHERE challenge_id=$1")
            .bind(choice.challenge_id.as_slice())
            .execute(&mut *auth.tx)
            .await?;
        let result = async {
            if auth.tick()? >= deadline {
                return Err(PackageError::Session(SessionError::Expired));
            }
            if !self.keys.has_manifest(&choice.manifest_sha256)? {
                return Err(PackageError::Denied);
            }
            let (_, release) = packages
                .load_active_release(
                    &mut auth.tx,
                    binding.app_id,
                    ReleaseScope {
                        build_id: binding.build_id,
                        generation_id: binding.generation_id,
                        function_id: choice.function_id,
                        module_id: choice.module_id,
                        version: choice.module_version,
                    },
                    Some(choice.descriptor_sha256),
                    Some(choice.manifest_sha256),
                )
                .await?;
            let grant = auth.activate(&choice, signed.digest(), deadline).await?;
            Ok((grant, release.expires_at_ms))
        }
        .await;
        match result {
            Ok((grant, release_expiry)) => {
                auth.commit_before(deadline).await?;
                ensure_release_live(session, release_expiry)?;
                Ok(grant)
            }
            Err(
                error @ (PackageError::Unavailable
                | PackageError::Session(SessionError::Unavailable)),
            ) => Err(error),
            Err(error) => {
                auth.tx.commit().await?;
                Err(error)
            }
        }
    }
}

fn ensure_release_live(session: &crate::session::SessionStore, expires_at_ms: u64) -> Result<()> {
    if session.package_time()? >= expires_at_ms {
        return Err(PackageError::Session(SessionError::Expired));
    }
    Ok(())
}

async fn record_offer(tx: &mut Tx<'_>, offer: &GenerationOffer) -> Result<bool> {
    let duplicate: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM session_requests WHERE device_id=$1 AND request_id=$2
         UNION ALL SELECT 1 FROM package_fetch_requests WHERE device_id=$1 AND request_id=$2
         UNION ALL SELECT 1 FROM operation_requests WHERE device_id=$1 AND request_id=$2
             UNION ALL SELECT 1 FROM session_observation_reports WHERE device_id=$1 AND request_id=$2)",
    )
    .bind(offer.device_id.as_slice())
    .bind(offer.request_id.as_slice())
    .fetch_one(&mut **tx)
    .await?;
    if duplicate {
        return Ok(false);
    }
    let changed = sqlx::query(
        "INSERT INTO generation_offers (device_id,request_id,digest) VALUES ($1,$2,$3) ON CONFLICT DO NOTHING",
    ).bind(offer.device_id.as_slice()).bind(offer.request_id.as_slice()).bind(offer.digest()?.as_slice())
     .execute(&mut **tx).await?;
    Ok(changed.rows_affected() == 1)
}

fn field<const N: usize>(row: &PgRow, name: &str) -> Result<[u8; N]> {
    row.try_get::<&[u8], _>(name)?
        .try_into()
        .map_err(|_| PackageError::Unavailable)
}

fn form(row: &PgRow) -> Result<VmForm> {
    u8::try_from(row.try_get::<i16, _>("form")?)
        .map_err(|_| PackageError::Unavailable)?
        .try_into()
        .map_err(|_| PackageError::Unavailable)
}

fn millis(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn version(value: u64) -> Result<i64> {
    i64::try_from(value)
        .ok()
        .filter(|n| *n > 0)
        .ok_or(PackageError::Invalid)
}

fn random<const N: usize>() -> Result<[u8; N]> {
    let mut value = [0; N];
    OsRng
        .try_fill_bytes(&mut value)
        .map_err(|_| PackageError::Unavailable)?;
    Ok(value)
}
