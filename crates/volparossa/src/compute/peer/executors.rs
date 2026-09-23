//! Owner-enrolled replacement permission and immutable per-attempt executor admissions.
//! These local records attest neither model quality nor independently portable execution.

use std::collections::BTreeSet;

use volparossa_content::provider::compute::dataset::VerifiedPublicDataset;

use super::*;

const FILE: &str = "executor-admission.json";
const MAX_BYTES: usize = 16 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Authorization {
    pub(super) workflow_sha256: String,
    pub(super) publisher_key: String,
    pub(super) dataset_manifest_id: String,
    pub(super) dataset_sha256: String,
    pub(super) model_fingerprint: String,
    pub(super) task: Option<rpc::PublicTask>,
    pub(super) document: bool,
    pub(super) derived: bool,
    pub(super) enrolled_at: u64,
    pub(super) source_expires: u64,
}

impl Authorization {
    fn query(&self) -> Result<rpc::EligibilityQuery> {
        ensure!(
            [
                &self.workflow_sha256,
                &self.dataset_manifest_id,
                &self.dataset_sha256,
                &self.model_fingerprint
            ]
            .iter()
            .all(|value| rpc::nonzero_hex(value, 64))
                && self.enrolled_at > 0
                && self.enrolled_at < self.source_expires
                && self
                    .task
                    .as_ref()
                    .is_none_or(|task| task.question().is_ok()),
            "compute_executor_authorization"
        );
        let query = rpc::EligibilityQuery {
            model_profile: None, // The already-enrolled full fingerprint is stricter.
            publisher_keys: vec![self.publisher_key.clone()],
            model_fingerprint: Some(self.model_fingerprint.clone()),
            require_task_derivation_v1: self.task.is_some(),
            require_document_inference_v2: self.document,
            require_derived_inference_v3: self.derived,
            require_principle_inference_v4: false,
        };
        query.validate()?;
        Ok(query)
    }

    pub(super) fn validate_handle(
        &self,
        source: &VerifiedPublicDataset,
        original: &JobHandle,
    ) -> Result<()> {
        self.query()?;
        ensure!(
            self.dataset_manifest_id == hex::encode(source.manifest_id())
                && self.source_expires == source.expires()
                && self.document == source.is_document()
                && self.derived == source.is_derived()
                && original.binding.dataset_manifest_id == self.dataset_manifest_id
                && original.binding.model_fingerprint == self.model_fingerprint
                && original.binding.task == self.task,
            "compute_executor_original_binding"
        );
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Admission {
    version: u32,
    authorization: Authorization,
    observed_at: u64,
    pub(super) provider_keys: Vec<String>,
}

impl Admission {
    fn validate(&self, authorization: &Authorization) -> Result<()> {
        authorization.query()?;
        ensure!(
            self.version == 1
                && &self.authorization == authorization
                && self.observed_at >= authorization.enrolled_at
                && self.observed_at < authorization.source_expires
                && self.observed_at <= now()?
                && (1..=4).contains(&self.provider_keys.len()),
            "compute_executor_admission_binding"
        );
        let mut unique = BTreeSet::new();
        for key in &self.provider_keys {
            parse_key(key).map_err(anyhow::Error::msg)?;
            ensure!(unique.insert(key), "compute_executor_duplicate_provider");
        }
        Ok(())
    }
}

pub(super) async fn discover(
    authorization: &Authorization,
    socket: &Path,
    activity: &tokio::sync::watch::Receiver<bool>,
) -> Result<discovery::Selected> {
    ensure!(
        now()? < authorization.source_expires,
        "compute_peer_source_expired"
    );
    let found = discovery::select_replacements(socket, authorization.query()?, activity).await?;
    ensure!(!*activity.borrow(), "compute_executor_discovery_cancelled");
    ensure!(
        now()? < authorization.source_expires,
        "compute_peer_source_expired"
    );
    Ok(found)
}

/// Called after creating the fresh attempt directory, before saving any new handle/Submit.
pub(super) fn admit(
    output: &Path,
    authorization: &Authorization,
    selected: &discovery::Selected,
) -> Result<()> {
    ensure!(
        selected.model_fingerprint == authorization.model_fingerprint,
        "compute_executor_model_changed"
    );
    let admission = Admission {
        version: 1,
        authorization: authorization.clone(),
        observed_at: now()?,
        provider_keys: selected
            .providers
            .iter()
            .map(|key| hex::encode(key.as_bytes()))
            .collect(),
    };
    admission.validate(authorization)?;
    save_new(&output.join(FILE), &admission)
}

/// Historical admissions survive source expiry; they never extend permission for new work.
pub(super) fn load(
    output: &Path,
    authorization: Option<&Authorization>,
) -> Result<Option<Admission>> {
    let path = output.join(FILE);
    if !path.try_exists()? {
        return Ok(None);
    }
    let authorization = authorization.context("compute_executor_unrequested_admission")?;
    let admission: Admission = serde_json::from_slice(&read_file(&path, MAX_BYTES)?)?;
    admission.validate(authorization)?;
    Ok(Some(admission))
}

#[cfg(test)]
mod tests;
