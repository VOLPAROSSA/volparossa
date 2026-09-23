//! Fixed-field binary-as-hex package: no archive paths, arbitrary files or executable artifacts.

use super::super::super::{JobHandle, transcript};
use super::*;

const STAGES: [&str; 4] = ["assessment-0", "assessment-1", "review-0", "review-1"];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Bundle {
    version: u32,
    pub(super) requester_key: String,
    enrollment: String,
    subject: String,
    subject_manifest: String,
    source_receipt: String,
    result: String,
    stages: [Stage; 4],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Stage {
    context: String,
    context_manifest: String,
    dataset: String,
    dataset_manifest: String,
    handle: String,
    receipt: String,
    provider_transcript: String,
}

pub(super) fn decode(bytes: &[u8]) -> Result<Bundle> {
    ensure!(
        !bytes.is_empty() && bytes.len() as u64 <= policy_bundle::MAX_BYTES,
        "compute_policy_bundle_bound"
    );
    let bundle: Bundle = serde_json::from_slice(bytes)?;
    ensure!(bundle.version == 1, "compute_policy_bundle_version");
    parse_key(&bundle.requester_key).map_err(anyhow::Error::msg)?;
    Ok(bundle)
}

fn read(root: &Path, name: &str, maximum: u64) -> Result<String> {
    Ok(hex::encode(storage::read(&root.join(name), maximum)?))
}

pub(super) fn collect(root: &Path, requester: &str) -> Result<Bundle> {
    let mut stages = Vec::new();
    for name in STAGES {
        let path = root.join(name);
        let handle_bytes = storage::read(&path.join("work/job-0.json"), 32 * 1024)?;
        let handle: JobHandle = serde_json::from_slice(&handle_bytes)?;
        ensure!(
            rpc::nonzero_hex(&handle.binding.job_id, 32),
            "compute_policy_bundle_job_id"
        );
        let receipt_name = format!("receipt-{}.json", handle.binding.job_id);
        let mut receipt = None;
        for directory in std::iter::once(path.join("work"))
            .chain((0..32).map(|index| path.join(format!("poll-{index:02}"))))
        {
            if storage::exists(&directory.join(&receipt_name))? {
                receipt = Some(read(&directory, &receipt_name, 128 * 1024)?);
            }
        }
        stages.push(Stage {
            context: read(&path, "context.txt", 4096)?,
            context_manifest: read(&path, "context.manifest", 64 * 1024)?,
            dataset: read(&path, "dataset.json", 64 * 1024)?,
            dataset_manifest: read(&path, "dataset.manifest", 64 * 1024)?,
            handle: hex::encode(handle_bytes),
            receipt: receipt.context("compute_policy_bundle_receipt_missing")?,
            provider_transcript: read(&path, "provider-transcript.json", 256 * 1024)?,
        });
    }
    Ok(Bundle {
        version: 1,
        requester_key: requester.into(),
        enrollment: read(root, "enrollment.json", 16 * 1024)?,
        subject: read(root, "subject.txt", 512)?,
        subject_manifest: read(root, "subject.manifest", 64 * 1024)?,
        source_receipt: read(root, "subject-download.json", 64 * 1024)?,
        result: read(root, "result.json", 256 * 1024)?,
        stages: stages
            .try_into()
            .map_err(|_| anyhow::anyhow!("compute_policy_bundle_stages"))?,
    })
}

fn bytes(encoded: &str, maximum: usize) -> Result<Vec<u8>> {
    ensure!(
        !encoded.is_empty() && encoded.len() <= maximum * 2,
        "compute_policy_bundle_field_bound"
    );
    Ok(hex::decode(encoded)?)
}

fn put(root: &Path, name: &str, encoded: &str, maximum: usize) -> Result<()> {
    task::write_bytes(&root.join(name), &bytes(encoded, maximum)?, false)
}

impl Bundle {
    /// Caller supplies a fresh owned temporary directory. All names are fixed in this function.
    pub(super) fn materialize(&self, root: &Path) -> Result<()> {
        ensure!(self.version == 1, "compute_policy_bundle_version");
        crate::compute::private_directory(root)?;
        parse_key(&self.requester_key).map_err(anyhow::Error::msg)?;
        put(root, "enrollment.json", &self.enrollment, 16 * 1024)?;
        put(root, "subject.txt", &self.subject, 512)?;
        put(root, "subject.manifest", &self.subject_manifest, 64 * 1024)?;
        put(
            root,
            "subject-download.json",
            &self.source_receipt,
            64 * 1024,
        )?;
        put(root, "result.json", &self.result, 256 * 1024)?;
        for (name, stage) in STAGES.into_iter().zip(&self.stages) {
            let path = root.join(name);
            storage::directory(&path)?;
            storage::directory(&path.join("work"))?;
            let handle: JobHandle = serde_json::from_slice(&bytes(&stage.handle, 32 * 1024)?)?;
            ensure!(
                rpc::nonzero_hex(&handle.binding.job_id, 32),
                "compute_policy_bundle_job_id"
            );
            let proof: transcript::Retained =
                serde_json::from_slice(&bytes(&stage.provider_transcript, 256 * 1024)?)?;
            ensure!(
                proof.requester_key == self.requester_key,
                "compute_policy_bundle_requester"
            );
            put(&path, "context.txt", &stage.context, 4096)?;
            put(
                &path,
                "context.manifest",
                &stage.context_manifest,
                64 * 1024,
            )?;
            put(&path, "dataset.json", &stage.dataset, 64 * 1024)?;
            put(
                &path,
                "dataset.manifest",
                &stage.dataset_manifest,
                64 * 1024,
            )?;
            put(&path, "work/job-0.json", &stage.handle, 32 * 1024)?;
            put(
                &path,
                &format!("work/receipt-{}.json", handle.binding.job_id),
                &stage.receipt,
                128 * 1024,
            )?;
            put(
                &path,
                "provider-transcript.json",
                &stage.provider_transcript,
                256 * 1024,
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_rejects_untyped_archives_incomplete_sets_and_excessive_bytes() {
        for value in [
            json!({"version":1,"files":{"../../escape":"00"}}),
            json!({"version":1,"stages":[]}),
            json!({"version":2}),
        ] {
            assert!(decode(&serde_json::to_vec(&value).unwrap()).is_err());
        }
        assert!(decode(&[]).is_err());
        assert!(
            decode(&vec![
                b' ';
                usize::try_from(policy_bundle::MAX_BYTES).unwrap() + 1
            ])
            .is_err()
        );
        assert!(bytes(&"00".repeat(513), 512).is_err());
        assert!(bytes("not hex", 512).is_err());
    }
}
