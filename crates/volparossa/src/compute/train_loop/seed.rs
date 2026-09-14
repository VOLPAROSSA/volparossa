//! Optional independently selected public peer update as the loop's initial warmstart.

use super::{
    Deserialize, Options, Path, PathBuf, Result, Serialize, State, Store, Value, active, content,
    ensure, json, private_directory, read_file, watch,
};
use crate::content::agent_artifact::{self, ImportSelection};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Seed {
    publisher_key: String,
    dataset_publisher_key: String,
    name: String,
    dataset_name: String,
    #[serde(default)]
    min_revision: Option<u64>,
}
impl Seed {
    fn query(&self) -> Result<ImportSelection> {
        content::parse_content_name(&self.name).map_err(anyhow::Error::msg)?;
        content::parse_content_name(&self.dataset_name).map_err(anyhow::Error::msg)?;
        ensure!(self.min_revision != Some(0), "train_loop_seed_revision");
        Ok(ImportSelection {
            publisher_key: content::parse_publisher_key(&self.publisher_key)
                .map_err(anyhow::Error::msg)?,
            dataset_publisher_key: content::parse_publisher_key(&self.dataset_publisher_key)
                .map_err(anyhow::Error::msg)?,
            name: self.name.clone(),
            dataset_name: self.dataset_name.clone(),
            min_revision: self.min_revision,
        })
    }
}

pub(super) fn selection(args: &Options) -> Result<Option<Value>> {
    args.seed
        .as_ref()
        .map(|path| {
            let seed: Seed = serde_json::from_slice(&read_file(path, 64 * 1024)?)?;
            seed.query()?;
            Ok(serde_json::to_value(seed)?)
        })
        .transpose()
}

pub(super) async fn prepare(
    args: &Options,
    socket: &Path,
    enrollment: &Value,
    store: &Store,
    state: &mut State,
    activity: &watch::Receiver<bool>,
) -> Result<()> {
    let Some(selected) = enrollment.get("seed").filter(|value| !value.is_null()) else {
        ensure!(state.seed.is_none(), "train_loop_unrequested_seed");
        return Ok(());
    };
    let root = args.directory.join("seed-input");
    if let Some(expected) = &state.seed {
        ensure!(&snapshot(&root)? == expected, "train_loop_seed_changed");
        return Ok(());
    }
    ensure!(active(activity), "train_loop_seed_cancelled");
    // Imports publish their directory atomically. An uncheckpointed pre-existing
    // import is retained, not silently accepted as an authenticated saved receipt.
    ensure!(
        !root.try_exists()?,
        "train_loop_unconfirmed_seed_import_retained"
    );
    let seed: Seed = serde_json::from_value(selected.clone())?;
    let request = agent_artifact::Fetch::coordinator(
        seed.query()?,
        args.cache.clone(),
        true,
        root.clone(),
        args.limits.clone(),
    );
    let mut receiver = activity.clone();
    tokio::select! {biased;
        _=receiver.changed()=>anyhow::bail!("train_loop_seed_cancelled"),
        result=agent_artifact::fetch(&request,socket)=>{result?;}
    }
    state.seed = Some(snapshot(&root)?);
    store.save_state(&serde_json::to_value(state)?)
}

pub(super) fn adapter(args: &Options, state: &State) -> Result<Option<PathBuf>> {
    if let Some(expected) = &state.seed {
        let root = args.directory.join("seed-input");
        ensure!(&snapshot(&root)? == expected, "train_loop_seed_changed");
        Ok(Some(root.join("adapter")))
    } else {
        Ok(args.adapter_root.clone())
    }
}

fn snapshot(root: &Path) -> Result<Value> {
    private_directory(root)?;
    private_directory(&root.join("adapter"))?;
    let mut files = serde_json::Map::new();
    for (name, limit) in [
        ("provenance.json", 64 * 1024),
        ("dataset.json", 1024 * 1024),
        ("adapter/README.md", 16 * 1024),
        ("adapter/adapter_config.json", 16 * 1024),
        ("adapter/adapter_model.safetensors", 2 * 1024 * 1024),
    ] {
        let bytes = read_file(&root.join(name), limit)?;
        files.insert(
            name.into(),
            json!({"bytes":bytes.len(),"sha256":hex::encode(Sha256::digest(&bytes))}),
        );
    }
    Ok(Value::Object(files))
}
