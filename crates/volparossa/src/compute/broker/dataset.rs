//! Cheap strict public-data admission before starting the real fixed worker.

use anyhow::{Result, ensure};
use serde::Deserialize;

use super::super::is_hex;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Dataset {
    version: u32,
    visibility: String,
    license: String,
    source_revision: String,
    train: Vec<Answered>,
    heldout: Vec<Answered>,
    inference: Vec<Question>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Answered {
    question: String,
    context: String,
    answer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Question {
    question: String,
    context: String,
}

pub(super) fn validate(json: &str, rows: usize) -> Result<()> {
    let header: serde_json::Value = serde_json::from_str(json)?;
    if header["version"] == 2 {
        volparossa_content::provider::compute::dataset::validate_document_json(json, rows)?;
        return Ok(());
    }
    let dataset: Dataset = serde_json::from_str(json)?;
    ensure!(
        dataset.version == 1
            && dataset.visibility == "public"
            && dataset.license == "GPL-3.0-only"
            && is_hex(&dataset.source_revision, 40),
        "compute_broker_public_dataset"
    );
    ensure!(
        dataset.train.len() <= 32
            && (1..=8).contains(&dataset.heldout.len())
            && (1..=4).contains(&rows)
            && dataset.inference.len() == rows,
        "compute_broker_dataset_rows"
    );
    for row in dataset.train.iter().chain(&dataset.heldout) {
        text(&row.question, 512)?;
        text(&row.context, 4096)?;
        text(&row.answer, 1024)?;
    }
    for row in &dataset.inference {
        text(&row.question, 512)?;
        text(&row.context, 4096)?;
    }
    Ok(())
}

fn text(value: &str, maximum: usize) -> Result<()> {
    ensure!(
        !value.is_empty() && value.len() <= maximum && !value.contains('\0'),
        "compute_broker_dataset_text"
    );
    Ok(())
}
