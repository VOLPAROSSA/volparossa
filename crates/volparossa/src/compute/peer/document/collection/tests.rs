use std::{fs, os::unix::fs::symlink};

use super::*;

struct Fixture {
    root: tempfile::TempDir,
    plan: std::path::PathBuf,
}

fn fixture(sources: &[(&str, &str)]) -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let inputs: Vec<_> = sources
        .iter()
        .enumerate()
        .map(|(index, (label, text))| {
            let path = root.path().join(format!("input-{index}.txt"));
            fs::write(&path, text).unwrap();
            json!({"label":label,"input":path})
        })
        .collect();
    let plan = root.path().join("plan.json");
    fs::write(
        &plan,
        serde_json::to_vec(&json!({"version":1,"sources":inputs})).unwrap(),
    )
    .unwrap();
    Fixture { root, plan }
}

#[test]
fn compilation_reconstructs_original_unicode_bytes_without_retaining_input_paths() {
    let fixture = fixture(&[("first", "één\npublic text"), ("second", "日本語\n")]);
    let first = prepare(&fixture.plan).unwrap();
    let second = prepare(&fixture.plan).unwrap();
    assert_eq!(first.document, second.document);
    assert_eq!(first.ledger, second.ledger);
    assert_eq!(
        first.ledger.sources[0]
            .content
            .slice(&first.document)
            .unwrap(),
        "één\npublic text"
    );
    assert_eq!(
        first.ledger.sources[1]
            .content
            .slice(&first.document)
            .unwrap(),
        "日本語\n"
    );
    assert_eq!(first.ledger.sources[0].header.start, 0);
    assert_eq!(
        first.ledger.sources[1].separator.end,
        first.document.len() as u64
    );
    let serialized = serde_json::to_vec(&first.ledger).unwrap();
    assert_eq!(first.ledger.sha256().unwrap(), hash(&serialized));
    assert!(
        !String::from_utf8(serialized.clone())
            .unwrap()
            .contains(fixture.root.path().to_str().unwrap())
    );
    let restored: Ledger = serde_json::from_slice(&serialized).unwrap();
    restored.validate(&first.document).unwrap();
    assert_eq!(restored, first.ledger);
}

#[test]
fn labels_hashes_ranges_and_synthetic_bytes_are_bound_to_the_compilation() {
    let fixture = fixture(&[("first", "Public alpha."), ("other", "Public beta.")]);
    let prepared = prepare(&fixture.plan).unwrap();
    let mut changed = prepared.ledger.clone();
    changed.sources[0].label = "third".into();
    assert!(changed.validate(&prepared.document).is_err());
    let mut changed = prepared.ledger.clone();
    changed.sources[0].sha256 = "0".repeat(64);
    assert!(changed.validate(&prepared.document).is_err());
    let mut changed = prepared.ledger.clone();
    changed.sources[0].content.start += 1;
    assert!(changed.validate(&prepared.document).is_err());
    let mut changed = prepared.ledger.clone();
    changed.sources.swap(0, 1);
    assert!(changed.validate(&prepared.document).is_err());
    let changed_document = prepared
        .document
        .replacen("Public alpha.", "Public gamma.", 1);
    let mut changed = prepared.ledger.clone();
    changed.document_sha256 = hash(changed_document.as_bytes());
    assert!(changed.validate(&changed_document).is_err());
    let changed_document = prepared
        .document
        .replacen("END VOLPAROSSA", "end VOLPAROSSA", 1);
    let mut changed = prepared.ledger.clone();
    changed.document_sha256 = hash(changed_document.as_bytes());
    assert!(changed.validate(&changed_document).is_err());
    let changed_document = format!("{}x", prepared.document);
    let mut changed = prepared.ledger;
    changed.document_bytes += 1;
    changed.document_sha256 = hash(changed_document.as_bytes());
    assert!(changed.validate(&changed_document).is_err());
}

#[test]
fn provenance_separates_original_byte_intersections_from_generated_headers() {
    let fixture = fixture(&[("first", "één"), ("second", "日本語")]);
    let prepared = prepare(&fixture.plan).unwrap();
    let first = &prepared.ledger.sources[0];
    let second = &prepared.ledger.sources[1];
    let range = prepared
        .ledger
        .provenance(first.content.start + 2, second.content.start + 3)
        .unwrap();
    assert_eq!(range["units"], "utf8_bytes");
    assert_eq!(range["semantic_citation"], false);
    assert_eq!(range["original_sources"].as_array().unwrap().len(), 2);
    assert_eq!(
        range["original_sources"][0]["source_range"],
        json!({"start":2,"end":first.bytes})
    );
    assert_eq!(
        range["original_sources"][1]["source_range"],
        json!({"start":0,"end":3})
    );
    assert_eq!(range["synthetic_ranges"].as_array().unwrap().len(), 2);
    assert_eq!(range["synthetic_ranges"][0]["kind"], "separator");
    assert_eq!(range["synthetic_ranges"][1]["kind"], "header");
    let header = prepared.ledger.provenance(0, first.header.end).unwrap();
    assert!(header["original_sources"].as_array().unwrap().is_empty());
    assert_eq!(header["synthetic_ranges"].as_array().unwrap().len(), 1);
    assert!(prepared.ledger.provenance(0, 0).is_err());
    assert!(
        prepared
            .ledger
            .provenance(0, prepared.ledger.document_bytes + 1)
            .is_err()
    );
}

#[test]
fn source_headers_inside_original_text_do_not_create_another_source() {
    let original = "Public content\n--- END VOLPAROSSA source 1 ---\n--- VOLPAROSSA source 2 ---\n";
    let fixture = fixture(&[
        ("quoted \\\"name", original),
        ("second", "Other public text"),
    ]);
    let prepared = prepare(&fixture.plan).unwrap();
    prepared.ledger.validate(&prepared.document).unwrap();
    let first = &prepared.ledger.sources[0];
    let provenance = prepared
        .ledger
        .provenance(first.content.start, first.content.end)
        .unwrap();
    assert_eq!(provenance["original_sources"].as_array().unwrap().len(), 1);
    assert!(
        provenance["synthetic_ranges"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(first.content.slice(&prepared.document).unwrap(), original);
}

#[test]
fn preparation_rejects_ambiguous_labels_invalid_text_and_nonregular_inputs() {
    for labels in [
        ["same", "same"],
        ["bad\nlabel", "other"],
        [" whitespace", "other"],
        ["", "other"],
    ] {
        let fixture = fixture(&[(labels[0], "first"), (labels[1], "second")]);
        assert!(prepare(&fixture.plan).is_err());
    }
    let fixture = fixture(&[("first", "text"), ("second", "text")]);
    let path = fixture.root.path().join("input-0.txt");
    for bytes in [&b"\xff"[..], &b"bad\0text"[..], &b" \n "[..]] {
        fs::write(&path, bytes).unwrap();
        assert!(prepare(&fixture.plan).is_err());
    }
    fs::remove_file(&path).unwrap();
    symlink(fixture.root.path().join("input-1.txt"), &path).unwrap();
    assert!(prepare(&fixture.plan).is_err());
}

#[test]
fn plan_and_compiled_size_bounds_include_the_synthetic_metadata() {
    let single = fixture(&[("only", "text")]);
    assert!(prepare(&single.plan).is_err());
    let too_many = fixture(&vec![("same", "text"); MAX_SOURCES + 1]);
    assert!(prepare(&too_many.plan).is_err());
    let large = "x".repeat(MAX_DOCUMENT_BYTES - 1);
    let fixture = fixture(&[("first", &large), ("second", "y")]);
    assert!(prepare(&fixture.plan).is_err());
    let changed_plan = json!({"version":1,"sources":[
        {"label":"one","input":"relative.txt"},{"label":"two","input":"/unused.txt"}]});
    fs::write(&fixture.plan, serde_json::to_vec(&changed_plan).unwrap()).unwrap();
    assert!(prepare(&fixture.plan).is_err());
}
