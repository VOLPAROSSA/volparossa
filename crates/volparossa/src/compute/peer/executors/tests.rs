//! Local record checks only, never worker/model/network execution.
use super::*;
use std::os::unix::fs::PermissionsExt;

#[test]
fn replacement_permission_is_exact_durable_and_not_a_new_source_lease() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let at = now().unwrap();
    let publisher = ed25519_dalek::SigningKey::from_bytes(&[51; 32]).verifying_key();
    let authorization = Authorization {
        workflow_sha256: "1".repeat(64),
        publisher_key: hex::encode(publisher.as_bytes()),
        dataset_manifest_id: "2".repeat(64),
        dataset_sha256: "3".repeat(64),
        model_fingerprint: "4".repeat(64),
        task: None,
        document: false,
        derived: false,
        enrolled_at: at - 1,
        source_expires: at + 600,
    };
    let selected = discovery::Selected {
        providers: vec![ed25519_dalek::SigningKey::from_bytes(&[52; 32]).verifying_key()],
        model_fingerprint: authorization.model_fingerprint.clone(),
    };
    assert!(load(root.path(), None).unwrap().is_none());
    admit(root.path(), &authorization, &selected).unwrap();
    let original = fs::read(root.path().join(FILE)).unwrap();
    assert_eq!(
        load(root.path(), Some(&authorization))
            .unwrap()
            .unwrap()
            .provider_keys
            .len(),
        1
    );
    assert!(load(root.path(), None).is_err());
    assert!(admit(root.path(), &authorization, &selected).is_err());
    for changed in [
        Authorization {
            model_fingerprint: "5".repeat(64),
            ..authorization.clone()
        },
        Authorization {
            workflow_sha256: "6".repeat(64),
            ..authorization.clone()
        },
        Authorization {
            source_expires: at + 1200,
            ..authorization.clone()
        },
    ] {
        assert!(load(root.path(), Some(&changed)).is_err());
    }
    assert_eq!(fs::read(root.path().join(FILE)).unwrap(), original);
}
