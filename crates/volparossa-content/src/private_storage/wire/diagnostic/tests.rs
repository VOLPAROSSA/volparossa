use super::*;

#[test]
fn tuple_codes_are_static_bounded_and_preserve_whole_tuple_identity() {
    let operations = [
        None,
        Some(Operation::Reserve),
        Some(Operation::Append),
        Some(Operation::Progress),
        Some(Operation::Finalize),
        Some(Operation::ReadRange),
        Some(Operation::Renew),
        Some(Operation::Delete),
    ];
    let phases = [
        Phase::Grant,
        Phase::Challenge,
        Phase::Request,
        Phase::Payload,
        Phase::DiskAdmission,
        Phase::Backend,
        Phase::Receipt,
        Phase::ResponsePayload,
    ];
    let categories = [
        Category::Io,
        Category::Auth,
        Category::Invalid,
        Category::Busy,
        Category::Store,
        Category::Timeout,
        Category::Database,
        Category::Integrity,
        Category::Expired,
        Category::Ownership,
        Category::Conflict,
        Category::Deleted,
        Category::Quota,
        Category::NotFound,
        Category::NotCommitted,
        Category::Entropy,
    ];
    let mut codes = std::collections::BTreeSet::new();
    for operation in operations {
        for phase in phases {
            for category in categories {
                let code: &'static str = Failure {
                    operation,
                    phase,
                    category,
                    payload_io: None,
                }
                .event_code();
                assert!(
                    code.len() <= 96
                        && code
                            .bytes()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == b'_')
                );
                assert_eq!(code.split("__").count(), 3);
                assert!(codes.insert(code));
            }
        }
    }
    assert_eq!(
        codes.len(),
        operations.len() * phases.len() * categories.len()
    );
}

#[test]
fn caller_owned_timeout_uses_active_phase_without_inventing_commit_outcome() {
    let mut observation = Observation::default();
    assert!(observation.failure(true).is_none());
    observation.begin();
    assert_eq!(
        observation.failure(true).unwrap().event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_UNKNOWN__GRANT__TIMEOUT"
    );
    observation.verified(StorageOperation::Finalize);
    observation.phase = Phase::Backend;
    assert_eq!(
        observation.failure(true).unwrap().event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_FINALIZE__BACKEND__TIMEOUT"
    );
    // A successful apply moves to Receipt before any subsequent authorization/write work.
    observation.phase = Phase::Receipt;
    observation.finish(&Err(WireError::Protocol(ProtocolError::Expired)));
    assert_eq!(
        observation.failure(false).unwrap().event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_FINALIZE__RECEIPT__EXPIRED"
    );
    observation.begin();
    observation.finish(&Ok(()));
    assert!(observation.failure(false).is_none());
    assert!(observation.failure(true).is_none());
}

#[test]
fn nested_error_payloads_never_enter_closed_backend_categories() {
    let secret = "/private/database/owner-key-and-ciphertext";
    let cases = [
        (
            ProviderError::Storage(StorageError::Io(std::io::Error::other(secret))),
            Category::Io,
        ),
        (
            ProviderError::Storage(StorageError::Database(
                rusqlite::Error::InvalidParameterName(secret.into()),
            )),
            Category::Database,
        ),
        (
            ProviderError::Storage(StorageError::Integrity),
            Category::Integrity,
        ),
        (
            ProviderError::Storage(StorageError::Expired),
            Category::Expired,
        ),
        (ProviderError::Unauthorized, Category::Ownership),
    ];
    for (error, expected) in cases {
        assert_eq!(Category::backend(&error), expected);
        let diagnostic = Failure {
            operation: Some(Operation::Finalize),
            phase: Phase::Backend,
            category: Category::backend(&error),
            payload_io: None,
        };
        assert!(!diagnostic.event_code().contains(secret));
        assert!(!format!("{diagnostic:?}").contains(secret));
    }
}

#[test]
fn append_payload_io_codes_are_closed_and_do_not_change_the_v1_tuple() {
    let cases = [
        (std::io::ErrorKind::UnexpectedEof, "UNEXPECTED_EOF"),
        (std::io::ErrorKind::TimedOut, "TIMED_OUT"),
        (std::io::ErrorKind::ConnectionReset, "CONNECTION_RESET"),
        (std::io::ErrorKind::BrokenPipe, "BROKEN_PIPE"),
        (std::io::ErrorKind::InvalidData, "INVALID_DATA"),
        (std::io::ErrorKind::Interrupted, "INTERRUPTED"),
        (std::io::ErrorKind::Other, "OTHER"),
        (std::io::ErrorKind::PermissionDenied, "OTHER"),
    ];
    let mut codes = std::collections::BTreeSet::new();
    for boundary in [PayloadBoundary::Header, PayloadBoundary::Body] {
        for (kind, label) in cases {
            let mut observation = Observation::default();
            observation.begin();
            observation.verified(StorageOperation::Append {
                offset: 0,
                length: 1,
                sha256: [0; 32],
            });
            observation.payload_read_error(boundary, kind);
            observation.finish(&Err(WireError::Io(std::io::Error::new(
                kind,
                "/private/provider/io-canary",
            ))));
            let failure = observation.failure(false).unwrap();
            assert_eq!(
                failure.event_code(),
                "CONTENT_PROVIDER_STORAGE_V1_APPEND__PAYLOAD__IO"
            );
            let code = failure.payload_io_event_code().unwrap();
            let stage = match boundary {
                PayloadBoundary::Header => "PAYLOAD_HEADER",
                PayloadBoundary::Body => "PAYLOAD_BODY",
            };
            assert_eq!(
                code,
                format!("CONTENT_PROVIDER_STORAGE_V2_APPEND__{stage}__{label}")
            );
            assert!(code.len() <= 96);
            assert!(!format!("{failure:?}").contains("canary"));
            codes.insert(code);
        }
    }
    assert_eq!(codes.len(), 14);
}

#[test]
fn payload_io_never_labels_unverified_other_phase_or_timeout_as_an_append_read_error() {
    let payload = Some(PayloadIo {
        boundary: PayloadBoundary::Body,
        kind: PayloadIoKind::UnexpectedEof,
    });
    for (operation, phase, category) in [
        (None, Phase::Request, Category::Io),
        (Some(Operation::Finalize), Phase::Payload, Category::Io),
        (Some(Operation::Append), Phase::Receipt, Category::Io),
        (Some(Operation::Append), Phase::Payload, Category::Timeout),
        (Some(Operation::Append), Phase::Payload, Category::Invalid),
    ] {
        assert!(
            Failure {
                operation,
                phase,
                category,
                payload_io: payload,
            }
            .payload_io_event_code()
            .is_none()
        );
    }
    let mut observation = Observation::default();
    observation.begin();
    observation.payload_read_error(PayloadBoundary::Header, std::io::ErrorKind::UnexpectedEof);
    observation.finish(&Err(WireError::Io(std::io::Error::other("private"))));
    assert!(
        observation
            .failure(false)
            .unwrap()
            .payload_io_event_code()
            .is_none()
    );
    observation.begin();
    observation.verified(StorageOperation::Append {
        offset: 0,
        length: 1,
        sha256: [0; 32],
    });
    assert!(
        observation
            .failure(true)
            .unwrap()
            .payload_io_event_code()
            .is_none()
    );
    observation.payload_read_error(PayloadBoundary::Body, std::io::ErrorKind::UnexpectedEof);
    observation.finish(&Ok(()));
    assert!(observation.failure(false).is_none());
    observation.begin();
    observation.verified(StorageOperation::Append {
        offset: 0,
        length: 1,
        sha256: [0; 32],
    });
    observation.finish(&Err(WireError::Io(std::io::Error::other("private"))));
    assert!(
        observation
            .failure(false)
            .unwrap()
            .payload_io_event_code()
            .is_none()
    );
}
