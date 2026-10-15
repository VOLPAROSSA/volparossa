use std::{io, path::PathBuf};

use volparossa_routing::HelperProtocolError;
use volparossa_wireguard::WireGuardError;

use super::*;
use crate::helper::HelperClient;
use crate::mptcp_flow_runtime::client_refill::ClientRefillObservations;
use crate::mptcp_transport::{ClientMptcpTransport, retirement::Retirements};

const CANARY: &str = "private-path-peer-address-error-canary";

#[test]
fn flow_acquire_helper_reasons_are_typed_and_erase_private_error_content() {
    let errors = [
        (
            HelperClientError::Io(io::Error::other(CANARY)),
            Reason::HelperIo,
        ),
        (HelperClientError::UnsafeToken, Reason::HelperAuthority),
        (HelperClientError::UntrustedServer, Reason::HelperAuthority),
        (
            HelperClientError::Protocol(HelperProtocolError::Invalid(CANARY)),
            Reason::HelperValidation,
        ),
        (
            HelperClientError::DescriptorHandoff(io::Error::other(CANARY)),
            Reason::HelperValidation,
        ),
        (
            HelperClientError::DescriptorValidation(io::Error::other(CANARY)),
            Reason::HelperValidation,
        ),
        (
            HelperClientError::CapabilityAlreadyUsed,
            Reason::HelperValidation,
        ),
        (HelperClientError::Timeout, Reason::HelperTimeout),
        (HelperClientError::Correlation, Reason::HelperCorrelation),
        (
            HelperClientError::RuntimeChanged,
            Reason::HelperRuntimeChanged,
        ),
    ];
    for (error, expected) in errors {
        let actual = Reason::helper(&error);
        assert_eq!(actual, expected);
        assert!(!format!("{actual:?}").contains(CANARY));
    }
    for (result, expected) in [
        (HelperResult::Kernel, Reason::HelperKernel),
        (HelperResult::Capacity, Reason::HelperCapacity),
        (HelperResult::Unavailable, Reason::HelperUnavailable),
        (HelperResult::NotFound, Reason::HelperNotFound),
        (
            HelperResult::CleanupIncomplete,
            Reason::HelperCleanupIncomplete,
        ),
        (HelperResult::Unspecified, Reason::HelperOtherRejection),
        (HelperResult::Ok, Reason::HelperOtherRejection),
        (HelperResult::InvalidRequest, Reason::HelperOtherRejection),
        (HelperResult::UnauthorisedPeer, Reason::HelperOtherRejection),
        (HelperResult::AlreadyExists, Reason::HelperOtherRejection),
        (HelperResult::Expired, Reason::HelperOtherRejection),
    ] {
        assert_eq!(
            Reason::helper(&HelperClientError::Rejected(result)),
            expected
        );
    }
}

#[test]
fn flow_acquire_transport_observer_returns_original_error_without_capacity_inference() {
    for (error, expected) in [
        (MptcpTransportError::AcquireUnconfirmed, Reason::Unconfirmed),
        (MptcpTransportError::InvalidMetadata, Reason::Metadata),
        (MptcpTransportError::InsufficientPaths, Reason::Metadata),
        (
            MptcpTransportError::Topology(WireGuardError::InvalidTopology),
            Reason::Topology,
        ),
        (
            MptcpTransportError::Helper(HelperClientError::Timeout),
            Reason::HelperTimeout,
        ),
    ] {
        let original = format!("{error:?}");
        let mut observation = Observation::default();
        let returned = observation.transport_error(Stage::DescriptorAdoption, error);
        assert_eq!(format!("{returned:?}"), original);
        assert_eq!(observation.failure().unwrap().reason, expected);
    }
    let mut observation = Observation::default();
    let error = io::Error::other(CANARY);
    let original = error.get_ref().unwrap() as *const _;
    let returned = observation.transport_error(Stage::RetirementDrain, error.into());
    let MptcpTransportError::Io(returned) = returned else {
        panic!("original I/O variant must survive");
    };
    assert!(std::ptr::eq(returned.get_ref().unwrap(), original));
    assert_eq!(returned.kind(), io::ErrorKind::Other);
    assert_eq!(returned.to_string(), CANARY);
    assert_eq!(observation.failure().unwrap().reason, Reason::Io);
    assert!(!format!("{:?}", observation.failure()).contains(CANARY));
}

#[test]
fn flow_acquire_observation_freezes_first_failure_and_reset_discards_it() {
    let mut observation = Observation::default();
    observation.record(Stage::HelperAcquire, Reason::HelperTimeout);
    observation.record(Stage::DescriptorClone, Reason::Io);
    assert_eq!(
        observation.failure(),
        Some(Failure {
            stage: Stage::HelperAcquire,
            reason: Reason::HelperTimeout,
        }),
    );
    observation.reset();
    assert_eq!(observation.failure(), None);
    assert_eq!(observation.required(Stage::Material, Some(7)).unwrap(), 7);
    assert_eq!(observation.failure(), None);
    assert!(matches!(
        observation.required::<()>(Stage::Material, None),
        Err(MptcpTransportError::InvalidMetadata),
    ));
    assert_eq!(observation.failure().unwrap().reason, Reason::Metadata);
}

#[test]
fn flow_acquire_history_keeps_order_and_exact_one_to_eight_rounds() {
    let first = Failure {
        stage: Stage::HelperAcquire,
        reason: Reason::HelperKernel,
    };
    let last = Failure {
        stage: Stage::SlotReservation,
        reason: Reason::LocalCapacity,
    };
    let mut history = History::default();
    assert_eq!(history.summary(), None);
    history.record_round(Some(first));
    assert_eq!(
        history.summary(),
        Some(Summary {
            rounds: 1,
            first,
            last: first,
        }),
    );
    for rounds in 2..=8 {
        history.record_round(Some(last));
        assert_eq!(
            history.summary(),
            Some(Summary {
                rounds,
                first,
                last,
            }),
        );
    }
    let mut independent = History::default();
    independent.record_round(Some(last));
    assert_eq!(independent.summary().unwrap().first, last);
    assert_eq!(history.summary().unwrap().first, first);
}

#[test]
fn flow_acquire_history_omits_missing_or_out_of_bound_observations() {
    let failure = Failure {
        stage: Stage::SourcePort,
        reason: Reason::Entropy,
    };
    for missing_round in 0..8 {
        let mut history = History::default();
        for round in 0..8 {
            history.record_round((round != missing_round).then_some(failure));
        }
        assert_eq!(history.summary(), None);
    }
    let mut history = History::default();
    for _ in 0..9 {
        history.record_round(Some(failure));
    }
    assert_eq!(history.summary(), None);
}

fn unadopted_transport() -> ClientMptcpTransport {
    // This fixture exercises only local pre-handoff failures, never an MPTCP datapath.
    ClientMptcpTransport {
        initial_stream: None,
        initial_retirement: None,
        initial_flow_handle: Vec::new(),
        retirements: Retirements::new(),
        signal: None,
        route_context_id: vec![1; 16],
        context_handle: vec![2; 32],
        required_subflows: 2,
        active_paths: Vec::new(),
        certificate_der: Some(vec![1]),
        refill_observations: Some(ClientRefillObservations::new(
            [1; 16],
            44_443,
            &[1, 2],
            &[1, 2],
        )),
    }
}

#[tokio::test]
async fn flow_acquire_real_local_branches_preserve_metadata_capacity_and_poison_errors() {
    let helper = HelperClient::new(PathBuf::from(CANARY), PathBuf::from(CANARY));
    let mut observation = Observation::default();
    let mut transport = unadopted_transport();
    transport.certificate_der = None;
    observation.record(Stage::HelperAcquire, Reason::HelperTimeout);
    assert!(matches!(
        transport
            .acquire_flow(&helper, 50_000, &mut observation)
            .await,
        Err(MptcpTransportError::InvalidMetadata),
    ));
    assert_eq!(observation.failure().unwrap().stage, Stage::Material);
    assert_eq!(observation.failure().unwrap().reason, Reason::Metadata);

    let mut transport = unadopted_transport();
    let held = (0..64)
        .map(|_| transport.retirements.reserve().unwrap())
        .collect::<Vec<_>>();
    assert!(matches!(
        transport
            .acquire_flow(&helper, 50_000, &mut observation)
            .await,
        Err(MptcpTransportError::Io(error)) if error.kind() == io::ErrorKind::Other,
    ));
    assert_eq!(observation.failure().unwrap().stage, Stage::SlotReservation);
    assert_eq!(observation.failure().unwrap().reason, Reason::LocalCapacity);
    drop(held);

    let mut unknown = transport.retirements.reserve().unwrap();
    unknown.begin_acquire();
    drop(unknown);
    assert!(matches!(
        transport
            .acquire_flow(&helper, 50_000, &mut observation)
            .await,
        Err(MptcpTransportError::AcquireUnconfirmed),
    ));
    assert_eq!(observation.failure().unwrap().stage, Stage::RetirementDrain);
    assert_eq!(observation.failure().unwrap().reason, Reason::Unconfirmed);
    assert!(!format!("{:?}", observation.failure()).contains(CANARY));
}
