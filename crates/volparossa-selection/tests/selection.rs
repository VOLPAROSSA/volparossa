//! Integration tests for candidate, path, and route-context selection invariants.

use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use volparossa_core::{
    Bandwidth, CapacitySnapshot, FlowId, IpFamily, LocalProfileId, NetworkMetadata,
    NodeAdvertisement, NodeCapabilities, NodeId, NodeQuality, NodeRoles, ObservedNetworkOrigin,
    ObservedNetworkPrefix, OperatorId, OriginKey, PROTOCOL_VERSION, PathId, PeerId, PolicyHash,
    RouteContextId, ServiceRole, Transport, UnixTime,
};
use volparossa_selection::{
    Candidate, CandidateEvidence, CompleteRelayPathMetrics, DiversityAnchor, FilterRequirements,
    HardFilterReason, HysteresisPolicy, MAXIMUM_ACTIVE_FLOWS, MAXIMUM_CONTEXT_TTL_SECONDS,
    MAXIMUM_HYSTERESIS_PAIRS, MAXIMUM_ROUTE_CONTEXTS, MAXIMUM_SELECTION_CANDIDATES, PathMetrics,
    PathMetricsError, PathState, PathStatus, PathTransitionError, PrefixObservedCandidate,
    ProjectedRelayPath, ProspectiveRelayPolicy, RelayPathCandidate, RelaySelectionPolicy,
    RelaySelectionProjection, ReplacementDecision, ReplacementHysteresis, ReplacementReason,
    RouteContext, RouteContextCache, RouteContextError, RoutePlan, RouteScope, SelectionBand,
    SelectionError, SelectionMix, hard_filter, select_exit, select_exit_with_observed_prefixes,
    select_projected_relay_paths, select_prospective_relays,
    select_prospective_relays_with_observed_prefixes, select_relay_paths,
};

fn bandwidth(value: u32) -> Bandwidth {
    Bandwidth::new(value, value).expect("bounded bandwidth")
}

fn candidate(index: u8, role: ServiceRole, measurement_count: u32) -> Candidate {
    let roles = match role {
        ServiceRole::Relay => NodeRoles {
            client: false,
            relay: true,
            exit: false,
        },
        ServiceRole::Exit => NodeRoles {
            client: false,
            relay: false,
            exit: true,
        },
    };
    Candidate {
        advertisement: NodeAdvertisement {
            protocol_version: PROTOCOL_VERSION,
            node_id: NodeId::new(format!("node-{index}")).expect("valid id"),
            peer_id: PeerId::new(format!("peer-{index}")).expect("valid id"),
            sequence_number: u64::from(index),
            roles,
            capabilities: NodeCapabilities {
                tcp_mptcp: true,
                udp_single_path: true,
                multipath_quic: true,
                ipv4: true,
                ipv6: true,
                udp_hole_punching: true,
            },
            capacity: CapacitySnapshot {
                relay_limit: bandwidth(200),
                exit_limit: bandwidth(200),
                currently_reserved: bandwidth(20),
                estimated_free: bandwidth(100 + u32::from(index)),
                active_relay_sessions: u32::from(index),
                active_exit_sessions: u32::from(index),
                free_relay_slots: 10,
                free_exit_slots: 10,
                sample_window_seconds: 15,
            },
            network: NetworkMetadata {
                operator_id: OperatorId::new(format!("operator-{index}")).expect("valid id"),
                region: "eu-west".to_owned(),
                country_code: "NL".to_owned(),
                asn: Some(64_500 + u32::from(index)),
                ipv4_prefix_hint: Some(format!("10.{index}.1.0/24")),
                ipv6_prefix_hint: None,
            },
            quality: NodeQuality {
                local_uptime_seconds: 100_000,
                historical_uptime_score: 0.8,
                historical_delivery_ratio_p25: 0.8,
            },
            policy_hash: PolicyHash::from_bytes([9; 32]),
            control_endpoints: vec![format!("/ip4/10.{index}.1.10/udp/443/quic-v1")],
            measured_at: UnixTime::from_secs(1_000),
            expires_at: UnixTime::from_secs(1_300),
        },
        signature_verified: true,
        evidence: CandidateEvidence {
            locally_measured_p25: (measurement_count >= 3)
                .then(|| bandwidth(70 + u32::from(index))),
            reserved_path_limit: bandwidth(150),
            uptime_score: 0.70 + f64::from(index) / 100.0,
            reputation_score: 0.65 + f64::from(index) / 100.0,
            proximity_score: 0.80,
            recent_egress_quality: 0.75,
            rtt_ms: Some(20.0 + f64::from(index)),
            measurement_count,
            reachable: true,
            network_address_usable: true,
            observed_network_origin: Some(ObservedNetworkOrigin {
                address: IpAddr::V4(Ipv4Addr::new(10, index, 1, 10)),
            }),
            locally_blocked: false,
            serious_protocol_fault_until: None,
        },
    }
}

fn requirements(role: ServiceRole) -> FilterRequirements {
    FilterRequirements {
        now: UnixTime::from_secs(1_100),
        role,
        transport: Transport::MultipathQuic,
        policy_hash: PolicyHash::from_bytes([9; 32]),
        minimum_capacity: bandwidth(10),
        address_family: None,
        region: Some("eu-west".to_owned()),
        require_reachable: true,
    }
}

fn prospective_candidate(index: u8, measurement_count: u32) -> Candidate {
    let mut value = candidate(index, ServiceRole::Relay, measurement_count);
    value.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V4(Ipv4Addr::new(45, 67, index, 1)),
    });
    value
}

fn public_exit_candidate(index: u8, measurement_count: u32) -> Candidate {
    let mut value = candidate(index, ServiceRole::Exit, measurement_count);
    value.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V4(Ipv4Addr::new(45, 66, index, 1)),
    });
    value
}

fn discard_observed_origins(candidates: &mut [Candidate]) -> Vec<ObservedNetworkPrefix> {
    candidates
        .iter_mut()
        .map(|candidate| {
            ObservedNetworkPrefix::from_origin(
                candidate
                    .evidence
                    .observed_network_origin
                    .take()
                    .expect("fixture observed origin"),
            )
        })
        .collect()
}

fn prefix_observed_candidates<'a>(
    candidates: &'a [Candidate],
    prefixes: &[ObservedNetworkPrefix],
) -> Vec<PrefixObservedCandidate<'a>> {
    candidates
        .iter()
        .zip(prefixes)
        .map(|(candidate, prefix)| {
            PrefixObservedCandidate::new(candidate, *prefix).expect("raw-address-free fixture")
        })
        .collect()
}

fn prospective_anchors() -> [DiversityAnchor; 2] {
    [240_u8, 241_u8].map(|index| {
        let mut value = candidate(index, ServiceRole::Exit, 10);
        value.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
            address: IpAddr::V4(Ipv4Addr::new(45, 68, index, 1)),
        });
        DiversityAnchor::new(
            value.advertisement.node_id,
            value.advertisement.peer_id,
            value.advertisement.network.operator_id,
            value.advertisement.network.asn.expect("fixture ASN"),
            value
                .evidence
                .observed_network_origin
                .expect("fixture observed origin"),
        )
        .expect("valid anchor")
    })
}

fn prefix_native_prospective_anchors() -> [DiversityAnchor; 2] {
    prefix_native_prospective_anchors_for(IpFamily::Ipv4)
}

fn prefix_native_prospective_anchors_for(family: IpFamily) -> [DiversityAnchor; 2] {
    [240_u8, 241_u8].map(|index| {
        let value = candidate(index, ServiceRole::Exit, 10);
        let prefix = match family {
            IpFamily::Ipv4 => ObservedNetworkPrefix::ipv4_24([45, 68, index]),
            IpFamily::Ipv6 => ObservedNetworkPrefix::ipv6_48([0x26, 0x06, 0x47, 0x00, 0x47, index]),
        };
        DiversityAnchor::from_observed_prefix(
            value.advertisement.node_id,
            value.advertisement.peer_id,
            value.advertisement.network.operator_id,
            value.advertisement.network.asn.expect("fixture ASN"),
            prefix,
        )
        .expect("valid prefix-native anchor")
    })
}

fn selected_prospective_identities(
    candidates: &[Candidate],
    seed: u64,
) -> Vec<(NodeId, PeerId, SelectionBand)> {
    let mut rng = ChaCha8Rng::seed_from_u64(seed);
    select_prospective_relays(
        candidates,
        &requirements(ServiceRole::Relay),
        &prospective_anchors(),
        ProspectiveRelayPolicy::new(2, 8, SelectionMix::default()).expect("valid policy"),
        &mut rng,
    )
    .expect("prospective relay slate")
    .relays()
    .iter()
    .map(|relay| (relay.node_id.clone(), relay.peer_id.clone(), relay.band))
    .collect()
}

#[test]
fn prefix_native_exit_selection_is_seeded_differentially_identical() {
    let legacy = (1..=10)
        .map(|index| public_exit_candidate(index, u32::from(index < 9) * 10))
        .collect::<Vec<_>>();
    let mut prefix_native = legacy.clone();
    let prefixes = discard_observed_origins(&mut prefix_native);
    let observed = prefix_observed_candidates(&prefix_native, &prefixes);
    let mut required = requirements(ServiceRole::Exit);
    required.address_family = Some(IpFamily::Ipv4);

    for seed in [1, 17, 71, 9_001] {
        let mut legacy_rng = ChaCha8Rng::seed_from_u64(seed);
        let mut prefix_rng = ChaCha8Rng::seed_from_u64(seed);
        let selected_legacy =
            select_exit(&legacy, &required, SelectionMix::default(), &mut legacy_rng)
                .expect("legacy exit");
        let selected_prefix = select_exit_with_observed_prefixes(
            &observed,
            &required,
            SelectionMix::default(),
            &mut prefix_rng,
        )
        .expect("prefix-native exit");
        assert_eq!(selected_prefix, selected_legacy);
        assert_eq!(prefix_rng.next_u64(), legacy_rng.next_u64());
    }
}

#[test]
fn prefix_native_prospective_selection_is_seeded_differentially_identical() {
    let legacy = (1..=10)
        .map(|index| prospective_candidate(index, u32::from(index < 9) * 10))
        .collect::<Vec<_>>();
    let mut prefix_native = legacy.clone();
    let prefixes = discard_observed_origins(&mut prefix_native);
    let observed = prefix_observed_candidates(&prefix_native, &prefixes);
    let mut required = requirements(ServiceRole::Relay);
    required.address_family = Some(IpFamily::Ipv4);
    let policy = ProspectiveRelayPolicy::new(2, 8, SelectionMix::default()).expect("valid policy");

    for seed in [3, 29, 72, 8_800] {
        let mut legacy_rng = ChaCha8Rng::seed_from_u64(seed);
        let mut prefix_rng = ChaCha8Rng::seed_from_u64(seed);
        let selected_legacy = select_prospective_relays(
            &legacy,
            &required,
            &prospective_anchors(),
            policy,
            &mut legacy_rng,
        )
        .expect("legacy prospective relays");
        let selected_prefix = select_prospective_relays_with_observed_prefixes(
            &observed,
            &required,
            &prefix_native_prospective_anchors(),
            policy,
            &mut prefix_rng,
        )
        .expect("prefix-native prospective relays");
        assert_eq!(selected_prefix, selected_legacy);
        assert_eq!(prefix_rng.next_u64(), legacy_rng.next_u64());
    }
}

fn select_two_prefix_native_relays(
    prefixes: [ObservedNetworkPrefix; 2],
    family: IpFamily,
) -> Result<volparossa_selection::ProspectiveRelaySelection, SelectionError> {
    let mut candidates = vec![prospective_candidate(1, 10), prospective_candidate(2, 10)];
    for candidate in &mut candidates {
        candidate.evidence.observed_network_origin = None;
    }
    let observed = prefix_observed_candidates(&candidates, &prefixes);
    let mut required = requirements(ServiceRole::Relay);
    required.address_family = Some(family);
    select_prospective_relays_with_observed_prefixes(
        &observed,
        &required,
        &prefix_native_prospective_anchors_for(family),
        ProspectiveRelayPolicy::new(2, 2, SelectionMix::default()).expect("valid policy"),
        &mut ChaCha8Rng::seed_from_u64(91),
    )
}

#[test]
fn prefix_native_prospective_diversity_collides_on_ipv4_24_only() {
    let first = ObservedNetworkPrefix::ipv4_24([45, 70, 1]);
    assert_eq!(
        select_two_prefix_native_relays([first, first], IpFamily::Ipv4),
        Err(SelectionError::InsufficientDiversePaths {
            required: 2,
            available: 1,
        })
    );
    let adjacent = ObservedNetworkPrefix::ipv4_24([45, 70, 2]);
    assert_eq!(
        select_two_prefix_native_relays([first, adjacent], IpFamily::Ipv4)
            .expect("adjacent IPv4 /24 prefixes")
            .relays()
            .len(),
        2
    );
}

#[test]
fn prefix_native_prospective_diversity_collides_on_ipv6_48_only() {
    let first = ObservedNetworkPrefix::ipv6_48([0x26, 0x06, 0x47, 0x00, 0x48, 0x01]);
    assert_eq!(
        select_two_prefix_native_relays([first, first], IpFamily::Ipv6),
        Err(SelectionError::InsufficientDiversePaths {
            required: 2,
            available: 1,
        })
    );
    let adjacent = ObservedNetworkPrefix::ipv6_48([0x26, 0x06, 0x47, 0x00, 0x48, 0x02]);
    assert_eq!(
        select_two_prefix_native_relays([first, adjacent], IpFamily::Ipv6)
            .expect("adjacent IPv6 /48 prefixes")
            .relays()
            .len(),
        2
    );
}

#[test]
fn prefix_native_anchors_reject_special_prefixes_and_wrong_family() {
    let value = public_exit_candidate(238, 10);
    assert_eq!(
        DiversityAnchor::from_observed_prefix(
            value.advertisement.node_id,
            value.advertisement.peer_id,
            value.advertisement.network.operator_id,
            value.advertisement.network.asn.expect("fixture ASN"),
            ObservedNetworkPrefix::ipv4_24([10, 1, 2]),
        ),
        Err(SelectionError::InvalidDiversityAnchors)
    );

    let mut candidates = vec![prospective_candidate(1, 10), prospective_candidate(2, 10)];
    for candidate in &mut candidates {
        candidate.evidence.observed_network_origin = None;
    }
    let prefixes = [
        ObservedNetworkPrefix::ipv6_48([0x26, 0x06, 0x47, 0x00, 0x48, 1]),
        ObservedNetworkPrefix::ipv6_48([0x26, 0x06, 0x47, 0x00, 0x48, 2]),
    ];
    let observed = prefix_observed_candidates(&candidates, &prefixes);
    let mut required = requirements(ServiceRole::Relay);
    required.address_family = Some(IpFamily::Ipv6);
    assert_eq!(
        select_prospective_relays_with_observed_prefixes(
            &observed,
            &required,
            &prefix_native_prospective_anchors(),
            ProspectiveRelayPolicy::new(2, 2, SelectionMix::default()).expect("valid policy"),
            &mut ChaCha8Rng::seed_from_u64(93),
        ),
        Err(SelectionError::InvalidDiversityAnchors)
    );
}

#[test]
fn legacy_anchor_equality_retains_host_bits_but_native_anchor_does_not_mint_them() {
    let value = public_exit_candidate(239, 10);
    let make_legacy = |host| {
        DiversityAnchor::new(
            value.advertisement.node_id.clone(),
            value.advertisement.peer_id.clone(),
            value.advertisement.network.operator_id.clone(),
            value.advertisement.network.asn.expect("fixture ASN"),
            ObservedNetworkOrigin {
                address: IpAddr::V4(Ipv4Addr::new(45, 69, 1, host)),
            },
        )
        .expect("legacy anchor")
    };
    let legacy_left = make_legacy(1);
    let legacy_right = make_legacy(2);
    assert_ne!(legacy_left, legacy_right);

    let make_native = || {
        DiversityAnchor::from_observed_prefix(
            value.advertisement.node_id.clone(),
            value.advertisement.peer_id.clone(),
            value.advertisement.network.operator_id.clone(),
            value.advertisement.network.asn.expect("fixture ASN"),
            ObservedNetworkPrefix::ipv4_24([45, 69, 1]),
        )
        .expect("prefix-native anchor")
    };
    assert_eq!(make_native(), make_native());
}

#[test]
fn prospective_relays_are_randomized_diverse_and_bounded_to_eight() {
    let candidates = (1..=12)
        .map(|index| prospective_candidate(index, if index >= 11 { 0 } else { 10 }))
        .collect::<Vec<_>>();
    let selected = selected_prospective_identities(&candidates, 71);
    let mut reversed = candidates.clone();
    reversed.reverse();
    assert_eq!(selected, selected_prospective_identities(&reversed, 71));
    assert_ne!(selected, selected_prospective_identities(&candidates, 72));
    assert_eq!(selected.len(), 8);

    let selected_nodes = selected
        .iter()
        .map(|(node_id, _, _)| node_id)
        .collect::<std::collections::HashSet<_>>();
    let selected_peers = selected
        .iter()
        .map(|(_, peer_id, _)| peer_id)
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(selected_nodes.len(), selected.len());
    assert_eq!(selected_peers.len(), selected.len());

    let exploration_policy = ProspectiveRelayPolicy::new(
        1,
        1,
        SelectionMix {
            high: 0.0,
            diverse_middle: 0.0,
            exploration: 1.0,
        },
    )
    .expect("exploration policy");
    let mut rng = ChaCha8Rng::seed_from_u64(9);
    let exploration = select_prospective_relays(
        &candidates,
        &requirements(ServiceRole::Relay),
        &prospective_anchors(),
        exploration_policy,
        &mut rng,
    )
    .expect("exploration relay");
    assert_eq!(exploration.relays()[0].band, SelectionBand::Exploration);
}

#[test]
fn prospective_relays_reject_201_candidates_and_invalid_probe_limits() {
    let candidates = vec![prospective_candidate(1, 10); 201];
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    assert_eq!(
        select_prospective_relays(
            &candidates,
            &requirements(ServiceRole::Relay),
            &prospective_anchors(),
            ProspectiveRelayPolicy::new(1, 8, SelectionMix::default()).expect("valid policy"),
            &mut rng,
        ),
        Err(SelectionError::TooManyCandidates {
            supplied: 201,
            maximum: MAXIMUM_SELECTION_CANDIDATES,
        })
    );
    assert_eq!(
        ProspectiveRelayPolicy::new(0, 8, SelectionMix::default()),
        Err(SelectionError::InvalidPolicy)
    );
    assert_eq!(
        ProspectiveRelayPolicy::new(2, 9, SelectionMix::default()),
        Err(SelectionError::InvalidPolicy)
    );
    let anchor = candidate(242, ServiceRole::Exit, 10);
    assert_eq!(
        DiversityAnchor::new(
            anchor.advertisement.node_id,
            anchor.advertisement.peer_id,
            anchor.advertisement.network.operator_id,
            anchor.advertisement.network.asn.expect("fixture ASN"),
            ObservedNetworkOrigin {
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
        ),
        Err(SelectionError::InvalidDiversityAnchors)
    );
}

#[test]
fn prospective_relays_never_require_synthetic_complete_path_metrics() {
    let candidates = (1..=4)
        .map(|index| prospective_candidate(index, 0))
        .collect::<Vec<_>>();
    let mut rng = ChaCha8Rng::seed_from_u64(19);
    let selected = select_prospective_relays(
        &candidates,
        &requirements(ServiceRole::Relay),
        &prospective_anchors(),
        ProspectiveRelayPolicy::new(2, 4, SelectionMix::default()).expect("valid policy"),
        &mut rng,
    )
    .expect("peer-only evidence suffices");
    assert_eq!(selected.relays().len(), 4);
    assert!(
        selected
            .relays()
            .iter()
            .all(|relay| relay.band == SelectionBand::Exploration)
    );
}

fn assert_one_prospective_hard_filter_rejects(mutated: Candidate) {
    let mut candidates = (1..=4)
        .map(|index| prospective_candidate(index, 10))
        .collect::<Vec<_>>();
    candidates[0] = mutated;
    let mut rng = ChaCha8Rng::seed_from_u64(83);
    assert_eq!(
        select_prospective_relays(
            &candidates,
            &requirements(ServiceRole::Relay),
            &prospective_anchors(),
            ProspectiveRelayPolicy::new(4, 4, SelectionMix::default()).expect("valid policy"),
            &mut rng,
        ),
        Err(SelectionError::InsufficientDiversePaths {
            required: 4,
            available: 3,
        })
    );
}

#[test]
fn prospective_relays_apply_every_peer_hard_filter_before_sampling() {
    let baseline = prospective_candidate(1, 10);
    let mut rng = ChaCha8Rng::seed_from_u64(83);
    assert_eq!(
        select_prospective_relays(
            &[
                baseline.clone(),
                prospective_candidate(2, 10),
                prospective_candidate(3, 10),
                prospective_candidate(4, 10),
            ],
            &requirements(ServiceRole::Relay),
            &prospective_anchors(),
            ProspectiveRelayPolicy::new(4, 4, SelectionMix::default()).expect("valid policy"),
            &mut rng,
        )
        .expect("all baseline peers pass hard filters")
        .relays()
        .len(),
        4
    );

    let mut low_reserve = baseline.clone();
    low_reserve.evidence.reserved_path_limit = bandwidth(1);
    assert_one_prospective_hard_filter_rejects(low_reserve);

    let mut unreachable = baseline.clone();
    unreachable.evidence.reachable = false;
    unreachable.evidence.rtt_ms = None;
    assert_one_prospective_hard_filter_rejects(unreachable);

    let mut unusable = baseline.clone();
    unusable.evidence.network_address_usable = false;
    assert_one_prospective_hard_filter_rejects(unusable);

    let mut blocked = baseline.clone();
    blocked.evidence.locally_blocked = true;
    assert_one_prospective_hard_filter_rejects(blocked);

    let mut wrong_policy = baseline.clone();
    wrong_policy.advertisement.policy_hash = PolicyHash::from_bytes([8; 32]);
    assert_one_prospective_hard_filter_rejects(wrong_policy);

    let mut wrong_role = baseline;
    wrong_role.advertisement.roles.relay = false;
    wrong_role.advertisement.roles.exit = true;
    assert_one_prospective_hard_filter_rejects(wrong_role);
}

fn assert_anchor_conflict_is_excluded(conflict: Candidate, anchors: &[DiversityAnchor]) {
    let conflict_node = conflict.advertisement.node_id.clone();
    let candidates = vec![
        conflict,
        prospective_candidate(21, 10),
        prospective_candidate(22, 10),
    ];
    let mut rng = ChaCha8Rng::seed_from_u64(91);
    let selected = select_prospective_relays(
        &candidates,
        &requirements(ServiceRole::Relay),
        anchors,
        ProspectiveRelayPolicy::new(2, 3, SelectionMix::default()).expect("valid policy"),
        &mut rng,
    )
    .expect("two non-conflicting candidates");
    assert_eq!(selected.relays().len(), 2);
    assert!(
        selected
            .relays()
            .iter()
            .all(|relay| relay.node_id != conflict_node)
    );
}

fn assert_slate_pair_conflict_selects_at_most_one(
    first: Candidate,
    second: Candidate,
    anchors: &[DiversityAnchor],
) {
    let pair = [
        first.advertisement.node_id.clone(),
        second.advertisement.node_id.clone(),
    ];
    let candidates = vec![
        first,
        second,
        prospective_candidate(3, 10),
        prospective_candidate(4, 10),
        prospective_candidate(5, 10),
    ];
    let mut rng = ChaCha8Rng::seed_from_u64(97);
    let selected = select_prospective_relays(
        &candidates,
        &requirements(ServiceRole::Relay),
        anchors,
        ProspectiveRelayPolicy::new(3, 4, SelectionMix::default()).expect("valid policy"),
        &mut rng,
    )
    .expect("bounded diverse slate");
    assert_eq!(selected.relays().len(), 4);
    assert!(
        selected
            .relays()
            .iter()
            .filter(|relay| pair.contains(&relay.node_id))
            .count()
            <= 1
    );
}

#[test]
fn prospective_relays_enforce_each_anchor_and_slate_diversity_axis() {
    let anchors = prospective_anchors();
    let mut node = prospective_candidate(10, 10);
    node.advertisement.node_id = NodeId::new("node-240").expect("anchor node");
    assert_anchor_conflict_is_excluded(node, &anchors);

    let mut peer = prospective_candidate(10, 10);
    peer.advertisement.peer_id = PeerId::new("peer-240").expect("anchor peer");
    assert_anchor_conflict_is_excluded(peer, &anchors);

    let mut operator = prospective_candidate(10, 10);
    operator.advertisement.network.operator_id =
        OperatorId::new("operator-240").expect("anchor operator");
    assert_anchor_conflict_is_excluded(operator, &anchors);

    let mut asn = prospective_candidate(10, 10);
    asn.advertisement.network.asn = Some(64_740);
    assert_anchor_conflict_is_excluded(asn, &anchors);

    let mut exact_origin = prospective_candidate(10, 10);
    exact_origin.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V4(Ipv4Addr::new(45, 68, 240, 1)),
    });
    assert_anchor_conflict_is_excluded(exact_origin, &anchors);

    let mut ipv4_24 = prospective_candidate(10, 10);
    ipv4_24.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V4(Ipv4Addr::new(45, 68, 240, 99)),
    });
    assert_anchor_conflict_is_excluded(ipv4_24, &anchors);

    let mut ipv6_anchor_peer = candidate(239, ServiceRole::Exit, 10);
    ipv6_anchor_peer.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x100, 0, 0, 0, 0, 1)),
    });
    let ipv6_anchor = DiversityAnchor::new(
        ipv6_anchor_peer.advertisement.node_id,
        ipv6_anchor_peer.advertisement.peer_id,
        ipv6_anchor_peer.advertisement.network.operator_id,
        ipv6_anchor_peer
            .advertisement
            .network
            .asn
            .expect("anchor ASN"),
        ipv6_anchor_peer
            .evidence
            .observed_network_origin
            .expect("anchor origin"),
    )
    .expect("IPv6 anchor");
    let ipv6_anchors = [ipv6_anchor, anchors[1].clone()];
    let mut ipv6_48 = prospective_candidate(10, 10);
    ipv6_48.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x100, 1, 0, 0, 0, 2)),
    });
    assert_anchor_conflict_is_excluded(ipv6_48, &ipv6_anchors);

    let mut first = prospective_candidate(11, 10);
    let mut second = prospective_candidate(12, 10);
    second.advertisement.network.operator_id = first.advertisement.network.operator_id.clone();
    assert_slate_pair_conflict_selects_at_most_one(first.clone(), second.clone(), &anchors);
    second.advertisement.network.operator_id = OperatorId::new("operator-12").expect("operator");
    second.advertisement.network.asn = first.advertisement.network.asn;
    assert_slate_pair_conflict_selects_at_most_one(first.clone(), second.clone(), &anchors);
    second.advertisement.network.asn = Some(64_512);
    second.evidence.observed_network_origin = first.evidence.observed_network_origin;
    assert_slate_pair_conflict_selects_at_most_one(first.clone(), second.clone(), &anchors);
    second.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V4(Ipv4Addr::new(45, 67, 11, 99)),
    });
    assert_slate_pair_conflict_selects_at_most_one(first.clone(), second.clone(), &anchors);
    first.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0x4001, 0, 0, 0, 0, 1)),
    });
    second.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V6(Ipv6Addr::new(0x2a00, 0x1450, 0x4001, 1, 0, 0, 0, 2)),
    });
    assert_slate_pair_conflict_selects_at_most_one(first, second, &ipv6_anchors);
}

#[test]
fn prospective_relays_reject_conflicting_duplicates_independent_of_input_order() {
    let expected = Err(SelectionError::DuplicateIdentity);
    for duplicate_peer in [false, true] {
        let first = prospective_candidate(1, 10);
        let mut conflict = prospective_candidate(2, 10);
        if duplicate_peer {
            conflict.advertisement.peer_id = first.advertisement.peer_id.clone();
        } else {
            conflict.advertisement.node_id = first.advertisement.node_id.clone();
        }
        conflict.advertisement.network.operator_id =
            OperatorId::new("conflicting-operator").expect("operator");
        conflict.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
            address: IpAddr::V4(Ipv4Addr::new(91, 92, 93, 94)),
        });
        for candidates in [vec![first.clone(), conflict.clone()], vec![conflict, first]] {
            let mut rng = ChaCha8Rng::seed_from_u64(37);
            assert_eq!(
                select_prospective_relays(
                    &candidates,
                    &requirements(ServiceRole::Relay),
                    &prospective_anchors(),
                    ProspectiveRelayPolicy::new(1, 2, SelectionMix::default())
                        .expect("valid policy"),
                    &mut rng,
                ),
                expected
            );
        }
    }
}

#[test]
fn hard_filters_reject_signature_policy_slots_and_faults() {
    let mut value = candidate(1, ServiceRole::Exit, 8);
    let required = requirements(ServiceRole::Exit);
    value.signature_verified = false;
    assert_eq!(
        hard_filter(&value, &required),
        Err(HardFilterReason::InvalidSignature)
    );

    value.signature_verified = true;
    value.advertisement.policy_hash = PolicyHash::from_bytes([4; 32]);
    assert_eq!(
        hard_filter(&value, &required),
        Err(HardFilterReason::PolicyMismatch)
    );

    value.advertisement.policy_hash = required.policy_hash;
    value.advertisement.capacity.free_exit_slots = 0;
    assert_eq!(
        hard_filter(&value, &required),
        Err(HardFilterReason::NoFreeSlot)
    );

    value.advertisement.capacity.free_exit_slots = 1;
    value.evidence.serious_protocol_fault_until = Some(UnixTime::from_secs(1_200));
    assert_eq!(
        hard_filter(&value, &required),
        Err(HardFilterReason::SeriousProtocolFault)
    );

    value.evidence.serious_protocol_fault_until = None;
    value.advertisement.capacity.exit_limit = bandwidth(0);
    assert_eq!(
        hard_filter(&value, &required),
        Err(HardFilterReason::InsufficientCapacity)
    );

    let mut invalid_required = required;
    invalid_required.minimum_capacity = Bandwidth {
        up_mbps: 1_000_001,
        down_mbps: 1,
    };
    assert_eq!(
        hard_filter(&value, &invalid_required),
        Err(HardFilterReason::InvalidRequirements)
    );
}

#[test]
fn selection_uses_randomized_seventy_twenty_ten_pools() {
    let mut candidates: Vec<Candidate> = (1..=8)
        .map(|index| candidate(index, ServiceRole::Exit, 10))
        .collect();
    candidates.push(candidate(9, ServiceRole::Exit, 0));
    candidates.push(candidate(10, ServiceRole::Exit, 0));
    let mut rng = ChaCha8Rng::seed_from_u64(42);
    let mut high = 0_u32;
    let mut middle = 0_u32;
    let mut exploration = 0_u32;
    for _ in 0..20_000 {
        let selected = select_exit(
            &candidates,
            &requirements(ServiceRole::Exit),
            SelectionMix::default(),
            &mut rng,
        )
        .expect("eligible exit");
        match selected.band {
            SelectionBand::High => high += 1,
            SelectionBand::DiverseMiddle => middle += 1,
            SelectionBand::Exploration => exploration += 1,
        }
    }
    let total = f64::from(high + middle + exploration);
    assert!((f64::from(high) / total - 0.70).abs() < 0.02);
    assert!((f64::from(middle) / total - 0.20).abs() < 0.02);
    assert!((f64::from(exploration) / total - 0.10).abs() < 0.02);
}

fn relay_path(index: u8) -> RelayPathCandidate {
    RelayPathCandidate {
        relay: candidate(index, ServiceRole::Relay, 10),
        client_to_relay_capacity: bandwidth(100),
        relay_to_exit_capacity: bandwidth(90),
        exit_reserved_capacity: bandwidth(80),
        client_to_relay_rtt_ms: 10.0 + f64::from(index),
        relay_to_exit_rtt_ms: 10.0,
        unique_throughput_gain_ratio: 0.20,
        meaningful_failover: true,
    }
}

fn public_relay_path(index: u8) -> RelayPathCandidate {
    RelayPathCandidate {
        relay: prospective_candidate(index, 10),
        ..relay_path(index)
    }
}

fn projected_path<'a>(
    projection: &'a RelaySelectionProjection,
    path: &RelayPathCandidate,
) -> ProjectedRelayPath<'a> {
    ProjectedRelayPath::new(
        projection,
        CompleteRelayPathMetrics::new(
            path.client_to_relay_capacity,
            path.relay_to_exit_capacity,
            path.exit_reserved_capacity,
            path.client_to_relay_rtt_ms,
            path.relay_to_exit_rtt_ms,
            path.unique_throughput_gain_ratio,
            path.meaningful_failover,
        ),
    )
}

#[test]
fn sanitized_relay_selection_matches_legacy_and_golden_complete_path_scores() {
    let paths = vec![public_relay_path(1), public_relay_path(2)];
    let required = requirements(ServiceRole::Relay);
    let policy = RelaySelectionPolicy {
        active_paths: 2,
        minimum_paths: 2,
        maximum_paths: 8,
        warm_backup_paths: 0,
        ..RelaySelectionPolicy::default()
    };
    let projections = paths
        .iter()
        .map(|path| {
            RelaySelectionProjection::from_candidate(path.relay.clone(), &required)
                .expect("hard-filtered endpoint-free projection")
        })
        .collect::<Vec<_>>();
    let projected = paths
        .iter()
        .zip(&projections)
        .map(|(path, projection)| projected_path(projection, path))
        .collect::<Vec<_>>();
    let mut prefix_paths = paths.clone();
    let prefixes = prefix_paths
        .iter_mut()
        .map(|path| {
            ObservedNetworkPrefix::from_origin(
                path.relay
                    .evidence
                    .observed_network_origin
                    .take()
                    .expect("fixture observed origin"),
            )
        })
        .collect::<Vec<_>>();
    let prefix_projections = prefix_paths
        .iter()
        .zip(&prefixes)
        .map(|(path, prefix)| {
            let observed = PrefixObservedCandidate::new(&path.relay, *prefix)
                .expect("raw-address-free candidate");
            RelaySelectionProjection::from_prefix_observed_candidate(&observed, &required)
                .expect("prefix-native endpoint-free projection")
        })
        .collect::<Vec<_>>();
    let prefix_projected = prefix_paths
        .iter()
        .zip(&prefix_projections)
        .map(|(path, projection)| projected_path(projection, path))
        .collect::<Vec<_>>();

    let mut legacy_rng = ChaCha8Rng::seed_from_u64(29);
    let legacy =
        select_relay_paths(&paths, &required, policy, &mut legacy_rng).expect("legacy selection");
    let mut projected_rng = ChaCha8Rng::seed_from_u64(29);
    let selected = select_projected_relay_paths(&projected, &required, policy, &mut projected_rng)
        .expect("projected selection");
    let prefix_selected = select_projected_relay_paths(
        &prefix_projected,
        &required,
        policy,
        &mut ChaCha8Rng::seed_from_u64(29),
    )
    .expect("prefix-native projected selection");
    assert_eq!(selected, legacy);
    assert_eq!(prefix_selected, legacy);
    assert_eq!(
        selected
            .active
            .iter()
            .map(|path| path.relay_node_id.as_str())
            .collect::<Vec<_>>(),
        ["node-2", "node-1"]
    );

    let complete_path_quality_one = 1.0 / (1.0 + 21.0 / 100.0);
    let complete_path_quality_two = 1.0 / (1.0 + 22.0 / 100.0);
    let expected_one = 0.30 * (71.0 / 72.0)
        + 0.20 * (71.0 / 72.0)
        + 0.15 * 0.71
        + 0.15 * complete_path_quality_one
        + 0.10 * 0.66
        + 0.10 * 0.5;
    let expected_two =
        0.30 + 0.20 + 0.15 * 0.72 + 0.15 * complete_path_quality_two + 0.10 * 0.67 + 0.10 * 0.5;
    let one = selected
        .active
        .iter()
        .find(|path| path.relay_node_id.as_str() == "node-1")
        .expect("golden node one");
    let two = selected
        .active
        .iter()
        .find(|path| path.relay_node_id.as_str() == "node-2")
        .expect("golden node two");
    assert!((one.score - expected_one).abs() < 1e-12);
    assert!((two.score - expected_two).abs() < 1e-12);
    assert_eq!(one.band, SelectionBand::DiverseMiddle);
    assert_eq!(two.band, SelectionBand::High);
}

#[test]
fn sanitized_projection_preserves_hard_filters_and_rejects_unsafe_origin_before_stripping() {
    let required = requirements(ServiceRole::Relay);
    let baseline = prospective_candidate(20, 10);
    assert!(hard_filter(&baseline, &required).is_ok());
    assert!(RelaySelectionProjection::from_candidate(baseline, &required).is_ok());

    let mut mutations = Vec::new();
    let mut unsigned = prospective_candidate(21, 10);
    unsigned.signature_verified = false;
    mutations.push((unsigned, HardFilterReason::InvalidSignature));
    let mut wrong_policy = prospective_candidate(22, 10);
    wrong_policy.advertisement.policy_hash = PolicyHash::from_bytes([8; 32]);
    mutations.push((wrong_policy, HardFilterReason::PolicyMismatch));
    let mut no_slots = prospective_candidate(23, 10);
    no_slots.advertisement.capacity.free_relay_slots = 0;
    mutations.push((no_slots, HardFilterReason::NoFreeSlot));
    let mut blocked = prospective_candidate(24, 10);
    blocked.evidence.locally_blocked = true;
    mutations.push((blocked, HardFilterReason::LocallyBlocked));
    for (candidate, expected) in mutations {
        assert_eq!(hard_filter(&candidate, &required), Err(expected.clone()));
        assert!(matches!(
            RelaySelectionProjection::from_candidate(candidate, &required),
            Err(SelectionError::HardFilter(actual)) if actual == expected
        ));
    }

    let private_origin = candidate(25, ServiceRole::Relay, 10);
    assert!(hard_filter(&private_origin, &required).is_ok());
    assert!(matches!(
        RelaySelectionProjection::from_candidate(private_origin, &required),
        Err(SelectionError::HardFilter(
            HardFilterReason::UnusableNetworkAddress
        ))
    ));

    let mut ipv6_required = required.clone();
    ipv6_required.address_family = Some(IpFamily::Ipv6);
    let wrong_observed_family = prospective_candidate(26, 10);
    assert!(hard_filter(&wrong_observed_family, &ipv6_required).is_ok());
    assert!(matches!(
        RelaySelectionProjection::from_candidate(wrong_observed_family, &ipv6_required),
        Err(SelectionError::HardFilter(
            HardFilterReason::UnusableNetworkAddress
        ))
    ));

    let mut invalid_endpoint = prospective_candidate(27, 10);
    invalid_endpoint.advertisement.control_endpoints.clear();
    assert!(matches!(
        RelaySelectionProjection::from_candidate(invalid_endpoint, &required),
        Err(SelectionError::HardFilter(
            HardFilterReason::InvalidAdvertisement(_)
        ))
    ));
}

fn prefix_projection(
    candidate: &Candidate,
    prefix: ObservedNetworkPrefix,
    requirements: &FilterRequirements,
) -> Result<RelaySelectionProjection, SelectionError> {
    let observed =
        PrefixObservedCandidate::new(candidate, prefix).map_err(SelectionError::HardFilter)?;
    RelaySelectionProjection::from_prefix_observed_candidate(&observed, requirements)
}

#[test]
fn prefix_observed_wrapper_rejects_only_ambiguous_dual_input() {
    let with_legacy_origin = prospective_candidate(28, 10);
    assert!(matches!(
        PrefixObservedCandidate::new(
            &with_legacy_origin,
            ObservedNetworkPrefix::ipv4_24([45, 67, 28]),
        ),
        Err(HardFilterReason::UnusableNetworkAddress)
    ));

    let mut raw_address_free = with_legacy_origin;
    raw_address_free.evidence.observed_network_origin = None;
    assert!(
        PrefixObservedCandidate::new(
            &raw_address_free,
            ObservedNetworkPrefix::ipv4_24([10, 1, 2]),
        )
        .is_ok(),
        "constructor must normalize shape only; the hard filter validates publicness"
    );
}

#[test]
fn prefix_projection_keeps_filter_error_order_and_legacy_order_unchanged() {
    let mut prefix_candidate = prospective_candidate(29, 10);
    prefix_candidate.evidence.observed_network_origin = None;
    prefix_candidate.signature_verified = false;
    prefix_candidate.evidence.reachable = false;
    let private_prefix = ObservedNetworkPrefix::ipv4_24([10, 1, 2]);
    let public_prefix = ObservedNetworkPrefix::ipv4_24([45, 67, 29]);

    let mut invalid = requirements(ServiceRole::Relay);
    invalid.minimum_capacity = Bandwidth {
        up_mbps: 1_000_001,
        down_mbps: 1,
    };
    assert!(matches!(
        prefix_projection(&prefix_candidate, private_prefix, &invalid),
        Err(SelectionError::HardFilter(
            HardFilterReason::InvalidRequirements
        ))
    ));

    let required = requirements(ServiceRole::Relay);
    assert!(matches!(
        prefix_projection(&prefix_candidate, private_prefix, &required),
        Err(SelectionError::HardFilter(
            HardFilterReason::InvalidSignature
        ))
    ));
    prefix_candidate.signature_verified = true;
    assert!(matches!(
        prefix_projection(&prefix_candidate, private_prefix, &required),
        Err(SelectionError::HardFilter(
            HardFilterReason::UnusableNetworkAddress
        ))
    ));
    assert!(matches!(
        prefix_projection(&prefix_candidate, public_prefix, &required),
        Err(SelectionError::HardFilter(HardFilterReason::Unreachable))
    ));

    let mut ipv6_required = required.clone();
    ipv6_required.address_family = Some(IpFamily::Ipv6);
    prefix_candidate.evidence.reachable = true;
    assert!(matches!(
        prefix_projection(&prefix_candidate, public_prefix, &ipv6_required),
        Err(SelectionError::HardFilter(
            HardFilterReason::UnusableNetworkAddress
        ))
    ));

    let mut legacy_private_unreachable = candidate(30, ServiceRole::Relay, 10);
    legacy_private_unreachable.evidence.reachable = false;
    assert!(matches!(
        RelaySelectionProjection::from_candidate(legacy_private_unreachable, &required),
        Err(SelectionError::HardFilter(HardFilterReason::Unreachable))
    ));
}

fn assert_projected_selection_bounds_and_scope() {
    let required = requirements(ServiceRole::Relay);
    let projections = (0..201)
        .map(|_| {
            RelaySelectionProjection::from_candidate(prospective_candidate(1, 10), &required)
                .expect("unique bounded projection")
        })
        .collect::<Vec<_>>();
    let source_paths = (0..201).map(|_| public_relay_path(1)).collect::<Vec<_>>();
    let projected = projections
        .iter()
        .zip(&source_paths)
        .map(|(projection, path)| projected_path(projection, path))
        .collect::<Vec<_>>();
    let mut rng = ChaCha8Rng::seed_from_u64(31);
    assert_eq!(
        select_projected_relay_paths(
            &projected,
            &required,
            RelaySelectionPolicy::default(),
            &mut rng,
        ),
        Err(SelectionError::TooManyCandidates {
            supplied: 201,
            maximum: MAXIMUM_SELECTION_CANDIDATES,
        })
    );

    let mut backwards = required.clone();
    backwards.now = UnixTime::from_secs(required.now.as_secs() - 1);
    assert!(matches!(
        select_projected_relay_paths(
            &projected[..2],
            &backwards,
            RelaySelectionPolicy {
                active_paths: 2,
                minimum_paths: 2,
                maximum_paths: 2,
                warm_backup_paths: 0,
                ..RelaySelectionPolicy::default()
            },
            &mut rng,
        ),
        Err(SelectionError::InsufficientDiversePaths {
            required: 2,
            available: 0
        })
    ));
}

fn projection_api(source: &str) -> &str {
    source
        .split("/// Opaque, endpoint-free relay metadata")
        .nth(1)
        .expect("projection documentation")
        .split("/// Endpoint-free complete-path scalar measurements.")
        .next()
        .expect("projection API end")
}

fn assert_projection_surface(source: &str) {
    let projection_api = projection_api(source);
    let declaration = projection_api
        .split("pub struct RelaySelectionProjection")
        .nth(1)
        .expect("projection declaration")
        .split('}')
        .next()
        .expect("projection declaration end");
    assert!(!projection_api.contains("#[derive"));
    assert!(!declaration.contains("\n    pub "));
    assert!(declaration.contains("network_prefix: ObservedNetworkPrefix"));
    for forbidden in [
        "derive(",
        "Candidate",
        "NodeAdvertisement",
        "ObservedNetworkOrigin",
        "IpAddr",
        "control_endpoints",
        "pub node_id",
        "pub peer_id",
    ] {
        assert!(
            !declaration.contains(forbidden),
            "leaking surface: {forbidden}"
        );
    }
    assert_eq!(
        projection_api
            .matches("impl RelaySelectionProjection {")
            .count(),
        1,
        "the opaque projection has one auditable inherent API"
    );
    assert_eq!(projection_api.matches("\n    pub ").count(), 2);
    assert!(projection_api.contains("\n    pub fn from_candidate("));
    assert!(projection_api.contains("\n    pub fn from_prefix_observed_candidate("));
    for forbidden in [
        "impl Clone for RelaySelectionProjection",
        "impl Copy for RelaySelectionProjection",
        "impl Debug for RelaySelectionProjection",
        "impl std::fmt::Debug for RelaySelectionProjection",
        "impl serde::Serialize for RelaySelectionProjection",
        "impl Serialize for RelaySelectionProjection",
        "Deserialize<'de> for RelaySelectionProjection",
        "pub fn node_id(",
        "pub fn peer_id(",
        "pub fn operator_id(",
        "pub fn asn(",
        "pub fn network_prefix(",
        "pub fn evidence(",
        "pub fn into_parts(",
        "pub fn decompose(",
    ] {
        assert!(!source.contains(forbidden), "leaking API: {forbidden}");
    }
}

fn assert_projection_helper_bodies(source: &str) {
    let projection_api = projection_api(source);
    for (type_name, marker) in [
        ("ProjectedRelayEvidence", "struct ProjectedRelayEvidence {"),
        ("ProjectedRelayScope", "struct ProjectedRelayScope {"),
    ] {
        let declaration = projection_api
            .split(marker)
            .nth(1)
            .expect("projected helper declaration")
            .split('}')
            .next()
            .expect("projected helper body");
        for forbidden in [
            "IpAddr",
            "ObservedNetworkOrigin",
            "Candidate",
            "NodeAdvertisement",
            "control_endpoints",
        ] {
            assert!(
                !declaration.contains(forbidden),
                "{type_name} leaks {forbidden}"
            );
        }
    }
    assert!(!projection_api.contains("ProjectedNetworkPrefix"));
}

fn assert_complete_path_metrics_surface(source: &str) {
    let metrics_api = source
        .split("/// Endpoint-free complete-path scalar measurements.")
        .nth(1)
        .expect("complete path metrics documentation")
        .split("/// Complete-path measurements paired with one opaque relay projection.")
        .next()
        .expect("complete path metrics API end");
    let metrics_body = metrics_api
        .split("pub struct CompleteRelayPathMetrics {")
        .nth(1)
        .expect("complete path metrics declaration")
        .split('}')
        .next()
        .expect("complete path metrics body");
    assert!(!metrics_api.contains("#[derive"));
    assert!(!metrics_body.contains("\n    pub "));
    assert_eq!(
        metrics_api
            .matches("impl CompleteRelayPathMetrics {")
            .count(),
        1
    );
    assert_eq!(metrics_api.matches("\n    pub ").count(), 1);
    assert!(metrics_api.contains("\n    pub const fn new("));
    for forbidden in [
        "IpAddr",
        "ObservedNetworkOrigin",
        "Candidate",
        "NodeAdvertisement",
        "control_endpoints",
    ] {
        assert!(
            !metrics_body.contains(forbidden),
            "metrics leak: {forbidden}"
        );
    }
    for forbidden in [
        "Clone for CompleteRelayPathMetrics",
        "Copy for CompleteRelayPathMetrics",
        "Debug for CompleteRelayPathMetrics",
        "Default for CompleteRelayPathMetrics",
        "Serialize for CompleteRelayPathMetrics",
        "Deserialize<'de> for CompleteRelayPathMetrics",
        "pub fn into_parts(",
        "pub fn decompose(",
    ] {
        assert!(!source.contains(forbidden), "metrics surface: {forbidden}");
    }
}

fn assert_prefix_wrapper_and_filter_surface(source: &str) {
    let product = source
        .split("/// Exact requirements applied before any score is computed.")
        .next()
        .expect("candidate prefix product source");
    let wrapper = product
        .split("/// A borrowed candidate paired with one canonical prefix-only local observation.")
        .nth(1)
        .expect("prefix wrapper")
        .split("enum ObservedNetworkInput")
        .next()
        .expect("prefix wrapper end");
    let declaration = wrapper
        .split("pub struct PrefixObservedCandidate")
        .nth(1)
        .expect("prefix wrapper declaration")
        .split('}')
        .next()
        .expect("prefix wrapper declaration end");
    assert!(!wrapper.contains("#[derive"));
    assert_eq!(declaration.matches("\n    pub(crate) ").count(), 2);
    assert!(declaration.contains("candidate: &'a Candidate"));
    assert!(declaration.contains("observed_network_prefix: ObservedNetworkPrefix"));
    assert_eq!(wrapper.matches("\n    pub fn ").count(), 1);
    assert!(wrapper.contains("\n    pub fn new("));
    for forbidden in [
        "Clone for PrefixObservedCandidate",
        "Copy for PrefixObservedCandidate",
        "impl std::fmt::Debug for PrefixObservedCandidate",
        "impl Debug for PrefixObservedCandidate",
        "Serialize for PrefixObservedCandidate",
        "Deserialize<'de> for PrefixObservedCandidate",
        "pub fn candidate(",
        "pub fn observed_network_prefix(",
        "pub fn into_parts(",
        "pub fn decompose(",
    ] {
        assert!(!source.contains(forbidden), "wrapper leak: {forbidden}");
    }
    assert!(wrapper.contains("observed_network_origin.is_some()"));
    assert!(!wrapper.contains("is_public_routable()"));
    assert!(!wrapper.contains(".family()"));

    let input = source
        .split("enum ObservedNetworkInput {")
        .nth(1)
        .expect("observed network input")
        .split('}')
        .next()
        .expect("observed network input end");
    assert!(input.contains("Legacy"));
    assert!(input.contains("Prefix(ObservedNetworkPrefix)"));
    assert!(!input.contains("bool"));
    assert!(!input.contains("Option<"));
    let hard_filter_signature = source
        .split("fn hard_filter_core(")
        .nth(1)
        .expect("shared hard filter")
        .split(") ->")
        .next()
        .expect("shared hard filter signature");
    assert!(hard_filter_signature.contains("observed_network: &ObservedNetworkInput"));
}

fn assert_prefix_weighted_uses_one_shared_selection_core(source: &str) {
    assert_eq!(source.matches("select_exit_core").count(), 3);
    assert_eq!(source.matches("select_prospective_relays_core").count(), 3);
    assert_eq!(source.matches("fn from_legacy_candidate(").count(), 1);
    assert_eq!(source.matches("from_legacy_candidate(").count(), 2);
    assert!(!source.contains("pub fn from_legacy_candidate("));
    assert_eq!(
        source
            .matches("pub fn select_exit_with_observed_prefixes")
            .count(),
        1
    );
    assert_eq!(
        source
            .matches("pub fn select_prospective_relays_with_observed_prefixes")
            .count(),
        1
    );
    assert!(!source.contains("ProjectedNetworkPrefix"));
    assert!(!source.contains(".ipv4_24()"));
    assert!(!source.contains(".ipv6_48()"));

    let diversity = source
        .split("struct DiversitySet {")
        .nth(1)
        .expect("shared diversity set")
        .split('}')
        .next()
        .expect("shared diversity fields");
    assert_eq!(
        diversity.matches("HashSet<ObservedNetworkPrefix>").count(),
        1
    );
    assert!(!diversity.contains("ObservedNetworkOrigin"));
    assert!(!diversity.contains("ipv4"));
    assert!(!diversity.contains("ipv6"));
}

#[test]
fn prefix_native_surface_has_one_unambiguous_filter_and_shared_selection_core() {
    assert_prefix_wrapper_and_filter_surface(include_str!("../src/candidate.rs"));
    assert_prefix_weighted_uses_one_shared_selection_core(include_str!("../src/weighted.rs"));
}

#[test]
fn sanitized_projection_is_bounded_scope_bound_and_has_no_leaking_surface() {
    assert_projected_selection_bounds_and_scope();
    let source = include_str!("../src/weighted.rs");
    assert_projection_surface(source);
    assert_projection_helper_bodies(source);
    assert_complete_path_metrics_surface(source);
}

#[test]
fn sanitized_projection_accepts_forward_time_but_rejects_expiry_and_static_scope_changes() {
    let required = requirements(ServiceRole::Relay);
    let paths = [public_relay_path(3), public_relay_path(4)];
    let projections = paths
        .iter()
        .map(|path| {
            RelaySelectionProjection::from_candidate(path.relay.clone(), &required)
                .expect("valid scoped projection")
        })
        .collect::<Vec<_>>();
    let projected = paths
        .iter()
        .zip(&projections)
        .map(|(path, projection)| projected_path(projection, path))
        .collect::<Vec<_>>();
    let policy = RelaySelectionPolicy {
        active_paths: 2,
        minimum_paths: 2,
        maximum_paths: 2,
        warm_backup_paths: 0,
        ..RelaySelectionPolicy::default()
    };
    let select = |requirements: &FilterRequirements| {
        select_projected_relay_paths(
            &projected,
            requirements,
            policy,
            &mut ChaCha8Rng::seed_from_u64(37),
        )
    };

    let mut forward = required.clone();
    forward.now = UnixTime::from_secs(1_299);
    assert!(select(&forward).is_ok());
    let mut expired = forward.clone();
    expired.now = UnixTime::from_secs(1_300);
    assert!(matches!(
        select(&expired),
        Err(SelectionError::InsufficientDiversePaths {
            required: 2,
            available: 0
        })
    ));

    let mut mutations = Vec::new();
    let mut transport = required.clone();
    transport.transport = Transport::TcpMptcp;
    mutations.push(transport);
    let mut policy_hash = required.clone();
    policy_hash.policy_hash = PolicyHash::from_bytes([8; 32]);
    mutations.push(policy_hash);
    let mut minimum = required.clone();
    minimum.minimum_capacity = bandwidth(11);
    mutations.push(minimum);
    let mut family = required.clone();
    family.address_family = Some(IpFamily::Ipv4);
    mutations.push(family);
    let mut region = required.clone();
    region.region = Some("eu-central".to_owned());
    mutations.push(region);
    let mut reachable = required.clone();
    reachable.require_reachable = false;
    mutations.push(reachable);
    for changed in mutations {
        assert!(matches!(
            select(&changed),
            Err(SelectionError::InsufficientDiversePaths {
                required: 2,
                available: 0
            })
        ));
    }
    let mut role = required.clone();
    role.role = ServiceRole::Exit;
    assert_eq!(select(&role), Err(SelectionError::WrongSelectionRole));

    let mut future_measured = [public_relay_path(5), public_relay_path(6)];
    future_measured[0].relay.advertisement.measured_at = UnixTime::from_secs(1_200);
    let mut legacy_rng = ChaCha8Rng::seed_from_u64(41);
    let legacy = select_relay_paths(&future_measured, &required, policy, &mut legacy_rng)
        .expect("legacy accepts future measured-at parity fixture");
    let future_projections = future_measured
        .iter()
        .map(|path| {
            RelaySelectionProjection::from_candidate(path.relay.clone(), &required)
                .expect("projected future measured-at parity fixture")
        })
        .collect::<Vec<_>>();
    let future_projected = future_measured
        .iter()
        .zip(&future_projections)
        .map(|(path, projection)| projected_path(projection, path))
        .collect::<Vec<_>>();
    let projected = select_projected_relay_paths(
        &future_projected,
        &required,
        policy,
        &mut ChaCha8Rng::seed_from_u64(41),
    )
    .expect("projected selection preserves legacy measured-at semantics");
    assert_eq!(projected, legacy);
}

#[test]
fn sanitized_selection_preserves_minimum_gain_failover_warm_and_filter_semantics() {
    let required = requirements(ServiceRole::Relay);
    let mut paths = (1..=5).map(public_relay_path).collect::<Vec<_>>();
    paths[0].unique_throughput_gain_ratio = 0.0;
    paths[0].meaningful_failover = false;
    paths[1].unique_throughput_gain_ratio = 0.40;
    paths[1].meaningful_failover = false;
    paths[2].unique_throughput_gain_ratio = 0.0;
    paths[2].meaningful_failover = true;
    paths[3].unique_throughput_gain_ratio = 0.30;
    paths[3].meaningful_failover = false;
    paths[4].relay.evidence.locally_blocked = true;
    paths.push(paths[1].clone());
    let policy = RelaySelectionPolicy {
        active_paths: 3,
        minimum_paths: 2,
        maximum_paths: 4,
        warm_backup_paths: 1,
        minimum_unique_throughput_gain_ratio: 0.20,
        mix: SelectionMix {
            high: 1.0,
            diverse_middle: 0.0,
            exploration: 0.0,
        },
        ..RelaySelectionPolicy::default()
    };
    let projected_sources = paths
        .iter()
        .enumerate()
        .filter(|(index, _)| *index != 4)
        .map(|(_, path)| path)
        .collect::<Vec<_>>();
    let projections = projected_sources
        .iter()
        .map(|path| {
            RelaySelectionProjection::from_candidate(path.relay.clone(), &required)
                .expect("eligible sanitized candidate")
        })
        .collect::<Vec<_>>();
    assert!(matches!(
        RelaySelectionProjection::from_candidate(paths[4].relay.clone(), &required),
        Err(SelectionError::HardFilter(HardFilterReason::LocallyBlocked))
    ));
    let projected_paths = projected_sources
        .iter()
        .zip(&projections)
        .map(|(path, projection)| projected_path(projection, path))
        .collect::<Vec<_>>();
    let legacy = select_relay_paths(
        &paths,
        &required,
        policy,
        &mut ChaCha8Rng::seed_from_u64(43),
    )
    .expect("legacy rich selection");
    let projected = select_projected_relay_paths(
        &projected_paths,
        &required,
        policy,
        &mut ChaCha8Rng::seed_from_u64(43),
    )
    .expect("projected rich selection");
    assert_eq!(projected, legacy);
    assert_eq!(projected.active.len(), 3);
    assert_eq!(projected.warm_backups.len(), 1);
    assert!(
        projected
            .active
            .iter()
            .chain(&projected.warm_backups)
            .all(|path| path.relay_node_id.as_str() != "node-5")
    );
    assert_eq!(
        projected
            .active
            .iter()
            .chain(&projected.warm_backups)
            .filter(|path| path.relay_node_id.as_str() == "node-2")
            .count(),
        1,
        "a duplicate node/peer is never selected as an independent path"
    );
}

#[test]
fn relay_selection_enforces_operator_prefix_and_asn_diversity() {
    let mut paths: Vec<RelayPathCandidate> = (1..=6).map(relay_path).collect();
    paths[1].relay.advertisement.network.operator_id =
        paths[0].relay.advertisement.network.operator_id.clone();
    paths[2].relay.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V4(Ipv4Addr::new(10, 1, 1, 99)),
    });
    paths[3].relay.advertisement.network.asn = paths[0].relay.advertisement.network.asn;

    let mut rng = ChaCha8Rng::seed_from_u64(17);
    let selected = select_relay_paths(
        &paths,
        &requirements(ServiceRole::Relay),
        RelaySelectionPolicy {
            active_paths: 3,
            minimum_paths: 2,
            maximum_paths: 8,
            warm_backup_paths: 1,
            ..RelaySelectionPolicy::default()
        },
        &mut rng,
    )
    .expect("enough diverse paths");
    assert_eq!(selected.active.len(), 3);
    assert_eq!(selected.warm_backups.len(), 1);

    let chosen: Vec<&Candidate> = selected
        .active
        .iter()
        .chain(&selected.warm_backups)
        .map(|path| {
            paths
                .iter()
                .find(|candidate| candidate.relay.advertisement.node_id == path.relay_node_id)
                .map(|candidate| &candidate.relay)
                .expect("selected candidate exists")
        })
        .collect();
    for (position, left) in chosen.iter().enumerate() {
        for right in chosen.iter().skip(position + 1) {
            assert_ne!(
                left.advertisement.network.operator_id,
                right.advertisement.network.operator_id
            );
            assert_ne!(
                left.evidence
                    .observed_network_origin
                    .and_then(|origin| origin.ipv4_24()),
                right
                    .evidence
                    .observed_network_origin
                    .and_then(|origin| origin.ipv4_24())
            );
        }
    }
}

#[test]
fn legacy_complete_path_keeps_private_special_and_wrong_family_compatibility() {
    let baseline_paths = vec![relay_path(1), relay_path(2)];
    let mut special_paths = baseline_paths.clone();
    special_paths[1].relay.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V6("2001:db8::1".parse().expect("special IPv6 address")),
    });
    let mut required = requirements(ServiceRole::Relay);
    required.address_family = Some(IpFamily::Ipv4);
    for path in &special_paths {
        assert!(hard_filter(&path.relay, &required).is_ok());
    }
    let policy = RelaySelectionPolicy {
        active_paths: 2,
        minimum_paths: 2,
        maximum_paths: 2,
        warm_backup_paths: 0,
        ..RelaySelectionPolicy::default()
    };
    let baseline = select_relay_paths(
        &baseline_paths,
        &required,
        policy,
        &mut ChaCha8Rng::seed_from_u64(97),
    )
    .expect("baseline legacy paths");
    let special = select_relay_paths(
        &special_paths,
        &required,
        policy,
        &mut ChaCha8Rng::seed_from_u64(97),
    )
    .expect("legacy lax special/wrong-family paths");
    assert_eq!(special, baseline);
}

#[test]
fn udp_selection_keeps_exactly_one_active_relay() {
    let paths: Vec<RelayPathCandidate> = (1..=3).map(relay_path).collect();
    let mut required = requirements(ServiceRole::Relay);
    required.transport = Transport::UdpSinglePath;
    let mut rng = ChaCha8Rng::seed_from_u64(23);
    let selected = select_relay_paths(
        &paths,
        &required,
        RelaySelectionPolicy {
            active_paths: 1,
            minimum_paths: 1,
            maximum_paths: 3,
            warm_backup_paths: 1,
            ..RelaySelectionPolicy::default()
        },
        &mut rng,
    )
    .expect("single-path UDP relay");
    assert_eq!(selected.active.len(), 1);
    assert_eq!(selected.warm_backups.len(), 1);
}

#[test]
fn selected_results_preserve_authenticated_peer_bindings() {
    let exit = candidate(7, ServiceRole::Exit, 10);
    let expected_exit_node = exit.advertisement.node_id.clone();
    let expected_exit_peer = exit.advertisement.peer_id.clone();
    let mut rng = ChaCha8Rng::seed_from_u64(71);
    let selected_exit = select_exit(
        &[exit],
        &requirements(ServiceRole::Exit),
        SelectionMix::default(),
        &mut rng,
    )
    .expect("one verified exit");
    assert_eq!(selected_exit.node_id, expected_exit_node);
    assert_eq!(selected_exit.peer_id, expected_exit_peer);

    let paths = vec![relay_path(1), relay_path(2)];
    let selected = select_relay_paths(
        &paths,
        &requirements(ServiceRole::Relay),
        RelaySelectionPolicy {
            active_paths: 2,
            minimum_paths: 2,
            maximum_paths: 8,
            warm_backup_paths: 0,
            ..RelaySelectionPolicy::default()
        },
        &mut rng,
    )
    .expect("two verified relay paths");
    for path in selected.active {
        let source = paths
            .iter()
            .find(|candidate| candidate.relay.advertisement.node_id == path.relay_node_id)
            .expect("selected relay came from the verified input");
        assert_eq!(path.relay_peer_id, source.relay.advertisement.peer_id);
    }
}

#[test]
fn defaults_and_weighted_scores_match_the_specification_exactly() {
    let policy = RelaySelectionPolicy::default();
    assert_eq!(policy.active_paths, 4);
    assert_eq!(policy.minimum_paths, 2);
    assert_eq!(policy.maximum_paths, 8);
    assert_eq!(policy.warm_backup_paths, 2);
    assert!((policy.maximum_rtt_spread_ms - 20.0).abs() < f64::EPSILON);
    assert!((policy.minimum_unique_throughput_gain_ratio - 0.10).abs() < f64::EPSILON);
    assert_eq!(
        policy.mix,
        SelectionMix {
            high: 0.70,
            diverse_middle: 0.20,
            exploration: 0.10,
        }
    );

    let mut exit = candidate(1, ServiceRole::Exit, 10);
    exit.advertisement.capacity.estimated_free = bandwidth(100);
    exit.advertisement.capacity.active_exit_sessions = 1;
    exit.evidence.locally_measured_p25 = Some(bandwidth(100));
    exit.evidence.reserved_path_limit = bandwidth(100);
    exit.evidence.uptime_score = 0.8;
    exit.evidence.recent_egress_quality = 0.6;
    exit.evidence.reputation_score = 0.7;
    let mut rng = ChaCha8Rng::seed_from_u64(1);
    let selected_exit = select_exit(
        &[exit],
        &requirements(ServiceRole::Exit),
        SelectionMix::default(),
        &mut rng,
    )
    .expect("one eligible exit");
    let expected_exit_score =
        0.30 * 1.0 + 0.20 * 1.0 + 0.15 * 0.8 + 0.15 * 0.6 + 0.10 * 0.7 + 0.10 * 0.5;
    assert!((selected_exit.score - expected_exit_score).abs() < 1e-12);

    let mut paths = vec![relay_path(1), relay_path(2)];
    for path in &mut paths {
        path.relay.evidence.locally_measured_p25 = Some(bandwidth(80));
        path.relay.evidence.uptime_score = 0.8;
        path.relay.evidence.reputation_score = 0.7;
        path.client_to_relay_rtt_ms = 10.0;
        path.relay_to_exit_rtt_ms = 10.0;
    }
    let selected = select_relay_paths(
        &paths,
        &requirements(ServiceRole::Relay),
        RelaySelectionPolicy {
            active_paths: 2,
            minimum_paths: 2,
            maximum_paths: 8,
            warm_backup_paths: 0,
            ..RelaySelectionPolicy::default()
        },
        &mut rng,
    )
    .expect("two complete paths");
    let complete_path_quality = 1.0 / (1.0 + 20.0 / 100.0);
    let expected_relay_score = 0.30 * 1.0
        + 0.20 * 1.0
        + 0.15 * 0.8
        + 0.15 * complete_path_quality
        + 0.10 * 0.7
        + 0.10 * 0.5;
    for path in selected.active {
        assert!((path.score - expected_relay_score).abs() < 1e-12);
    }
}

#[test]
fn complete_path_capacity_includes_conservative_local_relay_evidence() {
    let mut path = relay_path(1);
    path.client_to_relay_capacity = bandwidth(80);
    path.relay_to_exit_capacity = bandwidth(70);
    path.exit_reserved_capacity = bandwidth(60);
    path.relay.advertisement.capacity.estimated_free = bandwidth(100);
    path.relay.evidence.locally_measured_p25 = Some(bandwidth(30));
    path.relay.evidence.reserved_path_limit = bandwidth(25);
    assert_eq!(path.path_capacity(), bandwidth(25));
}

#[test]
fn one_invalid_relay_candidate_cannot_deny_service_to_valid_paths() {
    let mut paths = vec![relay_path(1), relay_path(2), relay_path(3)];
    paths[0].client_to_relay_rtt_ms = f64::NAN;
    let mut rng = ChaCha8Rng::seed_from_u64(5);
    let selected = select_relay_paths(
        &paths,
        &requirements(ServiceRole::Relay),
        RelaySelectionPolicy {
            active_paths: 2,
            minimum_paths: 2,
            maximum_paths: 8,
            warm_backup_paths: 0,
            ..RelaySelectionPolicy::default()
        },
        &mut rng,
    )
    .expect("valid paths survive a malformed peer");
    assert_eq!(selected.active.len(), 2);
    assert!(
        selected
            .active
            .iter()
            .all(|path| path.relay_node_id.as_str() != "node-1")
    );
}

#[test]
fn duplicate_node_or_peer_identity_never_counts_as_an_independent_path() {
    let mut node_duplicates = vec![relay_path(1), relay_path(2)];
    node_duplicates[1].relay.advertisement.node_id =
        node_duplicates[0].relay.advertisement.node_id.clone();
    let policy = RelaySelectionPolicy {
        active_paths: 2,
        minimum_paths: 2,
        maximum_paths: 8,
        warm_backup_paths: 0,
        ..RelaySelectionPolicy::default()
    };
    let mut rng = ChaCha8Rng::seed_from_u64(7);
    assert_eq!(
        select_relay_paths(
            &node_duplicates,
            &requirements(ServiceRole::Relay),
            policy,
            &mut rng
        ),
        Err(SelectionError::InsufficientDiversePaths {
            required: 2,
            available: 1,
        })
    );

    let mut peer_duplicates = vec![relay_path(1), relay_path(2)];
    peer_duplicates[1].relay.advertisement.peer_id =
        peer_duplicates[0].relay.advertisement.peer_id.clone();
    assert_eq!(
        select_relay_paths(
            &peer_duplicates,
            &requirements(ServiceRole::Relay),
            policy,
            &mut rng
        ),
        Err(SelectionError::InsufficientDiversePaths {
            required: 2,
            available: 1,
        })
    );
}

#[test]
fn candidate_input_is_bounded_before_selection_allocates() {
    let candidates = vec![candidate(1, ServiceRole::Exit, 10); MAXIMUM_SELECTION_CANDIDATES + 1];
    let mut rng = ChaCha8Rng::seed_from_u64(9);
    assert_eq!(
        select_exit(
            &candidates,
            &requirements(ServiceRole::Exit),
            SelectionMix::default(),
            &mut rng,
        ),
        Err(SelectionError::TooManyCandidates {
            supplied: MAXIMUM_SELECTION_CANDIDATES + 1,
            maximum: MAXIMUM_SELECTION_CANDIDATES,
        })
    );
}

#[test]
fn ipv6_prefix_and_asn_diversity_are_enforced() {
    let mut same_ipv6_origin = vec![relay_path(1), relay_path(2)];
    same_ipv6_origin[0].relay.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V6(
            "2001:db8:abcd:1::1"
                .parse::<Ipv6Addr>()
                .expect("valid IPv6"),
        ),
    });
    same_ipv6_origin[1].relay.evidence.observed_network_origin = Some(ObservedNetworkOrigin {
        address: IpAddr::V6(
            "2001:db8:abcd:2::1"
                .parse::<Ipv6Addr>()
                .expect("valid IPv6"),
        ),
    });
    let policy = RelaySelectionPolicy {
        active_paths: 2,
        minimum_paths: 2,
        maximum_paths: 8,
        warm_backup_paths: 0,
        ..RelaySelectionPolicy::default()
    };
    let mut rng = ChaCha8Rng::seed_from_u64(11);
    assert!(matches!(
        select_relay_paths(
            &same_ipv6_origin,
            &requirements(ServiceRole::Relay),
            policy,
            &mut rng
        ),
        Err(SelectionError::InsufficientDiversePaths { .. })
    ));

    let mut asn_paths = vec![relay_path(1), relay_path(2), relay_path(3)];
    asn_paths[0].relay.advertisement.network.asn = Some(64_500);
    asn_paths[1].relay.advertisement.network.asn = Some(64_500);
    asn_paths[2].relay.advertisement.network.asn = Some(64_501);
    let selected = select_relay_paths(
        &asn_paths,
        &requirements(ServiceRole::Relay),
        policy,
        &mut rng,
    )
    .expect("a distinct ASN is available");
    let selected_asns: Vec<Option<u32>> = selected
        .active
        .iter()
        .map(|selected_path| {
            asn_paths
                .iter()
                .find(|path| path.relay.advertisement.node_id == selected_path.relay_node_id)
                .expect("selected path exists")
                .relay
                .advertisement
                .network
                .asn
        })
        .collect();
    assert_ne!(selected_asns[0], selected_asns[1]);
}

#[test]
fn extra_active_paths_require_ten_percent_unique_gain_or_failover() {
    let mut paths: Vec<RelayPathCandidate> = (1..=3).map(relay_path).collect();
    for path in &mut paths {
        path.unique_throughput_gain_ratio = 0.099;
        path.meaningful_failover = false;
    }
    let policy = RelaySelectionPolicy {
        active_paths: 3,
        minimum_paths: 2,
        maximum_paths: 8,
        warm_backup_paths: 0,
        ..RelaySelectionPolicy::default()
    };
    let mut rng = ChaCha8Rng::seed_from_u64(13);
    let selected = select_relay_paths(&paths, &requirements(ServiceRole::Relay), policy, &mut rng)
        .expect("minimum paths remain viable");
    assert_eq!(selected.active.len(), 2);

    for path in &mut paths {
        path.unique_throughput_gain_ratio = 0.10;
    }
    let selected = select_relay_paths(&paths, &requirements(ServiceRole::Relay), policy, &mut rng)
        .expect("ten percent gain activates the third path");
    assert_eq!(selected.active.len(), 3);

    for path in &mut paths {
        path.unique_throughput_gain_ratio = 0.0;
        path.meaningful_failover = true;
    }
    let selected = select_relay_paths(&paths, &requirements(ServiceRole::Relay), policy, &mut rng)
        .expect("failover value activates the third path");
    assert_eq!(selected.active.len(), 3);
}

#[test]
fn warm_backups_are_not_subject_to_the_active_rtt_spread() {
    let mut paths = vec![relay_path(1), relay_path(2), relay_path(3)];
    paths[0].client_to_relay_rtt_ms = 10.0;
    paths[0].relay_to_exit_rtt_ms = 10.0;
    paths[1].client_to_relay_rtt_ms = 15.0;
    paths[1].relay_to_exit_rtt_ms = 10.0;
    paths[2].client_to_relay_rtt_ms = 90.0;
    paths[2].relay_to_exit_rtt_ms = 10.0;
    let mut rng = ChaCha8Rng::seed_from_u64(14);
    let selected = select_relay_paths(
        &paths,
        &requirements(ServiceRole::Relay),
        RelaySelectionPolicy {
            active_paths: 2,
            minimum_paths: 2,
            maximum_paths: 8,
            warm_backup_paths: 1,
            mix: SelectionMix {
                high: 1.0,
                diverse_middle: 0.0,
                exploration: 0.0,
            },
            ..RelaySelectionPolicy::default()
        },
        &mut rng,
    )
    .expect("high-latency path remains usable as a warm backup");
    assert_eq!(selected.active.len(), 2);
    assert_eq!(selected.warm_backups.len(), 1);
    assert_eq!(selected.warm_backups[0].relay_node_id.as_str(), "node-3");
}

#[test]
fn rtt_spread_and_non_finite_policy_values_fail_closed() {
    let mut paths = vec![relay_path(1), relay_path(2), relay_path(3)];
    paths[0].client_to_relay_rtt_ms = 10.0;
    paths[0].relay_to_exit_rtt_ms = 10.0;
    paths[1].client_to_relay_rtt_ms = 20.0;
    paths[1].relay_to_exit_rtt_ms = 10.0;
    paths[2].client_to_relay_rtt_ms = 31.0;
    paths[2].relay_to_exit_rtt_ms = 10.0;
    let mut rng = ChaCha8Rng::seed_from_u64(15);
    assert!(matches!(
        select_relay_paths(
            &paths,
            &requirements(ServiceRole::Relay),
            RelaySelectionPolicy {
                active_paths: 3,
                minimum_paths: 3,
                maximum_paths: 8,
                warm_backup_paths: 0,
                ..RelaySelectionPolicy::default()
            },
            &mut rng,
        ),
        Err(SelectionError::InsufficientDiversePaths { .. })
    ));

    for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
        assert_eq!(
            select_exit(
                &[candidate(1, ServiceRole::Exit, 10)],
                &requirements(ServiceRole::Exit),
                SelectionMix {
                    high: invalid,
                    diverse_middle: 0.0,
                    exploration: 0.0,
                },
                &mut rng,
            ),
            Err(SelectionError::InvalidPolicy)
        );
    }
}

fn scope(origin: &str) -> RouteScope {
    RouteScope {
        local_profile: LocalProfileId::new("default").expect("valid"),
        origin_key: OriginKey::new(origin).expect("opaque key"),
        transport: Transport::TcpMptcp,
        policy_version: 7,
        policy_hash: PolicyHash::from_bytes([9; 32]),
    }
}

fn context(id: &str, route_scope: RouteScope, expires_at: u64, exit: &str) -> RouteContext {
    RouteContext {
        route_context_id: RouteContextId::new(id).expect("valid"),
        scope: route_scope,
        plan: RoutePlan {
            exit_node_id: NodeId::new(exit).expect("valid"),
            active_relays: vec![
                NodeId::new(format!("relay-a-{id}")).expect("valid"),
                NodeId::new(format!("relay-b-{id}")).expect("valid"),
            ],
            warm_relays: Vec::new(),
        },
        created_at: UnixTime::from_secs(1_000),
        expires_at: UnixTime::from_secs(expires_at),
    }
}

#[test]
fn route_ttl_affects_new_flows_but_never_moves_existing_flow() {
    let route_scope = scope("opaque-origin-a");
    let mut cache = RouteContextCache::new(4, 3_600).expect("valid cache");
    cache
        .insert_context(
            context("context-1", route_scope.clone(), 1_200, "exit-a"),
            UnixTime::from_secs(1_050),
        )
        .expect("insert");
    let old_flow = FlowId::new("flow-1").expect("valid");
    let binding = cache
        .begin_flow(&route_scope, old_flow.clone(), UnixTime::from_secs(1_100))
        .expect("pin old flow");
    assert_eq!(binding.exit_node_id.as_str(), "exit-a");

    assert!(cache.expire(UnixTime::from_secs(1_200)).is_empty());
    assert_eq!(
        cache.begin_flow(
            &route_scope,
            FlowId::new("flow-2").expect("valid"),
            UnixTime::from_secs(1_201)
        ),
        Err(RouteContextError::NoActiveContext)
    );
    assert_eq!(
        cache
            .flow_binding(&old_flow)
            .expect("still pinned")
            .exit_node_id,
        binding.exit_node_id
    );

    cache
        .insert_context(
            context("context-2", route_scope.clone(), 1_500, "exit-b"),
            UnixTime::from_secs(1_210),
        )
        .expect("new generation");
    let new_binding = cache
        .begin_flow(
            &route_scope,
            FlowId::new("flow-3").expect("valid"),
            UnixTime::from_secs(1_220),
        )
        .expect("new flow");
    assert_eq!(new_binding.exit_node_id.as_str(), "exit-b");

    let retired = cache
        .finish_flow(&old_flow, UnixTime::from_secs(1_230))
        .expect("finish")
        .expect("old generation now cleanable");
    assert_eq!(retired.route_context_id.as_str(), "context-1");
}

fn metrics(rtt: f64, progress: u64) -> PathMetrics {
    PathMetrics {
        smoothed_rtt_ms: rtt,
        rtt_variance_ms: 1.0,
        packet_loss_ratio: 0.01,
        delivery_rate_mbps: 100.0,
        loaded_rtt_ms: rtt + 5.0,
        bytes_in_flight: 1_000,
        last_progress_at: UnixTime::from_secs(progress),
        relay_reported_free: bandwidth(100),
        locally_estimated_free: bandwidth(80),
    }
}

#[test]
fn path_replacement_requires_stable_improvement_but_degradation_is_immediate() {
    let active = PathStatus::new(
        PathId::new(1).expect("valid"),
        PathState::Active,
        metrics(80.0, 1_000),
        UnixTime::from_secs(1_000),
    )
    .expect("valid status");
    let candidate = PathStatus::new(
        PathId::new(2).expect("valid"),
        PathState::Warm,
        metrics(20.0, 1_000),
        UnixTime::from_secs(1_000),
    )
    .expect("valid status");
    let mut hysteresis =
        ReplacementHysteresis::new(HysteresisPolicy::default()).expect("valid policy");
    assert_eq!(
        hysteresis
            .consider(&active, &candidate, UnixTime::from_secs(1_001))
            .expect("metrics"),
        ReplacementDecision::Observe {
            remaining_seconds: 15
        }
    );
    assert_eq!(
        hysteresis
            .consider(&active, &candidate, UnixTime::from_secs(1_016))
            .expect("metrics"),
        ReplacementDecision::Replace {
            reason: ReplacementReason::StableImprovement
        }
    );

    let degraded = PathStatus::new(
        PathId::new(3).expect("valid"),
        PathState::Degraded,
        metrics(80.0, 1_000),
        UnixTime::from_secs(1_000),
    )
    .expect("valid status");
    assert_eq!(
        hysteresis
            .consider(&degraded, &candidate, UnixTime::from_secs(1_017))
            .expect("metrics"),
        ReplacementDecision::Replace {
            reason: ReplacementReason::ActivePathDegraded
        }
    );
}

#[test]
fn route_context_capacity_retires_the_least_recently_used_unpinned_generation() {
    let scope_a = scope("opaque-origin-lru-a");
    let scope_b = scope("opaque-origin-lru-b");
    let scope_c = scope("opaque-origin-lru-c");
    let mut cache = RouteContextCache::new(2, 3_600).expect("valid cache");
    cache
        .insert_context(
            context("context-lru-a", scope_a.clone(), 1_500, "exit-a"),
            UnixTime::from_secs(1_050),
        )
        .expect("first context");
    cache
        .insert_context(
            context("context-lru-b", scope_b, 1_500, "exit-b"),
            UnixTime::from_secs(1_051),
        )
        .expect("second context");

    let flow = FlowId::new("flow-lru-a").expect("valid flow");
    cache
        .begin_flow(&scope_a, flow.clone(), UnixTime::from_secs(1_060))
        .expect("touch first context");
    assert!(
        cache
            .finish_flow(&flow, UnixTime::from_secs(1_061))
            .expect("finish flow")
            .is_none()
    );

    let outcome = cache
        .insert_context(
            context("context-lru-c", scope_c, 1_500, "exit-c"),
            UnixTime::from_secs(1_062),
        )
        .expect("LRU insertion");
    assert_eq!(outcome.retired.len(), 1);
    assert_eq!(
        outcome.retired[0].route_context_id.as_str(),
        "context-lru-b"
    );
    assert_eq!(cache.context_count(), 2);
}

#[test]
fn route_context_capacity_failure_is_atomic_when_every_generation_is_pinned() {
    let scope_a = scope("opaque-origin-pinned-a");
    let scope_b = scope("opaque-origin-pinned-b");
    let mut cache = RouteContextCache::new(1, 3_600).expect("valid cache");
    cache
        .insert_context(
            context("context-pinned-a", scope_a.clone(), 1_500, "exit-a"),
            UnixTime::from_secs(1_050),
        )
        .expect("first context");
    let flow = FlowId::new("flow-pinned-a").expect("valid flow");
    let original = cache
        .begin_flow(&scope_a, flow.clone(), UnixTime::from_secs(1_060))
        .expect("pin context");

    assert_eq!(
        cache.insert_context(
            context("context-pinned-b", scope_b, 1_500, "exit-b"),
            UnixTime::from_secs(1_061),
        ),
        Err(RouteContextError::AllContextsPinned)
    );
    assert_eq!(cache.context_count(), 1);
    assert_eq!(cache.flow_count(), 1);
    assert_eq!(cache.flow_binding(&flow), Some(&original));
}

#[test]
fn invalid_float_and_selection_policy_bounds_fail_closed() {
    let required = requirements(ServiceRole::Exit);
    for invalid in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.01, 1.01] {
        let mut value = candidate(1, ServiceRole::Exit, 10);
        value.evidence.uptime_score = invalid;
        assert_eq!(
            hard_filter(&value, &required),
            Err(HardFilterReason::InvalidLocalEvidence)
        );
    }

    let mut invalid_path = relay_path(1);
    invalid_path.unique_throughput_gain_ratio = f64::NAN;
    let mut rng = ChaCha8Rng::seed_from_u64(31);
    assert_eq!(
        select_relay_paths(
            &[invalid_path],
            &requirements(ServiceRole::Relay),
            RelaySelectionPolicy::default(),
            &mut rng,
        ),
        Err(SelectionError::InvalidPathEvidence)
    );

    for invalid_spread in [0.0, 1_001.0, f64::NAN, f64::INFINITY] {
        assert_eq!(
            select_relay_paths(
                &[relay_path(1), relay_path(2)],
                &requirements(ServiceRole::Relay),
                RelaySelectionPolicy {
                    active_paths: 2,
                    minimum_paths: 2,
                    maximum_paths: 8,
                    warm_backup_paths: 0,
                    maximum_rtt_spread_ms: invalid_spread,
                    ..RelaySelectionPolicy::default()
                },
                &mut rng,
            ),
            Err(SelectionError::InvalidPolicy)
        );
    }
}

#[test]
fn route_context_limits_and_transport_path_counts_fail_closed() {
    assert!(matches!(
        RouteContextCache::new(MAXIMUM_ROUTE_CONTEXTS + 1, MAXIMUM_CONTEXT_TTL_SECONDS),
        Err(RouteContextError::InvalidLimits)
    ));
    assert!(matches!(
        RouteContextCache::new(1, MAXIMUM_CONTEXT_TTL_SECONDS + 1),
        Err(RouteContextError::InvalidLimits)
    ));
    assert!(matches!(
        RouteContextCache::new_with_maximum_flows(
            1,
            MAXIMUM_CONTEXT_TTL_SECONDS,
            MAXIMUM_ACTIVE_FLOWS + 1,
        ),
        Err(RouteContextError::InvalidLimits)
    ));

    let mut cache = RouteContextCache::new(2, MAXIMUM_CONTEXT_TTL_SECONDS).expect("valid cache");
    let mut single_path_multipath = context(
        "context-single-multipath",
        scope("opaque-single-multipath"),
        1_500,
        "exit-a",
    );
    single_path_multipath.plan.active_relays.truncate(1);
    assert_eq!(
        cache.insert_context(single_path_multipath, UnixTime::from_secs(1_050)),
        Err(RouteContextError::InvalidTransportPathCount)
    );

    let mut multi_path_udp = context(
        "context-multi-udp",
        scope("opaque-multi-udp"),
        1_500,
        "exit-a",
    );
    multi_path_udp.scope.transport = Transport::UdpSinglePath;
    assert_eq!(
        cache.insert_context(multi_path_udp.clone(), UnixTime::from_secs(1_050)),
        Err(RouteContextError::InvalidTransportPathCount)
    );
    multi_path_udp.plan.active_relays.truncate(1);
    cache
        .insert_context(multi_path_udp, UnixTime::from_secs(1_050))
        .expect("exactly one UDP relay");
}

#[test]
fn established_flow_limit_and_backwards_time_fail_atomically() {
    let route_scope = scope("opaque-flow-limit");
    let mut cache = RouteContextCache::new_with_maximum_flows(1, MAXIMUM_CONTEXT_TTL_SECONDS, 1)
        .expect("small valid cache");
    cache
        .insert_context(
            context("context-flow-limit", route_scope.clone(), 1_500, "exit-a"),
            UnixTime::from_secs(1_050),
        )
        .expect("context");

    assert_eq!(
        cache.begin_flow(
            &route_scope,
            FlowId::new("flow-too-early").expect("valid"),
            UnixTime::from_secs(1_049),
        ),
        Err(RouteContextError::ClockMovedBackwards)
    );
    assert_eq!(cache.flow_count(), 0);

    let first = FlowId::new("flow-bounded-1").expect("valid");
    cache
        .begin_flow(&route_scope, first.clone(), UnixTime::from_secs(1_060))
        .expect("first flow");
    assert_eq!(
        cache.begin_flow(
            &route_scope,
            FlowId::new("flow-bounded-2").expect("valid"),
            UnixTime::from_secs(1_061),
        ),
        Err(RouteContextError::TooManyFlows)
    );
    assert_eq!(cache.flow_count(), 1);

    assert_eq!(
        cache.finish_flow(&first, UnixTime::from_secs(1_059)),
        Err(RouteContextError::ClockMovedBackwards)
    );
    assert!(cache.flow_binding(&first).is_some());
    cache
        .finish_flow(&first, UnixTime::from_secs(1_061))
        .expect("monotonic finish");
    assert_eq!(cache.flow_count(), 0);
}

#[test]
fn equal_lru_timestamps_have_a_deterministic_identifier_tiebreak() {
    let mut cache = RouteContextCache::new(2, MAXIMUM_CONTEXT_TTL_SECONDS).expect("valid cache");
    cache
        .insert_context(
            context("context-tie-b", scope("opaque-tie-b"), 1_500, "exit-b"),
            UnixTime::from_secs(1_050),
        )
        .expect("first");
    cache
        .insert_context(
            context("context-tie-a", scope("opaque-tie-a"), 1_500, "exit-a"),
            UnixTime::from_secs(1_050),
        )
        .expect("second");
    let outcome = cache
        .insert_context(
            context("context-tie-c", scope("opaque-tie-c"), 1_500, "exit-c"),
            UnixTime::from_secs(1_051),
        )
        .expect("deterministic LRU");
    assert_eq!(outcome.retired.len(), 1);
    assert_eq!(
        outcome.retired[0].route_context_id.as_str(),
        "context-tie-a"
    );
}

#[test]
fn path_observation_errors_do_not_partially_replace_metrics() {
    let mut dead = PathStatus::new(
        PathId::new(1).expect("valid"),
        PathState::Dead,
        metrics(80.0, 1_000),
        UnixTime::from_secs(1_000),
    )
    .expect("valid status");
    let before = dead.clone();
    let mut lossy = metrics(10.0, 1_001);
    lossy.packet_loss_ratio = 0.5;
    assert_eq!(
        dead.observe(
            lossy,
            UnixTime::from_secs(1_001),
            HysteresisPolicy::default(),
        ),
        Err(PathTransitionError::InvalidTransition {
            from: PathState::Dead,
            to: PathState::Degraded,
        })
    );
    assert_eq!(dead, before);

    let mut active = PathStatus::new(
        PathId::new(2).expect("valid"),
        PathState::Active,
        metrics(30.0, 1_000),
        UnixTime::from_secs(1_000),
    )
    .expect("valid status");
    let before = active.clone();
    assert_eq!(
        active.observe(
            metrics(20.0, 1_000),
            UnixTime::from_secs(999),
            HysteresisPolicy::default(),
        ),
        Err(PathTransitionError::ClockMovedBackwards)
    );
    assert_eq!(active, before);
}

#[test]
fn replacement_hysteresis_and_scheduler_penalties_are_bounded() {
    assert_eq!(
        metrics(20.0, 1_000).estimated_delivery_time_ms(0, 120_001.0, 0.0),
        Err(PathMetricsError::InvalidPenalty)
    );

    let active = PathStatus::new(
        PathId::new(1).expect("valid"),
        PathState::Active,
        metrics(80.0, 1_000),
        UnixTime::from_secs(1_000),
    )
    .expect("valid active");
    let mut hysteresis =
        ReplacementHysteresis::new(HysteresisPolicy::default()).expect("valid policy");
    for path_id in 2_u16..=66 {
        let candidate = PathStatus::new(
            PathId::new(path_id).expect("valid"),
            PathState::Warm,
            metrics(20.0, 1_000),
            UnixTime::from_secs(1_000),
        )
        .expect("valid candidate");
        assert!(matches!(
            hysteresis
                .consider(&active, &candidate, UnixTime::from_secs(1_001))
                .expect("valid comparison"),
            ReplacementDecision::Observe { .. }
        ));
        assert!(hysteresis.tracked_pair_count() <= MAXIMUM_HYSTERESIS_PAIRS);
    }
    assert_eq!(hysteresis.tracked_pair_count(), MAXIMUM_HYSTERESIS_PAIRS);

    let future_candidate = PathStatus::new(
        PathId::new(100).expect("valid"),
        PathState::Warm,
        metrics(20.0, 2_000),
        UnixTime::from_secs(1_000),
    )
    .expect("structurally valid candidate");
    assert_eq!(
        hysteresis.consider(&active, &future_candidate, UnixTime::from_secs(1_001)),
        Err(PathMetricsError::InvalidTimestamp)
    );
}
