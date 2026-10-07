// Included in discovery::tests to reuse its real signed-ingestion fixtures, not fabricated caps.
mod route_readiness_tests {
    use super::*;
    use volparossa_local_control::{RouteReadinessObservation, RouteReadinessOutcome};

    fn parameters() -> ClientPreselectionParameters {
        ClientPreselectionParameters::new(
            Transport::TcpMptcp,
            ObservationAddressFamily::Ipv4,
            Bandwidth::new(8, 8).unwrap(),
            Bandwidth::new(32, 32).unwrap(),
            Bandwidth::new(32, 32).unwrap(),
            2,
            2,
            16,
        )
    }

    async fn ready_fixture(capacities: &[u64]) -> RuntimeFixture {
        let mut fixture = fixture(test_client_roles());
        let now = unix_millis();
        let mut controls = Vec::new();
        for index in 0..3 {
            let identity = Identity::generate();
            assert!(
                ingest_direct_snapshot_advertisement_with_capabilities(
                    &mut fixture,
                    &identity,
                    RolesConfig {
                        client: false,
                        relay: true,
                        exit: false
                    },
                    1,
                    generate_nonce(),
                    now,
                    PreselectionTestCapabilities::all_on_network(40 + index)
                )
                .await
                .is_some()
            );
            controls.push(fixture.runtime.direct_relays[identity.peer_id()].clone());
        }
        for (index, capacity) in capacities.iter().enumerate() {
            let identity = Identity::generate();
            let seed = service_advertisement_with_capabilities(
                &identity,
                RolesConfig {
                    client: false,
                    relay: false,
                    exit: true,
                },
                &fixture.policy,
                1,
                generate_nonce(),
                now,
                &fixture.directory,
                PreselectionTestCapabilities::all_on_network(50 + u8::try_from(index).unwrap()),
            );
            let mut replay = ReplayCache::new(1).unwrap();
            let mut wire = verify_control_message::<WireAdvertisement>(
                seed.signed_envelope(),
                now,
                TimePolicy::default(),
                &mut replay,
            )
            .unwrap()
            .into_message();
            let limits = wire.capacity.as_mut().unwrap();
            limits.operator_exit_limit_up_mbps = *capacity;
            limits.operator_exit_limit_down_mbps = *capacity;
            limits.estimated_free_up_mbps = *capacity;
            limits.estimated_free_down_mbps = *capacity;
            let response = AdvertisementResponse::new(sign_with_identity(
                &wire,
                &identity,
                wire.measured_at_ms,
                wire.expires_at_ms,
                generate_nonce(),
            ))
            .unwrap();
            let deadline = now + 20_000;
            fixture
                .runtime
                .mark_forwarded_exit_target(*identity.peer_id(), deadline);
            assert!(
                fixture
                    .runtime
                    .ingest_advertisement(
                        *identity.peer_id(),
                        response,
                        forwarded_provenance(&controls[0], &identity, deadline),
                        &fixture.state
                    )
                    .await
                    .is_some()
            );
        }
        fixture
    }

    async fn observe(
        fixture: &mut RuntimeFixture,
    ) -> Result<RouteReadinessObservation, RouteReadinessError> {
        let (reply, response) = oneshot::channel();
        fixture
            .runtime
            .handle_command(
                DiscoveryCommand::ObserveRouteReadiness {
                    parameters: parameters(),
                    reply,
                },
                &fixture.state,
            )
            .await;
        response.await.unwrap()
    }

    #[tokio::test]
    async fn route_readiness_actual_signed_capacity_one_cannot_substitute_for_thirty_two() {
        let mut only_small = Box::pin(ready_fixture(&[1])).await;
        assert_eq!(
            observe(&mut only_small).await.unwrap().outcome,
            RouteReadinessOutcome::NoEligibleExitPair as i32
        );
        let mut both = Box::pin(ready_fixture(&[1, 32])).await;
        for _ in 0..8 {
            assert_eq!(
                observe(&mut both).await.unwrap().outcome,
                RouteReadinessOutcome::EligibleAdvertisementSlate as i32
            );
        }
    }

    #[tokio::test]
    async fn route_readiness_distinct_live_exit_identities_are_not_hardpicked() {
        let mut fixture = Box::pin(ready_fixture(&[32, 32])).await;
        let caps = fixture.runtime.forwarded_exits.clone();
        assert_eq!(caps.len(), 2);
        for (key, value) in &caps {
            fixture.runtime.forwarded_exits.clear();
            fixture.runtime.forwarded_exits.insert(*key, value.clone());
            assert_eq!(
                observe(&mut fixture).await.unwrap().outcome,
                RouteReadinessOutcome::EligibleAdvertisementSlate as i32
            );
        }
    }

    #[tokio::test]
    async fn route_readiness_signed_cache_without_live_forwarding_lineage_is_incomplete() {
        let mut fixture = Box::pin(ready_fixture(&[32])).await;
        let now = UnixTime::from_secs(unix_millis() / 1000);
        let stored = fixture.runtime.store.load_candidates(now, 16).unwrap();
        assert_eq!(stored.len(), 4);
        for peer in &stored {
            assert!(revalidate_stored_advertisement(peer, unix_millis()).is_ok());
        }
        fixture.runtime.forwarded_exits.clear();
        assert_eq!(
            observe(&mut fixture).await.unwrap().outcome,
            RouteReadinessOutcome::IncompleteSnapshot as i32
        );
        assert_eq!(
            fixture.runtime.store.load_candidates(now, 16).unwrap(),
            stored
        );
    }

    #[tokio::test]
    async fn route_readiness_expired_changed_control_and_policy_all_fail_closed() {
        for mutation in 0..4 {
            let mut fixture = Box::pin(ready_fixture(&[32])).await;
            match mutation {
                0 => {
                    fixture
                        .runtime
                        .forwarded_exits
                        .values_mut()
                        .next()
                        .unwrap()
                        .expires_at_ms = 1;
                }
                1 => {
                    fixture
                        .runtime
                        .forwarded_exits
                        .values_mut()
                        .next()
                        .unwrap()
                        .control_relay_advertisement_sequence += 1;
                }
                2 => {
                    fixture
                        .runtime
                        .forwarded_exits
                        .values_mut()
                        .next()
                        .unwrap()
                        .exit_advertisement_payload_hash =
                        AdvertisementPayloadHash::for_test([99; 32]);
                }
                _ => fixture.state.write().await.set_policy(None),
            }
            let result = observe(&mut fixture).await;
            if mutation == 3 {
                assert_eq!(result.unwrap_err(), RouteReadinessError::PolicyUnavailable);
            } else {
                assert_ne!(
                    result.unwrap().outcome,
                    RouteReadinessOutcome::EligibleAdvertisementSlate as i32
                );
            }
        }
    }

    #[tokio::test]
    async fn route_readiness_repeated_observations_leave_actor_store_and_dispatch_ownership_unchanged()
     {
        let mut fixture = Box::pin(ready_fixture(&[32])).await;
        let direct = fixture.runtime.direct_relays.clone();
        let forwarded = fixture.runtime.forwarded_exits.clone();
        let now = UnixTime::from_secs(unix_millis() / 1000);
        let stored = fixture.runtime.store.load_candidates(now, 16).unwrap();
        let status = fixture.state.read().await.status();
        let logs = fixture.state.read().await.logs(1000);
        for _ in 0..8 {
            assert_eq!(
                observe(&mut fixture).await.unwrap().outcome,
                RouteReadinessOutcome::EligibleAdvertisementSlate as i32
            );
            assert!(matches!(
                fixture.runtime.client_preselection,
                ClientPreselectionOwner::Available(_)
            ));
            assert!(
                !fixture
                    .runtime
                    .service
                    .client_preselection_slot_active_for_test()
            );
            assert!(fixture.runtime.pending_client_forwards.is_empty());
            assert!(fixture.runtime.pending_relay_forwards.is_empty());
            assert!(fixture.runtime.pending_datapath.is_empty());
        }
        assert_eq!(fixture.runtime.direct_relays, direct);
        assert_eq!(fixture.runtime.forwarded_exits, forwarded);
        assert_eq!(
            fixture.runtime.store.load_candidates(now, 16).unwrap(),
            stored
        );
        assert_eq!(fixture.state.read().await.status(), status);
        assert_eq!(fixture.state.read().await.logs(1000), logs);
    }

    #[tokio::test]
    async fn route_readiness_requires_live_other_relays_and_exact_accepted_exit_record() {
        for mutation in 0..2 {
            let mut fixture = Box::pin(ready_fixture(&[32])).await;
            let exit = fixture
                .runtime
                .forwarded_exits
                .values()
                .next()
                .unwrap()
                .clone();
            if mutation == 0 {
                // An eligible signed exit and its control relay are not enough:
                // the unchanged sampler also needs two other suitable relays.
                fixture
                    .runtime
                    .direct_relays
                    .retain(|peer, _| *peer == exit.control_relay_peer_id);
            } else {
                fixture
                    .runtime
                    .accepted_advertisements
                    .remove(&exit.exit_node_id);
            }
            let direct = fixture.runtime.direct_relays.clone();
            let forwarded = fixture.runtime.forwarded_exits.clone();
            assert_ne!(
                observe(&mut fixture).await.unwrap().outcome,
                RouteReadinessOutcome::EligibleAdvertisementSlate as i32
            );
            assert_eq!(fixture.runtime.direct_relays, direct);
            assert_eq!(fixture.runtime.forwarded_exits, forwarded);
        }
    }

    #[tokio::test]
    async fn route_readiness_role_store_and_profile_errors_are_not_static_success() {
        let mut disabled = fixture(RolesConfig::default());
        assert_eq!(
            observe(&mut disabled).await.unwrap_err(),
            RouteReadinessError::ClientDisabled
        );
        assert_eq!(disabled.runtime.route_snapshot_build_attempts.get(), 0);
        let mut fixture = Box::pin(ready_fixture(&[32])).await;
        fixture.runtime.route_snapshot_store_failure = true;
        assert_eq!(
            observe(&mut fixture).await.unwrap_err(),
            RouteReadinessError::StoreUnavailable
        );
        let mut invalid = parameters();
        invalid.maximum_other_relays = 0;
        let now = unix_millis();
        let state = fixture.state.read().await;
        assert_eq!(
            fixture
                .runtime
                .observe_advertisement_slate(&invalid, now, &state.policy_snapshot(now))
                .unwrap_err(),
            RouteReadinessError::InvalidProfile
        );
        assert!(matches!(
            fixture.runtime.client_preselection,
            ClientPreselectionOwner::Available(_)
        ));
    }

    #[tokio::test]
    async fn route_readiness_dropped_caller_and_shutdown_do_not_start_observation() {
        let mut fixture = Box::pin(ready_fixture(&[32])).await;
        let before = fixture.runtime.route_snapshot_build_attempts.get();
        let (reply, response) = oneshot::channel();
        drop(response);
        fixture
            .runtime
            .handle_command(
                DiscoveryCommand::ObserveRouteReadiness {
                    parameters: parameters(),
                    reply,
                },
                &fixture.state,
            )
            .await;
        assert_eq!(fixture.runtime.route_snapshot_build_attempts.get(), before);
        let (reply, response) = oneshot::channel();
        fixture
            .control
            .sender
            .try_send(DiscoveryCommand::ObserveRouteReadiness {
                parameters: parameters(),
                reply,
            })
            .unwrap();
        fixture.runtime.reject_queued_outbound_commands();
        assert_eq!(
            response.await.unwrap().unwrap_err(),
            RouteReadinessError::Closed
        );
        assert_eq!(fixture.runtime.route_snapshot_build_attempts.get(), before);
    }

    #[test]
    fn route_readiness_product_path_cannot_acquire_or_dispatch_a_route() {
        let observer = include_str!("../route_readiness.rs");
        for forbidden in [
            "purge_completed",
            "begin_client_preselection(",
            "helper.",
            "PreselectionAttemptGate",
            "set_roles(",
            "state.write()",
            "reserve(",
        ] {
            assert!(
                !observer.contains(forbidden),
                "unexpected side effect: {forbidden}"
            );
        }
        assert!(observer.contains("build_route_candidate_snapshot_with_scope("));
        assert!(observer.contains("narrow_route_candidate_snapshot(snapshot, scope)"));
    }
}
