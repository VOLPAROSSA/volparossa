## Change

<!-- What changes, and why is this the smallest useful slice? -->

## Invariant and failure mode

<!-- Which security, privacy, routing, or resource invariant is preserved or strengthened? -->

## Scope and non-goals

<!-- State what is deliberately not implemented or claimed. -->

## Verification

<!-- List focused tests and any machine-readable evidence. Never attach secrets or private traffic. -->

- [ ] Focused tests cover the success and fail-closed paths.
- [ ] `cargo fmt --all -- --check` passes.
- [ ] Strict Clippy and the relevant workspace tests pass.
- [ ] Dependency, license, or third-party provenance checks pass when applicable.

## Safety and truthfulness

- [ ] Normal traffic still follows `client -> exactly one relay -> exit` on every path; parallel paths use different relays and the same exit.
- [ ] No ordinary TCP or single-path QUIC is described as multipath.
- [ ] No production key, account, private browsing metadata, telemetry, or hidden network action is added.
- [ ] No test changes the development host's routes, DNS, firewall, interfaces, sysctls, or VPN.
- [ ] External inputs, allocations, queues, sessions, and timeouts remain bounded and fail closed.
- [ ] New third-party inputs are pinned and their provenance and licenses are recorded, or none were added.

## Documentation and status

- [ ] Documentation reflects the implemented behaviour and remaining limitations.
- [ ] `docs/IMPLEMENTATION_STATUS.md` changed only where passing evidence supports it, or did not need to change.
