# Transaction-layer state-machine simulation

Research only. This standalone Rust library operates on fictitious integer units
in one process. It is not a payment service, bank, ownership registry, production
ledger, or demonstrated distributed transaction protocol. It has no dependencies,
network, keys, external execution, filesystem persistence, or daemon hooks.

Run the focused checks without building the production workspace:

```sh
cargo test --offline --manifest-path research/transaction-layer/Cargo.toml
```

## What this experiment checks

- An explicit simulated debit authority authorises immutable transfer details.
  Reservation removes available units; commit credits the internal recipient.
- Identical operation IDs are idempotent during this process lifetime. Conflicting
  payloads fail without changing balances or the event log. A submission retry
  returns `AlreadyRecordedDoNotRetry`; it never authorises another external send.
- An external outcome can remain `OutboundUnknownPending`. Its reservation stays
  locked: timeout does not mean failure, refund, or permission to retry.
- Explicit simulated finality moves reserved units into a separate external
  accounting total. Those units are no longer locally spendable.
- A separately scoped correction appends a new event without erasing the
  original commit. At most one correction is admitted per original transfer.
  Only the recipient's remaining available units can be compensated; the result
  separately reports recovered units, shortfall and recovery outcome.
- If the recipient forwarded/split the units or reserved them for another
  operation, no downstream account is silently seized. A shortfall is not a
  transferable or legally enforceable claim. Further tracing/recovery is absent.
- A correction of an externally final transfer reports
  `ExternalFinalNotRecoverable`, zero recovered units, and the full shortfall.
  It does not claim that an external transfer was recalled or undone.
- Checked `u64` arithmetic and fixed account/operation/event bounds preserve
  `available + reserved/uncertain + externally final = initial supply`.
  Rejected operations are atomic in this single-process model.

## Deliberate limits

`SimulationAuthority` is freely constructible test input, not a verified grant or
an immune-system judgement. Its narrow operation scopes follow the existing core
private-storage rights pattern; this crate does not extend those grants or invent
new cryptography. All accounts use one fictitious unit; there are no currencies,
market prices, securities, fees, credit or newly minted supply.

The event sequence is append-only through this API but is **not durable or
tamper-evident**. A process restart loses the ledger and duplicate-ID protection.
Replication, consensus, authenticated rights, anti-replay across restarts,
external reconciliation, cancellation/release, legal ownership, downstream claim
recovery and crash-safe settlement remain unimplemented. An exhausted journal
refuses further mutations; recovery/compaction is not modeled. Passing these
tests establishes only the stated in-memory transitions and invariants.
