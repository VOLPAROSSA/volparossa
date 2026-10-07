# Transaction layer: implementation and research

[Documentation](../README.md) · [Bank application](https://github.com/VOLPAROSSA/volparossa-bank)

Requested on 2026-10-04. The Transaction-layer is required reusable functionality
for the core, not a payment requirement for network participation. Research and
test-value trials are implementation stages, not the final deliverable. No daemon
endpoint, real-money ledger, licensed financial service or external financial
adapter is active.

## Responsibility boundaries

The Bank application owns portfolio methodology, investment presentation and user
mandates. The core should own transfer authorization, reservations, replay and
double-spend prevention, transaction state, settlement adapters and correction
cases. Existing layers supply protected transport, authorized public information,
private storage and cooperative analysis. Financial records must not enter public
cache or shared training merely because they traverse VOLPAROSSA.

The confirmed portfolio rule is ROIC times FCF-yield with nonnegative inputs. Portfolio
weights do not establish prices, legal title or redemption guarantees. The Bank
[research document](https://github.com/VOLPAROSSA/volparossa-bank/blob/main/docs/RESEARCH.md)
compares Interledger/Open Payments, GNU Taler and governed BFT ledger protocols,
and records financial/legal boundaries. The next TEST-unit milestone selects
CometBFT for ordering, not for payment gateways or securities ownership. Neither
Kademlia nor signed advertisements supply financial consensus.

## Intended versioned interface

These are design operations, not callable APIs yet:

| Operation | Required result and boundary |
| --- | --- |
| Quote | Asset, units, fees, expiry and executable terms; not a promise to trade. |
| Authorize and reserve | Exact payer mandate and available funded balance; one reservation per idempotency key. |
| Submit | Bind immutable intent, policy epoch and settlement domain; never acknowledge receipt as final payment. |
| Status and reconcile | Distinguish reserved, internally committed, externally submitted, uncertain and externally final. |
| Cancel | Release only an uncommitted reservation; do not retry an uncertain external transfer under a new identifier. |
| Dispute and correct | Preserve the original entry, reference independent authority and append a funded compensating entry or unresolved shortfall. |

Use exact integer asset units, checked arithmetic and explicit rounding. Each
transfer must bind asset/instrument identity, quantity, payer/payee, authorization,
expiry, nonce, origin operation and settlement domain. Financial signing keys and
authorizations must be separate from routine network identity and model outputs.
The existing core cryptographic primitives can be reused only after a reviewed
wire contract; this design introduces no custom cryptography.

Before network deployment, choose and verify a consensus/membership mechanism
that prevents two conflicting spends, including partitions and malicious peers.
Off-line message custody can carry an intent, but cannot guarantee spendable
value before that intent is validated and committed. A peer count is not a proof
of independent economic control.

## Distributed ownership and external settlement

Record internal claims separately from enforceable securities ownership and
external cash. Evidence must identify the instrument, beneficiary, custody or
registration chain, rights and final settlement receipt. Issuers, brokers,
registrars and payment systems do not disappear because a network records a
claim. An external instruction without a reply stays uncertain until reconciled.
No automatic double submission or invented successful settlement is permitted.

Ownership-limit checks must aggregate applicable beneficial ownership and voting
rights, including reserved orders and known external positions. Rules vary by
jurisdiction and instrument; a limit is not a blanket exemption from obligations.
The system must not divide one person's interest among identities to conceal a
reportable holding. Unknown or stale ownership data requires reconciliation.

## Immune review and recovery

Agents can flag forged rights, double spending, suspicious patterns, coordinated
abuse and conflicting evidence. Keep financial data restricted to authorized
participants and case reviewers; ordinary peers do not get everyone's identity,
balance or transaction graph. Selective-disclosure and established proof systems
are research directions, not currently implemented privacy guarantees.

An automated signal is not a legal finding. Binding holds/corrections require
explicit authority, independent checks, bounded scope and applicable intervention
and contest rights. Models cannot approve their own seizure, enlarge reviewer
permissions or treat the virtue framework as authority to confiscate assets.

For split/forwarded transfers, track an outstanding recovery claim and protected
lineage rather than repeatedly crediting the original amount. Bound the total
recovery across descendants; do not treat every subsequent recipient as culpable.
Preserve all originals and append corrections. A recovery reserve, if selected,
must be funded and its costs/loss allocation explicit. External final transfers
need gateway/legal recovery or compensation; a shortfall remains visible until
funds actually return. Privacy, recoverability, availability and finality impose
real trade-offs, not a guarantee that every illegal payment can be unwound.

## Isolated prototype and implementation sequence

`research/transaction-layer` is a standalone, dependency-free Rust state-machine
experiment. It is deliberately outside the production Cargo workspace and has no
network, persistence, keys, signatures, real assets or daemon integration. Its
caller-supplied authority markers are test inputs, not authenticated permissions.
The experiment examines reservations, internal/external status, idempotency and
bounded compensating corrections. It is not a functioning distributed ledger.

```sh
cargo test --offline --manifest-path research/transaction-layer/Cargo.toml
```

The first durable core slice replaces caller-supplied authority markers and volatile state
with signed, explicitly fictitious-unit commands and durable local accounting:
reserve, commit, cancel, inspect and safely retry after restart. A local store is
one building block, **not financial consensus**. It must not let two independent
copies of the database each claim authority over the same spendable balance.

### Durable test-unit core

`crates/volparossa-transaction` provides the local `Store` and `SignedCommand` API.
Accounts are explicitly initialized with separate financial test public keys and
an immutable initial supply. The unit is fixed to `volparossa.test.unit.v1`;
there is no configurable currency, security, later mint or financial adapter.

Each canonical signed command binds its ledger, payer, exact operation, amount
or reservation, validity interval and nonce. Reserving removes available units;
committing credits the original recipient; cancelling returns only an uncommitted
reservation. SQLite records the change, original signed bytes and historical
receipt in the same durable transaction. An identical accepted retry returns its
original receipt, including after expiry; it does not debit again or imply that
the receipt's historical reservation state is still current.

Applications can use `Store::inspect` to verify stored signed command terms and
payer enrollment before retrying, and `ledger_id` to bind their private intent
record to the opened ledger. Inspection does not check execution-time validity,
balances or reservation state and cannot authorize a mutation; `apply` still
performs those checks. This also lets an application inspect an expired original
command while reconciling its historical receipt.

This is **owner-local** storage and authorization, with a private directory and
database. File permissions are not encryption at rest or protection from the
device administrator. Neither a copied database nor a signature establishes
distributed finality. No network service, ordinary participation setting or
agent request activates these accounts. Corrections, external outcomes and
private financial review are not yet implemented in this durable API.

The offline example exercises signed reserve/commit/cancel, reopening the store,
expired exact retries and rejection of cancellation after commit. Supply a new
absolute directory whose parent already exists; existing stores are never adopted:

```sh
cargo test --locked --offline -p volparossa-transaction
cargo run --locked --offline -p volparossa-transaction --example durable_transfer -- /absolute/path/to/new-test-ledger
```

The example retains only its private test database. Its ephemeral test keys are
not saved, so it is not a wallet setup or a way to continue making transfers.
Process-crash checks are separate tests; ordinary close/reopen is not crash proof.

### Ordered application foundation

The new `OrderedStore` API prepares the Rust application for replicated execution;
it is not a network service or consensus engine. Its database mode and versioned
signature domain are separate from owner-local `Store`. Genesis binds an explicit
authority identifier, sorted initial accounts and agreed time into the ledger ID.
The existing local API and Bank integration remain compatible.

`stage` executes up to 64 commands and 64 KiB of command bytes in memory. It
returns provisional results and a logical state hash without changing the durable
database, balances or historical receipts. Ordinary command rejections roll back
their individual changes; storage failures abort execution. `commit` rechecks the
unchanged base, reruns the same commands at the agreed timestamp and atomically
persists the transitions and checkpoint only if results and hash match. A stale
writer cannot overwrite another committed block. `info` exposes committed state.

Twelve ordered-executor tests and all ten existing local-store tests pass. They
include real process kills at staging, before commit and after commit; rollback
of a two-command block when the second command encounters a database error;
exact replay; mode/domain isolation; timestamp bounds; and detection of altered
checkpoints, balances and old replay records. Two independent local stores agree
when given the same input order. That test supplies the order itself and therefore
does not prove distributed agreement. These application-level checks do not
replace the multi-validator fixture below.

### Private ABCI adapter

`crates/volparossa-transaction-abci` connects the ordered store to the official
CometBFT 0.40 ABCI socket protocol. Its only listener is an owner-private Unix
socket under a canonical mode-0700 directory; bounded frames and four connections
share one serialized application. No public RPC, real funds or automatic financial
participation is enabled by starting this adapter.

An explicit TEST genesis binds the chain, four equally weighted validators,
consensus parameters, initial accounts and agreed time. CheckTx and proposal
inspection do not mutate balances. FinalizeBlock stages results; Commit persists
them. Info reports committed state after restart. Queries expose committed TEST
balances or receipts, not cryptographic finality, and reject requested proofs or
unsupported historical heights. No snapshot import or validator-set update is
pretended to work.

Thirteen adapter tests cover real Unix framing and four connections, cross-connection
state visibility, lifecycle/replay, fatal shutdown, malformed input, proof rejection
and actual CLI signing. All twenty-two core tests also pass. These local checks do
not establish interoperability with a running CometBFT process. The exact schema,
import and license inventory is in [the vendored source record](../../third_party/cometbft/README.md).
Builds use the system Protobuf compiler and the locked Rust generator; they fetch
no schema at build time. Debian development prerequisites already include `protoc`.

### Distributed TEST execution

The next implementation target is four independently persisted validators using
**CometBFT v0.40.0**, pinned to
`0880b4d378f347ab16e54ec677ff50d803f37d62`, as a separate ordering process.
The Rust application retains VOLPAROSSA's signed TEST-unit rules. This does not
introduce a participation token, fees, Cosmos SDK or a new consensus algorithm.
CometBFT's [Apache-2.0 license](https://github.com/cometbft/cometbft/blob/0880b4d378f347ab16e54ec677ff50d803f37d62/LICENSE)
and [Go 1.25 toolchain declaration](https://github.com/cometbft/cometbft/blob/0880b4d378f347ab16e54ec677ff50d803f37d62/go.mod)
must accompany the guest-only source build; no unchecked binary is substituted.

The integration boundary is the official
[ABCI Protobuf socket interface](https://github.com/cometbft/cometbft/blob/0880b4d378f347ab16e54ec677ff50d803f37d62/proto/tendermint/abci/types.proto),
with private local sockets and bounded frames. ABCI is the interface between the
ordering process and the transaction application. Proposal checks must not change
committed balances. `FinalizeBlock` stages execution and returns deterministic
results; only `Commit` persists state. After restart, `Info` reports the last
committed height and application hash. These boundaries are required for
[CometBFT crash recovery](https://github.com/cometbft/cometbft/blob/0880b4d378f347ab16e54ec677ff50d803f37d62/spec/abci/abci%2B%2B_app_requirements.md#crash-recovery).

Ordered execution must use the agreed block timestamp, not each validator's wall
clock. Its state hash must cover sorted logical accounts, reservations, permanent
replay records and the chain/genesis binding, not SQLite file bytes. Local I/O
failure stops execution; it must not turn into a different transaction decision
on one validator. Owner-local `Store::apply` must not bypass ordered mode.

The disposable fixture must demonstrate:

- Competing spends submitted to different validators cannot both succeed; honest
  replicas converge and conserve the original supply.
- A three-node majority can progress during a 3–1 partition; an isolated validator
  cannot. A 2–2 split cannot finalize new transactions, and healing restores convergence.
- Retrying the same signed bytes through another validator, including after expiry,
  cannot produce another debit.
- Crashes before and after application commit preserve identical results on replay.
- A validator that actively equivocates cannot cause conflicting honest outcomes.
  Adapt the existing [upstream Byzantine harness](https://github.com/cometbft/cometbft/blob/0880b4d378f347ab16e54ec677ff50d803f37d62/consensus/byzantine_test.go)
  to the real Rust application; a killed process or upstream KVStore test alone is
  not this evidence.

Use fixed, explicitly configured TEST membership and synthetic data. Validators
can read replicated commands and account relationships; this fixture does not
prove confidential financial processing, open membership or protected overlay
transport. A response from one RPC endpoint is not independently verified finality.
The client still needs trusted validator membership and verified commit/header
binding. The `transaction-abci` disposable VM scenario now prepares this
four-validator interoperability trial within the existing four-CPU, 4 GiB RAM,
16 GiB disk envelope. It source-builds exact CometBFT with a separately hash-checked
Go compiler; no engine binary or private keys are exported. Five isolated guest
namespaces support genuine 3–1 and 2–2 partition rules without changing parent
routes, DNS or firewall. Acceptance requires live packet-drop observations,
rejoined state, original receipts, byte-identical retries in newly committed
blocks and complete owned-resource cleanup. Only bounded receipts are exported.

No distributed acceptance result is yet established: the fixture has not run.
Post-commit restart is not a pre-commit crash or actively equivocating validator;
those cases and independent client finality verification remain separate work.

### Bank integration and remaining financial functions

Bank's [first core integration](https://github.com/VOLPAROSSA/volparossa-bank/pull/4)
retains an immutable signed TEST intent before execution, reconciles the core's
receipt and safely retries after a crash. It uses the owner-local core, not a
second Bank ledger or distributed settlement. Ordered submission and verified
finality must extend this same intent lifecycle.

Gateway sandboxes, private financial review, decentrally established prices and
independently authorized corrections remain separate implementation work.
ILPv4 can connect ledgers but does not supply their underlying settlement or
membership: [ILPv4 specification](https://interledger.org/developers/rfcs/interledger-protocol/).
Real money remains disabled until legal classification, custody, gateway authority
and safeguards are established. General network membership never activates
financial services.
