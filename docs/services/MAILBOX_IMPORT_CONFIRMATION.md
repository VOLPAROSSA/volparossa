# Mailbox fetch and consumer import confirmation

Status: implemented candidate; one canonical receipt test and three actual CLI/local-service
tests pass, including retained custody, rejected confirmation, partial ACK and restart/retry.
These local services use real signatures and durable stores, not a live overlay or native
mail application. This is a reusable
local handoff for mail/chat adapters, not a Thunderbird or Signal integration, Signal
Protocol implementation, delivery guarantee or native application-import proof.

The existing `content mailbox receive` retains its compatibility behavior: authenticate,
decrypt to a fresh private directory, persist the output and acknowledge both providers.
Applications needing to commit their own database first must instead use the new split:

```text
content mailbox fetch --invitation INVITATION --output-dir NEW_DIRECTORY
    --identity OWNER_IDENTITY --passphrase-file PASSPHRASE_FILE

content mailbox confirm-import --pending NEW_DIRECTORY/MESSAGE_ID/pending.pb
    --import-token-file NEW_DIRECTORY/MESSAGE_ID/import-token
    --imported-sha256 DIGEST_OF_DURABLY_IMPORTED_BYTES
    --identity OWNER_IDENTITY --passphrase-file PASSPHRASE_FILE
```

Fetching performs the existing authenticated inbox/Get operations and decryption, but
does **not** send any ACK. A bounded 0700 handoff directory holds each message's 0600
payload, fresh 32-byte confirmation token and owner-signed `pending.pb`. The signed
receipt is persisted last, after payload/token and their directory entries are synced.
It uses the existing canonical mailbox Protobuf envelope/signing domain and distinct
message type 5. It binds the exact original invitation (owner, sender, recipient and
both providers), original signed message, payload digest/length and token digest.
It never extends the original grant/message expiration. Message count and aggregate
fetched bytes remain bounded by the original invitation and explicit cache-byte quota.

The application verifies/imports the entire payload, persists its own deduplication and
message state, then supplies the digest of those exact imported bytes and the private
token file. Neither token bytes nor payload are printed. Confirmation rejects wrong
owner, token, digest, original signatures, substituted local payload, unsafe local files
or expired authority before any provider request. It then uses the original fresh-
challenge authenticated ACK protocol, preserving exact message identity.

Every correlated provider ACK is recorded durably in its own bounded private progress
file. Partial failure retains the payload, token, receipt and earlier observations.
Restart/retry repeats the exact ACK idempotently; it never fetches a replacement message,
changes identity or treats a local progress file as authority to skip authentication.
`confirmed.json` is written only after both providers acknowledge. Local handoff files
remain under owner control; remote ACK does not prove erasure of untrusted copies.

Three states must stay distinct:

- **Provider custody:** encrypted bytes were accepted by a provider, not by the recipient app.
- **Fetched:** authenticated bytes are available locally; provider custody remains intact.
- **Consumer-confirmed:** the owning consumer attests durable import and both provider ACKs
  completed. The core cannot independently prove a native application's database commit.

An adapter needs authenticated address/device binding, real application
encryption, durable per-device outboxes, deduplication, retention renewal/replacement and
visible pending/failure states. Offline recipients are expected and must not alone trigger
ordinary mail/Signal-server fallback. Signal integrations must preserve native
Signal sessions and disappearing-message policy: this handoff cannot extend app retention
or acknowledge before its real decrypt/import transaction. Calling/video media is not a
store-and-forward mailbox feature. No message loss or exactly-once delivery is guaranteed
across arbitrary peers and stock mail servers.

## Testing an external consumer locally

The `mailbox-provider-pair` test executable runs two independently keyed
`MailboxService` instances with separate stores in one process. It uses the
same signed local-stream protocol fixture as the CLI integration tests. Build
it and the ordinary CLI with the locked workspace dependencies.

```sh
cargo build --locked -p volparossa --example mailbox-provider-pair --bin volparossa
```

Mount `target/debug/examples/mailbox-provider-pair` and `target/debug/volparossa`
as sibling executables inside a disposable nonroot, loopback-only namespace.
Start `mailbox-provider-pair <private-directory>` with an empty, owned `0700`
directory at a canonical absolute path. Keep its stdin pipe open. The helper
creates two test identities and uses the CLI to invite and enroll both mailbox
owners at both providers. Once `ready` appears, `a/core.json` and `b/core.json`
contain the CLI path, socket, identity, passphrase file, send and receive
invitation paths and the recipient's public key. Each `grants.json` contains
`sendGrant` and `receiveGrant`, the SHA-256 of the respective original signed
invitations, and `expires`, a Unix time in milliseconds before either expires.
The paired application authenticates and imports this private configuration.

Closing stdin or sending SIGTERM retires the fixture's private provider state
and published handles. The fixture lifetime is bounded to 15 minutes. The
caller retains ownership of application handoffs and the surrounding namespace.
Protected network routing and durable native application import require their
own end-to-end trials.

## Native Signal Desktop on the protected route

On 19 November 2026, two standalone Signal Desktops, each with its own SQLCipher
profile, exchanged a paired message through two signed mailbox providers in the
Debian 13 KVM topology. Both applications used one protected Core client. The
receiver was offline when the sender deposited the message. With the sender offline,
the receiver fetched it twice, imported it into Signal, and confirmed custody after
that transaction. The native row survived a restart. Replaying the import preserved the
Signal ratchet, the restarted sender displayed Delivered, and both provider inboxes
were empty. Signal used its ordinary simulated messaging service before pairing and
made zero stock submissions for the paired message.

The application phase recorded 32 completed Exit MPTCP/TLS exchanges and 32 exact
provider lookups. All five guest traffic captures passed. The before/after host
snapshots matched and cleanup left zero owned objects. This trial covers two
application identities behind a single Core client. Independent client machines,
other Signal platforms and ordinary Internet peers remain outside this measurement.

The [original guest report](../development/evidence/signal-mailbox-44538844389/signal-mailbox-smoke.json)
comes from [run 44538844389](https://github.com/VOLPAROSSA/volparossa/actions/runs/44538844389)
at Core `59c6d6d2` and Chat `7fa73f61`. GitHub artifact 14539906183 contained
18 files, 27,028 bytes, SHA-256 `e80da35af2d2cb95b084b6c6d369f0233fa743e8312d3542d8fd4a9750a1bef2`.

## Testing paired Mail over a protected route

The `paired-mail` topology scenario runs the ordinary Signal Mail sender, Core
mailbox CLI and Stalwart owner importer. A UTF-8 multipart message is deposited
at both signed providers while the recipient Mail process is offline. The
topology disconnects the sender route, reopens one persistent provider store,
and selects a fresh recipient route behind the same Client. The recipient has
only its own keys and its new process has only loopback and the Core socket.

The guest checks for zero provider acknowledgements before import, compares
Stalwart’s exact raw MIME readback to the sent bytes, binds two signed
acknowledgements to the same message and checks that a new fetch is empty.
It saves the two route selections, five-role privacy captures, provider traffic,
host snapshots and native artifact hashes. The app profiles, passwords, packets
and database stay in the disposable guest.

Select `paired-mail` in the Debian alpha topology workflow. The source pin
identifies the original Mail QA archive, Stalwart build, Node and Linux
libsignal binary. The producing Mail workflow retains the QA runtime for
14 days. The local VM entry point also accepts a retained, verified transfer
through `--paired-mail-bundle`.

On 19 November 2026, the Debian 13 twelve-node guest delivered the 90,139-byte
message on two successive MPTCP routes. Sender custody took six Exit TLS flows
and six exact provider lookups. After the sender exited and the second provider
reopened the same store, pickup, native import, confirmation and the final empty
fetch took seven flows and seven lookups. All ten physical-role captures passed.
The two original Ed25519 acknowledgements verified against the independently
selected provider keys. The host snapshots matched and cleanup found zero
owned objects. The applications shared one Client agent. The separate native
Mail producer exercised the ordinary Thunderbird Inbox.

Core revision `b9c01e976b49d94af4b88c033a08f15ca032178f` used Mail revision
`30cc423a234d0452f11d4475c94d11dee9552407`. The original 27-file guest ZIP had
SHA-256 `3f4cc66aeee04d1ad992eb5ac7eaba36fc561b142a9fdb4b0b99d93ec87c53e2`.
[Guest run](https://github.com/VOLPAROSSA/volparossa/actions/runs/44553382181) ·
[Original report](../development/evidence/paired-mail-44553382181/paired-mail-smoke.json) ·
[Native Mail producer](https://github.com/VOLPAROSSA/volparossa-mail/actions/runs/44547309790)

### Two independent Mail clients

The `paired-mail-peers` scenario gives each correspondent a separate Core
agent and private profile. R4 runs the recipient. Only R3 and R5 serve the
mailbox at the Exit. On `77c71187` the recipient enrolled with both providers,
then the guest failed to read the Exit’s private event log. The enrollment
captures also recorded three UDP/41000 packets from the Exit to R4 over the
physical link used by other fixtures to serve content. [Original trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44564630267)

The guest observer reads the service logs. Before starting the agents the
fixture verifies that the recipient and Exit cannot route directly to each
other’s public or link address. Both ends of the physical link stay under
capture. This scenario tests delivery with both clients isolated from the
Exit. Discovery behavior between directly reachable peers requires a separate
measurement.

On `ab17c375` the sender deposited 91,992 encrypted bytes at both custodians
while the recipient was offline. It reopened the original send after removing
the input. The restarted recipient received `NO_ELIGIBLE_PATHS` during route
selection. The guest exited before Stalwart import, cleaned up its objects and
matched the host digests. Each phase now waits for the three fixture relay
advertisements before calling the route selector. A timeout identifies
incomplete discovery. [Hosted trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/45409332468)
