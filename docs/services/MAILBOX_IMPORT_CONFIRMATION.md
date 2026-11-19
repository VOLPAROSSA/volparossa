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

Mail and chat adapters still need authenticated address/device binding, real application
encryption, durable per-device outboxes, deduplication, retention renewal/replacement and
visible pending/failure states. Offline recipients are expected and must not alone trigger
ordinary mail/Signal-server fallback. Future Signal integration must preserve native
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
