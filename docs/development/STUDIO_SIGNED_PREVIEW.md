# Explicit local signed site preview

`volparossa content site preview` opens an operator-selected local site bundle after validating the original signed manifest against an independently trusted publisher key and a reviewed SHA-256 digest:

```sh
volparossa content site preview \
  --input site.bundle \
  --manifest publication.pb \
  --publisher-key TRUSTED_ED25519_PUBLIC_KEY_HEX \
  --expected-input-sha256 REVIEWED_BUNDLE_SHA256 \
  --lifetime-seconds 60
```

Both inputs must be owned regular single-link files with mode 0600. Each is opened once without following symlinks and read through a bounded, stable descriptor. The manifest is bounded to 64 KiB and the bundle to the existing 256 MiB content limit. Canonical encoding, signature, version, original expiry, site content type, signed length, object and chunk digests, reviewed digest and site bundle encoding are checked before a listener is created. No identity is unlocked and no signing or daemon operation occurs.

The existing loopback HTTP server enforces its request, host, path, method and security header rules. The selected lifetime covers preparation and serving; the original signed publication expiry also applies. SIGINT/SIGTERM cancel preparation and join its worker before returning, or stop the listener. A blocked kernel operation or runtime destruction is not proof of completed cleanup.

The distinct `local_site_preview_ready` and `local_site_preview_closed` reports identify `local_signed_bundle`. A verified signature and reviewed digest do not authenticate an HTTPS origin, establish publisher name ownership or prove the globally latest revision. This command performs no named lookup or network retrieval, changes no revision floor, grants no Internet policy permission and creates no private named-download spool. Existing `content site open` keeps its named retrieval, role and helper requirements.

## Preparation for native review

An explicit `volparossa content site pack --directory export --output site.bundle --review-receipt` returns a separate schema-1 `site_pack_preparation` receipt. The normal pack receipt stays unchanged when the flag is absent. The review receipt binds the exact bundle SHA-256 and byte count to a canonical inventory of asset paths, content types, sizes and SHA-256 digests. It derives these values from the same immutable assets and encoded bundle that are written to the new private output; the bounded receipt is prepared before persistence and returned after atomic persistence and synchronization complete.

This receipt contains no absolute input/output path, identity or signing secret. It explicitly requires review and grants no native consent, signature, publisher authority, network publication or permission. A future native review controller must independently bind publisher, name, revision, expiry and an explicit user decision before using the existing checked publication command. Editor/MCP requests and this preparation receipt cannot approve publication.

## Hosted proof

The existing Quality workflow's opt-in `studio_export_pack` accepts `studio_proof_mode`:

- `viewer` (default): the retained viewer proof with its original three controller arguments and receipt schema.
- `signed-site-preflight`: focused Core site tests, new agent fixture controls, compilation and strict Clippy, plus Studio Python contracts. No Silex build or native acceptance claim.
- `signed-site-recovery`: the same checks followed by a fresh pinned Silex UI edit and ZIP export, actual CLI packaging and offline signing, two real roles-off agents sharing the same cache across a confirmed SIGKILL, public import/export/assembly, signed local preview and an independent browser observation of every exported asset.

The new proof requires exact Core and Studio revisions. Its separate receipt binds the dynamic bundle, manifest, publisher, original expiry, assets and chunks, and records negative previews for a wrong publisher and wrong reviewed digest. Success requires all owned CLI, agent and browser processes joined, the listener closed and private state removed. Test keys and identities are ephemeral. The proof grants no GUI native publication consent, network publication, protected peer retrieval, independent hosting, power-loss recovery, physical participation or full Studio acceptance.

All compilation, tests, native execution and browser trials run only on approved disposable hosted runners. Current exact-source results and remaining dependencies are maintained in the owning work report; this document describes the contract rather than claiming a successful runtime result.
