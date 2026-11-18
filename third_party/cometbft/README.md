# CometBFT ABCI schema inputs

The TEST transaction adapter uses CometBFT's official ABCI message definitions.
These files contain the wire schema and its imports, not a consensus engine or a
financial service. The Rust build generates Prost bindings from the local files;
ordinary builds must not download upstream source or start a validator.

## Pinned upstream sources

| Input | Source revision | License |
| --- | --- | --- |
| Five CometBFT schemas, LICENSE and NOTICE | [CometBFT v0.40.0](https://github.com/cometbft/cometbft/tree/0880b4d378f347ab16e54ec677ff50d803f37d62) | Apache-2.0 |
| Gogo options and LICENSE | [cosmos/gogoproto v1.7.2](https://github.com/cosmos/gogoproto/tree/cf5213e4dcbf1fea203185c0af00840e566790d9), as required by the pinned CometBFT go.mod | BSD-3-Clause |
| Timestamp, Duration, Descriptor and LICENSE | [Protocol Buffers v21.12](https://github.com/protocolbuffers/protobuf/tree/f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c) | BSD-3-Clause |

Every upstream file is verbatim, including original comments, license text and
NOTICE. No local patch is applied. [sources.json](sources.json) records each
original path, full commit, Git blob ID, byte count and SHA-256. The Google schemas
match the installed development compiler's 3.21.12 release; they do not replace
CometBFT's ABCI schema with a hand-written approximation.

## Offline verification

From the repository root:

```sh
python3 -B third_party/cometbft/verify.py
python3 -B third_party/cometbft/test_verify.py
```

The verifier checks exact bytes, notices, file inventory and import closure. Its
success proves source-input integrity only. It does not prove wire compatibility,
distributed agreement or successful execution of the separate CometBFT process.

## Build and runtime boundaries

The include roots are `proto/` and `vendor/`. Rust binding generation uses the
workspace's pinned Prost build dependency and a separately installed `protoc`;
generated files belong in Cargo's build output, not in this upstream tree.

A real validator trial additionally needs a source-built CometBFT executable,
its locked Go dependencies and retained licenses, isolated TEST keys and stores,
and explicit process/network cleanup. The fixture must verify its source revision
and build provenance; a runtime version string alone is insufficient. Installing
or compiling this adapter does not enable financial participation or real funds.
