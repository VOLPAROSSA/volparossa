//! Generate the exact vendored `CometBFT` schema; no network or generated substitute.
fn main() -> std::io::Result<()> {
    let root = std::path::PathBuf::from("../../third_party/cometbft");
    println!("cargo:rerun-if-changed={}", root.display());
    // These two upstream docs contain non-Rust examples. Keep the vendored
    // schemas verbatim and link their pinned documentation from generated types
    // instead of making rustdoc compile the examples as Rust tests.
    prost_build::Config::new()
        .compile_well_known_types()
        .disable_comments([".google.protobuf.Timestamp", ".google.protobuf.Duration"])
        .type_attribute(
            ".google.protobuf.Timestamp",
            r#"#[doc = "Original documentation: [vendored timestamp.proto](https://github.com/protocolbuffers/protobuf/blob/f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c/src/google/protobuf/timestamp.proto)."]"#,
        )
        .type_attribute(
            ".google.protobuf.Duration",
            r#"#[doc = "Original documentation: [vendored duration.proto](https://github.com/protocolbuffers/protobuf/blob/f0dc78d7e6e331b8c6bb2d5283e06aa26883ca7c/src/google/protobuf/duration.proto)."]"#,
        )
        .include_file("comet.rs")
        .compile_protos(
            &[root.join("proto/tendermint/abci/types.proto")],
            &[root.join("proto"), root.join("vendor")],
        )
}
