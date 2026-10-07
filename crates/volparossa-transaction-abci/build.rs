//! Generate the exact vendored `CometBFT` schema; no network or generated substitute.
fn main() -> std::io::Result<()> {
    let root = std::path::PathBuf::from("../../third_party/cometbft");
    println!("cargo:rerun-if-changed={}", root.display());
    prost_build::Config::new()
        .compile_well_known_types()
        .include_file("comet.rs")
        .compile_protos(
            &[root.join("proto/tendermint/abci/types.proto")],
            &[root.join("proto"), root.join("vendor")],
        )
}
