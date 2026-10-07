//! Real command-line signing against the app; private TEST fixtures only.
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    process::Command,
};
use volparossa_transaction_abci::{
    Account, Application, Genesis, consensus_params,
    proto::{
        google::protobuf::Timestamp,
        tendermint::abci::{self, request::Value as Q, response::Value as R},
    },
};

fn call(app: &mut Application, value: Q) -> R {
    app.handle(abci::Request { value: Some(value) })
        .unwrap()
        .value
        .unwrap()
}

fn initialized(store: &Path, payer: &SigningKey, recipient: [u8; 32]) -> Application {
    let config = Genesis {
        version: 1,
        chain_id: "volparossa-test-cli".to_owned(),
        seconds: 90,
        nanos: 0,
        validators: (0..4)
            .map(|_| hex::encode(SigningKey::generate(&mut OsRng).verifying_key().to_bytes()))
            .collect(),
        accounts: vec![
            Account {
                public_key: hex::encode(payer.verifying_key().to_bytes()),
                units: 100,
            },
            Account {
                public_key: hex::encode(recipient),
                units: 0,
            },
        ],
    };
    let mut app = Application::open(store, config.clone()).unwrap();
    call(
        &mut app,
        Q::InitChain(abci::RequestInitChain {
            time: Some(Timestamp {
                seconds: 90,
                nanos: 0,
            }),
            chain_id: config.chain_id.clone(),
            consensus_params: Some(consensus_params()),
            validators: config.validator_updates().unwrap(),
            app_state_bytes: serde_json::to_vec(&config).unwrap(),
            initial_height: 1,
        }),
    );
    app
}

fn signer(kind: &str, ledger: &str, secret: &Path, id: u8) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_volparossa-transaction-abci"));
    command
        .args([
            kind,
            "--ledger",
            ledger,
            "--operation",
            &hex::encode([id; 32]),
            "--valid-from",
            "100",
            "--expires",
            "200",
            "--secret-key",
        ])
        .arg(secret);
    command
}

#[test]
fn cli_signs_actual_reserve_and_commit_without_persisting_keys_in_app() {
    let temp = tempfile::tempdir().unwrap();
    let payer = SigningKey::generate(&mut OsRng);
    let recipient = SigningKey::generate(&mut OsRng).verifying_key().to_bytes();
    let store = temp.path().join("ledger");
    let mut app = initialized(&store, &payer, recipient);
    let R::Query(info) = call(
        &mut app,
        Q::Query(abci::RequestQuery {
            path: "/test/info".to_owned(),
            ..Default::default()
        }),
    ) else {
        panic!()
    };
    let info: serde_json::Value = serde_json::from_slice(&info.value).unwrap();
    let ledger = info["ledger_id"].as_str().unwrap();
    let secret = temp.path().join("signer.seed");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&secret)
        .unwrap();
    file.write_all(&payer.to_bytes()).unwrap();
    drop(file);
    for (kind, id) in [("sign-reserve", 1_u8), ("sign-commit", 2_u8)] {
        let mut command = signer(kind, ledger, &secret, id);
        if id == 1 {
            command.args(["--recipient", &hex::encode(recipient), "--units", "70"]);
        } else {
            command.args(["--reservation", &hex::encode([1; 32])]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let bytes = hex::decode(String::from_utf8(output.stdout).unwrap().trim()).unwrap();
        let R::FinalizeBlock(result) = call(
            &mut app,
            Q::FinalizeBlock(abci::RequestFinalizeBlock {
                height: i64::from(id),
                hash: vec![id; 32],
                time: Some(Timestamp {
                    seconds: 110,
                    nanos: 0,
                }),
                txs: vec![bytes],
                ..Default::default()
            }),
        ) else {
            panic!()
        };
        assert_eq!(result.tx_results[0].code, 0);
        call(&mut app, Q::Commit(abci::RequestCommit {}));
    }
    let R::Query(balance) = call(
        &mut app,
        Q::Query(abci::RequestQuery {
            path: "/test/balance".to_owned(),
            data: recipient.to_vec(),
            ..Default::default()
        }),
    ) else {
        panic!()
    };
    let balance: serde_json::Value = serde_json::from_slice(&balance.value).unwrap();
    assert_eq!(balance["available_units"], 70);
    let database = fs::read(store.join("test-transactions.sqlite3")).unwrap();
    assert!(
        !database
            .windows(32)
            .any(|window| window == payer.to_bytes())
    );
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).unwrap();
    let output = signer("sign-reserve", ledger, &secret, 3)
        .args(["--recipient", &hex::encode(recipient), "--units", "1"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[test]
fn serve_refuses_public_config_before_creating_state_or_socket() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("config.json");
    fs::write(&config, b"{}").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o644)).unwrap();
    let state = temp.path().join("ledger");
    let socket = temp.path().join("app.sock");
    let output = Command::new(env!("CARGO_BIN_EXE_volparossa-transaction-abci"))
        .arg("serve")
        .arg("--config")
        .arg(&config)
        .arg("--store")
        .arg(&state)
        .arg("--socket")
        .arg(&socket)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!state.exists());
    assert!(!socket.exists());
    assert!(output.stdout.is_empty());
}
