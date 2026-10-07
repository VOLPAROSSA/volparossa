//! Application and actual Unix socket tests, NOT Comet consensus evidence.
use super::*;
use ed25519_dalek::SigningKey;
use prost::Message as _;
use proto::{
    google::protobuf::Timestamp,
    tendermint::abci::{self, request::Value as Q, response::Value as R},
};
use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    path::Path,
};
use tokio::{io::AsyncWriteExt as _, net::UnixStream, sync::oneshot};
use volparossa_transaction::{Action, Command, SignedCommand};

fn key(id: u8) -> SigningKey {
    SigningKey::from_bytes(&[id; 32])
}
fn public(id: u8) -> [u8; 32] {
    key(id).verifying_key().to_bytes()
}
fn genesis() -> Genesis {
    Genesis {
        version: 1,
        chain_id: "volparossa-test-abci".to_owned(),
        seconds: 90,
        nanos: 0,
        validators: (3..=6).map(|id| hex::encode(public(id))).collect(),
        accounts: vec![
            Account {
                public_key: hex::encode(public(1)),
                units: 100,
            },
            Account {
                public_key: hex::encode(public(2)),
                units: 0,
            },
        ],
    }
    .normalized()
    .unwrap()
}
fn init(config: &Genesis) -> Q {
    Q::InitChain(abci::RequestInitChain {
        time: Some(Timestamp {
            seconds: config.seconds,
            nanos: config.nanos,
        }),
        chain_id: config.chain_id.clone(),
        consensus_params: Some(consensus_params()),
        validators: config.validator_updates().unwrap(),
        app_state_bytes: serde_json::to_vec(config).unwrap(),
        initial_height: 1,
    })
}
fn call(app: &mut Application, query: Q) -> R {
    app.handle(abci::Request { value: Some(query) })
        .unwrap()
        .value
        .unwrap()
}
fn app(path: &Path) -> Application {
    let mut value = Application::open(path, genesis()).unwrap();
    call(&mut value, init(&genesis()));
    value
}
fn query(app: &mut Application, path: &str, data: Vec<u8>) -> abci::ResponseQuery {
    let R::Query(value) = call(
        app,
        Q::Query(abci::RequestQuery {
            path: path.to_owned(),
            data,
            ..Default::default()
        }),
    ) else {
        panic!("not query")
    };
    value
}
fn ledger(app: &mut Application) -> [u8; 32] {
    let value: serde_json::Value =
        serde_json::from_slice(&query(app, "/test/info", vec![]).value).unwrap();
    let mut ledger = [0; 32];
    hex::decode_to_slice(value["ledger_id"].as_str().unwrap(), &mut ledger).unwrap();
    ledger
}
fn signed(ledger: [u8; 32], id: u8, action: Action) -> Vec<u8> {
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).expect("operating-system randomness unavailable");
    SignedCommand::sign_ordered(
        ledger,
        &key(1),
        Command {
            operation_id: [id; 32],
            payer: public(1),
            action,
        },
        100,
        200,
        nonce,
    )
    .unwrap()
    .encode()
}
fn reserve(app: &mut Application, id: u8, units: u64) -> Vec<u8> {
    signed(
        ledger(app),
        id,
        Action::Reserve {
            recipient: public(2),
            units,
        },
    )
}
fn finalize(height: i64, id: u8, time: i64, txs: Vec<Vec<u8>>) -> Q {
    Q::FinalizeBlock(abci::RequestFinalizeBlock {
        txs,
        height,
        hash: vec![id; 32],
        time: Some(Timestamp {
            seconds: time,
            nanos: 0,
        }),
        ..Default::default()
    })
}
fn info(app: &mut Application) -> abci::ResponseInfo {
    let R::Info(value) = call(app, Q::Info(abci::RequestInfo::default())) else {
        panic!("not info")
    };
    value
}

#[test]
fn init_binds_all_genesis_inputs_reopens_and_refuses_other_authority() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    let mut value = Application::open(&path, genesis()).unwrap();
    assert_eq!(info(&mut value).last_block_app_hash, Vec::<u8>::new());
    assert!(!path.exists());
    call(&mut value, init(&genesis()));
    let initial = info(&mut value);
    assert_eq!(initial.last_block_height, 0);
    call(&mut value, init(&genesis()));
    assert_eq!(info(&mut value), initial);
    drop(value);
    assert_eq!(
        info(&mut Application::open(&path, genesis()).unwrap()),
        initial
    );
    for changed in 0..4 {
        let mut config = genesis();
        match changed {
            0 => config.chain_id.push('x'),
            1 => config.accounts[0].units += 1,
            2 => config.nanos = 1,
            _ => config.validators[0] = hex::encode(public(9)),
        }
        assert!(Application::open(&path, config).is_err());
    }
}

#[test]
fn mismatched_init_is_fatal_without_creating_store() {
    for changed in 0..5 {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("ledger");
        let mut value = Application::open(&path, genesis()).unwrap();
        let Q::InitChain(mut request) = init(&genesis()) else {
            unreachable!()
        };
        match changed {
            0 => request.initial_height = 2,
            1 => request.validators[0].power = 1,
            2 => request.time.as_mut().unwrap().nanos = -1,
            3 => request.app_state_bytes = b"{}".to_vec(),
            _ => {
                request
                    .consensus_params
                    .as_mut()
                    .unwrap()
                    .abci
                    .as_mut()
                    .unwrap()
                    .vote_extensions_enable_height = 1;
            }
        }
        assert!(
            value
                .handle(abci::Request {
                    value: Some(Q::InitChain(request))
                })
                .is_err()
        );
        assert!(!path.exists());
        assert!(
            value
                .handle(abci::Request {
                    value: Some(init(&genesis()))
                })
                .is_err()
        );
    }
}

#[test]
fn proposals_and_checktx_are_readonly_and_never_occupy_finalize_slot() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    let mut value = app(&path);
    let bytes = reserve(&mut value, 1, 70);
    let original = fs::read(path.join("test-transactions.sqlite3")).unwrap();
    for _ in 0..2 {
        let R::CheckTx(result) = call(
            &mut value,
            Q::CheckTx(abci::RequestCheckTx {
                tx: bytes.clone(),
                r#type: 0,
            }),
        ) else {
            panic!()
        };
        assert_eq!(result.code, 0);
    }
    for seconds in [110, 111] {
        let R::PrepareProposal(result) = call(
            &mut value,
            Q::PrepareProposal(abci::RequestPrepareProposal {
                max_tx_bytes: 65_536,
                txs: vec![bytes.clone()],
                height: 1,
                time: Some(Timestamp { seconds, nanos: 0 }),
                ..Default::default()
            }),
        ) else {
            panic!()
        };
        assert_eq!(result.txs, vec![bytes.clone()]);
        let R::ProcessProposal(result) = call(
            &mut value,
            Q::ProcessProposal(abci::RequestProcessProposal {
                txs: vec![bytes.clone()],
                height: 1,
                hash: vec![3; 32],
                time: Some(Timestamp { seconds, nanos: 0 }),
                ..Default::default()
            }),
        ) else {
            panic!()
        };
        assert_eq!(result.status, 1);
    }
    assert_eq!(
        fs::read(path.join("test-transactions.sqlite3")).unwrap(),
        original
    );
    let R::FinalizeBlock(result) = call(&mut value, finalize(1, 1, 112, vec![bytes])) else {
        panic!()
    };
    assert_eq!(result.tx_results[0].code, 0);
    assert_eq!(info(&mut value).last_block_height, 0);
    assert_eq!(query(&mut value, "/test/operation", vec![1; 32]).code, 100);
    assert_eq!(
        fs::read(path.join("test-transactions.sqlite3")).unwrap(),
        original
    );
    call(&mut value, Q::Commit(abci::RequestCommit {}));
    assert_eq!(info(&mut value).last_block_height, 1);
    assert_eq!(query(&mut value, "/test/operation", vec![1; 32]).code, 0);
}

#[test]
fn deterministic_conflict_rejection_and_credit_share_one_real_ledger() {
    let temp = tempfile::tempdir().unwrap();
    let mut a = app(&temp.path().join("a"));
    let mut b = app(&temp.path().join("b"));
    let first = reserve(&mut a, 1, 70);
    let second = reserve(&mut a, 2, 70);
    let invalid = vec![0xff];
    let block = finalize(1, 1, 110, vec![first.clone(), second, invalid, first]);
    let ra = call(&mut a, block.clone());
    let rb = call(&mut b, block);
    assert_eq!(ra, rb);
    let R::FinalizeBlock(result) = ra else {
        panic!()
    };
    assert_eq!(
        result.tx_results.iter().map(|r| r.code).collect::<Vec<_>>(),
        vec![0, 7, 1, 0]
    );
    for value in [&mut a, &mut b] {
        call(value, Q::Commit(abci::RequestCommit {}));
    }
    let commit = signed(
        ledger(&mut a),
        3,
        Action::Commit {
            reservation_id: [1; 32],
        },
    );
    let block = finalize(2, 2, 111, vec![commit]);
    assert_eq!(call(&mut a, block.clone()), call(&mut b, block));
    for value in [&mut a, &mut b] {
        call(value, Q::Commit(abci::RequestCommit {}));
        let result = query(value, "/test/balance", public(2).to_vec());
        let balance: serde_json::Value = serde_json::from_slice(&result.value).unwrap();
        assert_eq!(balance["available_units"], 70);
    }
    assert_eq!(info(&mut a), info(&mut b));
}

#[test]
fn agreed_time_not_wall_clock_controls_expiry() {
    let temp = tempfile::tempdir().unwrap();
    let mut value = app(&temp.path().join("ledger"));
    let bytes = reserve(&mut value, 1, 70);
    let R::FinalizeBlock(result) = call(&mut value, finalize(1, 1, 200, vec![bytes])) else {
        panic!()
    };
    assert_eq!(result.tx_results[0].code, 4);
    call(&mut value, Q::Commit(abci::RequestCommit {}));
    assert_eq!(query(&mut value, "/test/operation", vec![1; 32]).code, 100);
}

#[test]
fn discard_by_restart_and_committed_replay_match_exactly() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("ledger");
    let mut value = app(&path);
    let bytes = reserve(&mut value, 1, 70);
    let block = finalize(1, 1, 110, vec![bytes]);
    let staged = call(&mut value, block.clone());
    drop(value);
    let mut value = Application::open(&path, genesis()).unwrap();
    assert_eq!(info(&mut value).last_block_height, 0);
    assert_eq!(call(&mut value, block.clone()), staged);
    call(&mut value, Q::Commit(abci::RequestCommit {}));
    drop(value);
    let mut value = Application::open(&path, genesis()).unwrap();
    assert_eq!(info(&mut value).last_block_height, 1);
    assert_eq!(call(&mut value, block), staged);
    call(&mut value, Q::Commit(abci::RequestCommit {}));
    assert_eq!(info(&mut value).last_block_height, 1);
}

#[test]
fn resource_bounds_and_unsupported_proofs_fail_closed() {
    let temp = tempfile::tempdir().unwrap();
    let mut value = app(&temp.path().join("ledger"));
    let public_status = query(&mut value, "/test/info", vec![]);
    assert_eq!(public_status.code, 0);
    assert!(public_status.proof_ops.is_none());
    let public_status: serde_json::Value = serde_json::from_slice(&public_status.value).unwrap();
    assert_eq!(public_status["consensus_certificate"], false);
    let R::PrepareProposal(result) = call(
        &mut value,
        Q::PrepareProposal(abci::RequestPrepareProposal {
            max_tx_bytes: 5,
            txs: vec![vec![1; 4], vec![2; 4], vec![3]],
            height: 1,
            time: Some(Timestamp {
                seconds: 110,
                nanos: 0,
            }),
            ..Default::default()
        }),
    ) else {
        panic!()
    };
    assert_eq!(result.txs, vec![vec![1; 4], vec![3]]);
    for txs in [
        vec![vec![1]; 65],
        vec![vec![1; 4097]],
        vec![vec![1; 4096]; 17],
    ] {
        let R::ProcessProposal(result) = call(
            &mut value,
            Q::ProcessProposal(abci::RequestProcessProposal {
                txs,
                height: 1,
                hash: vec![1; 32],
                time: Some(Timestamp {
                    seconds: 110,
                    nanos: 0,
                }),
                ..Default::default()
            }),
        ) else {
            panic!()
        };
        assert_eq!(result.status, 2);
    }
    for request in [
        abci::RequestQuery {
            path: "/test/info".to_owned(),
            prove: true,
            ..Default::default()
        },
        abci::RequestQuery {
            path: "/test/info".to_owned(),
            height: 5,
            ..Default::default()
        },
    ] {
        let R::Query(result) = call(&mut value, Q::Query(request)) else {
            panic!()
        };
        assert_ne!(result.code, 0);
        assert!(result.proof_ops.is_none());
    }
    assert!(
        value
            .handle(abci::Request {
                value: Some(Q::InsertTx(abci::RequestInsertTx { tx: vec![] }))
            })
            .is_err()
    );
    assert!(
        value
            .handle(abci::Request {
                value: Some(Q::Commit(abci::RequestCommit {}))
            })
            .is_err()
    );
}

#[test]
fn json_config_has_strict_fields_sizes_keys_and_membership() {
    let valid = serde_json::to_vec(&genesis()).unwrap();
    assert_eq!(Genesis::from_json(&valid).unwrap(), genesis());
    assert!(Genesis::from_json(&vec![b' '; 16385]).is_err());
    let mut value = serde_json::to_value(genesis()).unwrap();
    value["real_currency"] = true.into();
    assert!(Genesis::from_json(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut bad = genesis();
    bad.validators[0] = bad.validators[1].clone();
    assert!(bad.normalized().is_err());
    let mut bad = genesis();
    bad.accounts[0].units = u64::MAX;
    assert!(bad.normalized().is_err());
    let mut bad = genesis();
    bad.nanos = 1_000_000_000;
    assert!(bad.normalized().is_err());
}

async fn socket_call(socket: &mut UnixStream, query: Q) -> R {
    write_frame(
        socket,
        &abci::Request { value: Some(query) }.encode_to_vec(),
    )
    .await
    .unwrap();
    abci::Response::decode(read_frame(socket).await.unwrap().unwrap().as_slice())
        .unwrap()
        .value
        .unwrap()
}

#[tokio::test]
async fn real_socket_fifo_flush_four_connections_and_atomic_shared_state() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("abci.sock");
    let application = Application::open(&temp.path().join("ledger"), genesis()).unwrap();
    let server = Server::bind(&socket, application).unwrap();
    assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
    let (stop, shutdown) = oneshot::channel();
    let task = tokio::spawn(server.serve(async {
        let _ = shutdown.await;
    }));
    let mut connections = Vec::new();
    for _ in 0..4 {
        let mut client = UnixStream::connect(&socket).await.unwrap();
        assert!(matches!(
            socket_call(&mut client, Q::Flush(abci::RequestFlush {})).await,
            R::Flush(_)
        ));
        connections.push(client);
    }
    let mut extra = UnixStream::connect(&socket).await.unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(2), read_frame(&mut extra))
            .await
            .unwrap()
            .unwrap()
            .is_none()
    );
    socket_call(&mut connections[0], init(&genesis())).await;
    let request = abci::Request {
        value: Some(Q::Echo(abci::RequestEcho {
            message: "one".to_owned(),
        })),
    }
    .encode_to_vec();
    write_frame(&mut connections[0], &request).await.unwrap();
    write_frame(
        &mut connections[0],
        &abci::Request {
            value: Some(Q::Flush(abci::RequestFlush {})),
        }
        .encode_to_vec(),
    )
    .await
    .unwrap();
    for expected in [true, false] {
        let result = abci::Response::decode(
            read_frame(&mut connections[0])
                .await
                .unwrap()
                .unwrap()
                .as_slice(),
        )
        .unwrap();
        assert_eq!(matches!(result.value, Some(R::Echo(_))), expected);
    }
    socket_call(&mut connections[0], finalize(1, 1, 110, vec![])).await;
    let R::Info(before) =
        socket_call(&mut connections[1], Q::Info(abci::RequestInfo::default())).await
    else {
        panic!()
    };
    assert_eq!(before.last_block_height, 0);
    socket_call(&mut connections[2], Q::Commit(abci::RequestCommit {})).await;
    let R::Info(after) =
        socket_call(&mut connections[3], Q::Info(abci::RequestInfo::default())).await
    else {
        panic!()
    };
    assert_eq!(after.last_block_height, 1);
    stop.send(()).unwrap();
    task.await.unwrap().unwrap();
    assert!(!socket.exists());
}

#[tokio::test]
async fn framing_rejects_oversize_overflow_zero_and_truncation() {
    for bytes in [
        vec![0],
        vec![0xff, 0xff, 0x7f],
        vec![0x80, 0x80, 0x80, 0],
        vec![3, 1],
    ] {
        let (mut writer, mut reader) = tokio::io::duplex(16);
        writer.write_all(&bytes).await.unwrap();
        drop(writer);
        assert!(read_frame(&mut reader).await.is_err());
    }
    let (mut writer, mut reader) = tokio::io::duplex(16);
    write_frame(&mut writer, &[1, 2, 3]).await.unwrap();
    assert_eq!(read_frame(&mut reader).await.unwrap(), Some(vec![1, 2, 3]));
}

#[tokio::test]
async fn malformed_connection_stops_server_and_only_owned_socket_is_removed() {
    let temp = tempfile::tempdir().unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let socket = temp.path().join("abci.sock");
    let server = Server::bind(&socket, app(&temp.path().join("ledger"))).unwrap();
    let task = tokio::spawn(server.serve(std::future::pending()));
    let mut client = UnixStream::connect(&socket).await.unwrap();
    client.write_all(&[0]).await.unwrap();
    assert!(task.await.unwrap().is_err());
    assert!(!socket.exists());
    let server = Server::bind(&socket, app(&temp.path().join("second"))).unwrap();
    fs::remove_file(&socket).unwrap();
    fs::write(&socket, b"replacement").unwrap();
    drop(server);
    assert_eq!(fs::read(&socket).unwrap(), b"replacement");
}
