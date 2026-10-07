//! Serialized ABCI lifecycle; the ordered store remains the only ledger.
use crate::{
    Error, Genesis, MAX_FRAME_BYTES, consensus_params,
    proto::{google::protobuf::Timestamp, tendermint::abci},
};
use prost::Message as _;
use std::path::{Path, PathBuf};
use volparossa_transaction::{
    Block, BlockTime, CommandFailure, Error as StoreError, MAX_BLOCK_BYTES, MAX_BLOCK_COMMANDS,
    OrderedStore,
};

const CODESPACE: &str = "volparossa.test.v1";

/// A single serialized application instance, shared by `CometBFT`'s separate connections.
pub struct Application {
    genesis: Genesis,
    path: PathBuf,
    store: Option<OrderedStore>,
    pending: Option<[u8; 32]>,
    failed: bool,
}

impl Application {
    /// Prepare a new app or reopen its existing ordered store and verify full genesis.
    /// A new store is created only after a matching `InitChain`.
    ///
    /// # Errors
    /// Rejects invalid configuration, mismatched existing state and unsafe store files.
    pub fn open(path: &Path, genesis: Genesis) -> Result<Self, Error> {
        let genesis = genesis.normalized()?;
        if !path.is_absolute() {
            return Err(Error::Configuration);
        }
        let store = match path.symlink_metadata() {
            Ok(_) => {
                let value = OrderedStore::open(path)?;
                if !value.matches_genesis(
                    genesis.authority()?,
                    &genesis.accounts()?,
                    genesis.time()?,
                )? {
                    return Err(Error::Configuration);
                }
                Some(value)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            genesis,
            path: path.to_owned(),
            store,
            pending: None,
            failed: false,
        })
    }

    /// Handle exactly one bounded upstream request. Fatal errors stop the server.
    /// Command rejection codes are distinct from fatal database/protocol failures.
    ///
    /// # Errors
    /// Returns closed errors on impossible lifecycle, unsupported methods or store failure.
    pub fn handle(&mut self, request: abci::Request) -> Result<abci::Response, Error> {
        if self.failed {
            return Err(Error::Protocol);
        }
        let result = self.handle_inner(request);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn handle_inner(&mut self, request: abci::Request) -> Result<abci::Response, Error> {
        if request.encoded_len() > MAX_FRAME_BYTES {
            return Err(Error::Protocol);
        }
        use abci::{request::Value as Q, response::Value as R};
        let response = match request.value.ok_or(Error::Protocol)? {
            Q::Echo(value) => R::Echo(abci::ResponseEcho {
                message: value.message,
            }),
            Q::Flush(_) => R::Flush(abci::ResponseFlush {}),
            Q::Info(_) => R::Info(self.info()?),
            Q::InitChain(value) => R::InitChain(self.init_chain(&value)?),
            Q::CheckTx(value) => R::CheckTx(self.check_tx(&value)?),
            Q::PrepareProposal(value) => R::PrepareProposal(self.prepare(&value)?),
            Q::ProcessProposal(value) => R::ProcessProposal(self.process(&value)?),
            Q::FinalizeBlock(value) => R::FinalizeBlock(self.finalize(&value)?),
            Q::Commit(_) => {
                let id = self.pending.ok_or(Error::Protocol)?;
                self.store.as_mut().ok_or(Error::Protocol)?.commit(id)?;
                self.pending = None;
                R::Commit(abci::ResponseCommit { retain_height: 0 })
            }
            Q::Query(value) => R::Query(self.query(&value)?),
            // Advertising no snapshots is truthful; accepting one would not be.
            Q::ListSnapshots(_) => {
                R::ListSnapshots(abci::ResponseListSnapshots { snapshots: vec![] })
            }
            Q::OfferSnapshot(_) => R::OfferSnapshot(abci::ResponseOfferSnapshot {
                result: abci::response_offer_snapshot::Result::Reject as i32,
            }),
            Q::ApplySnapshotChunk(_) => R::ApplySnapshotChunk(abci::ResponseApplySnapshotChunk {
                result: abci::response_apply_snapshot_chunk::Result::Abort as i32,
                ..Default::default()
            }),
            // No fake successful vote extensions, application mempool or chunk loading.
            Q::LoadSnapshotChunk(_)
            | Q::ExtendVote(_)
            | Q::VerifyVoteExtension(_)
            | Q::InsertTx(_)
            | Q::ReapTxs(_) => return Err(Error::Protocol),
        };
        Ok(abci::Response {
            value: Some(response),
        })
    }

    fn store(&self) -> Result<&OrderedStore, Error> {
        self.store.as_ref().ok_or(Error::Protocol)
    }

    fn info(&self) -> Result<abci::ResponseInfo, Error> {
        let (height, hash) = match &self.store {
            Some(store) => {
                let value = store.info()?;
                (height_i64(value.height)?, value.app_hash.to_vec())
            }
            None => (0, vec![]),
        };
        Ok(abci::ResponseInfo {
            data: "ordered-fictitious-TEST-only".to_owned(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            app_version: 1,
            last_block_height: height,
            last_block_app_hash: hash,
        })
    }

    fn init_chain(
        &mut self,
        request: &abci::RequestInitChain,
    ) -> Result<abci::ResponseInitChain, Error> {
        if self.pending.is_some()
            || request.chain_id != self.genesis.chain_id
            || request.initial_height != 1
            || agreed_time(request.time.as_ref())? != self.genesis.time()?
            || request.consensus_params.as_ref() != Some(&consensus_params())
            || Genesis::from_json(&request.app_state_bytes)? != self.genesis
        {
            return Err(Error::Configuration);
        }
        let mut actual = request
            .validators
            .iter()
            .map(|validator| {
                use crate::proto::tendermint::crypto::public_key::Sum;
                match validator.pub_key.as_ref().and_then(|key| key.sum.as_ref()) {
                    Some(Sum::Ed25519(key)) if key.len() == 32 && validator.power == 10 => {
                        Ok(hex::encode(key))
                    }
                    _ => Err(Error::Configuration),
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        actual.sort();
        if actual != self.genesis.validators {
            return Err(Error::Configuration);
        }
        if self.store.is_none() {
            self.store = Some(OrderedStore::create(
                &self.path,
                self.genesis.authority()?,
                &self.genesis.accounts()?,
                self.genesis.time()?,
            )?);
        }
        let info = self.store()?.info()?;
        if info.height != 0 {
            return Err(Error::Protocol);
        }
        Ok(abci::ResponseInitChain {
            consensus_params: Some(consensus_params()),
            validators: self.genesis.validator_updates()?,
            app_hash: info.app_hash.to_vec(),
        })
    }

    fn check_tx(&self, request: &abci::RequestCheckTx) -> Result<abci::ResponseCheckTx, Error> {
        if abci::CheckTxType::try_from(request.r#type).is_err() {
            return Err(Error::Protocol);
        }
        // Signature/domain/enrollment only. No wall clock, mutation or finality promise.
        let code = match self.store()?.inspect(&request.tx) {
            Ok(_) => 0,
            Err(error) => rejection(error)? as u32,
        };
        Ok(abci::ResponseCheckTx {
            code,
            codespace: CODESPACE.to_owned(),
            ..Default::default()
        })
    }

    fn proposal_position(&self, height: i64, time: Option<&Timestamp>) -> Result<bool, Error> {
        let current = self.store()?.info()?;
        let Ok(time) = agreed_time(time) else {
            return Ok(false);
        };
        Ok(u64::try_from(height).ok() == current.height.checked_add(1) && time >= current.time)
    }

    fn prepare(
        &self,
        request: &abci::RequestPrepareProposal,
    ) -> Result<abci::ResponsePrepareProposal, Error> {
        if !self.proposal_position(request.height, request.time.as_ref())? {
            return Err(Error::Protocol);
        }
        let max_bytes = usize::try_from(request.max_tx_bytes)
            .map_err(|_| Error::Protocol)?
            .min(MAX_BLOCK_BYTES);
        let mut used = 0;
        let mut txs = Vec::new();
        for bytes in &request.txs {
            if txs.len() == MAX_BLOCK_COMMANDS {
                break;
            }
            if bytes.len() <= 4096 && bytes.len() <= max_bytes - used {
                used += bytes.len();
                txs.push(bytes.clone());
            }
        }
        Ok(abci::ResponsePrepareProposal { txs })
    }

    fn process(
        &self,
        request: &abci::RequestProcessProposal,
    ) -> Result<abci::ResponseProcessProposal, Error> {
        let accepted = self.proposal_position(request.height, request.time.as_ref())?
            && block_id(&request.hash).is_ok()
            && bounded_commands(&request.txs);
        Ok(abci::ResponseProcessProposal {
            status: if accepted {
                abci::response_process_proposal::ProposalStatus::Accept as i32
            } else {
                abci::response_process_proposal::ProposalStatus::Reject as i32
            },
        })
    }

    fn finalize(
        &mut self,
        request: &abci::RequestFinalizeBlock,
    ) -> Result<abci::ResponseFinalizeBlock, Error> {
        let block = Block {
            height: u64::try_from(request.height).map_err(|_| Error::Protocol)?,
            block_id: block_id(&request.hash)?,
            time: agreed_time(request.time.as_ref())?,
            commands: request.txs.clone(),
        };
        // Only FinalizeBlock occupies the one staged slot. Commit is separate.
        let staged = self.store.as_mut().ok_or(Error::Protocol)?.stage(&block)?;
        self.pending = Some(staged.block_id);
        let tx_results = staged
            .outcomes
            .iter()
            .map(|outcome| abci::ExecTxResult {
                code: match &outcome.result {
                    Ok(_) => 0,
                    Err(value) => *value as u32,
                },
                // This is an input digest, not a durable receipt or finality proof.
                data: outcome.command_sha256.to_vec(),
                codespace: CODESPACE.to_owned(),
                ..Default::default()
            })
            .collect();
        Ok(abci::ResponseFinalizeBlock {
            tx_results,
            app_hash: staged.app_hash.to_vec(),
            ..Default::default()
        })
    }

    fn query(&self, request: &abci::RequestQuery) -> Result<abci::ResponseQuery, Error> {
        let store = self.store()?;
        let current = store.info()?;
        let height = height_i64(current.height)?;
        let rejected = || abci::ResponseQuery {
            code: 100,
            height,
            codespace: CODESPACE.to_owned(),
            ..Default::default()
        };
        if request.prove || (request.height != 0 && request.height != height) {
            return Ok(rejected());
        }
        let value = match request.path.as_str() {
            "/test/info" if request.data.is_empty() => {
                serde_json::json!({"unit":volparossa_transaction::TEST_UNIT,"height":current.height,"app_hash":hex::encode(current.app_hash),"ledger_id":hex::encode(store.ledger_id()),"consensus_certificate":false})
            }
            "/test/balance" if request.data.len() == 32 => {
                let owner = request
                    .data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Protocol)?;
                match store.status(owner) {
                    Ok(balance) => {
                        serde_json::json!({"available_units":balance.available_units,"reserved_units":balance.reserved_units})
                    }
                    Err(StoreError::NotFound) => return Ok(rejected()),
                    Err(error) => return Err(error.into()),
                }
            }
            "/test/operation" if request.data.len() == 32 => {
                let id = request
                    .data
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::Protocol)?;
                match store.operation(id)? {
                    Some(receipt) => {
                        serde_json::json!({"operation_id":hex::encode(receipt.operation_id),"command_sha256":hex::encode(receipt.command_sha256),"sequence":receipt.sequence,"reservation_id":hex::encode(receipt.reservation_id),"state":format!("{:?}",receipt.state),"consensus_certificate":false})
                    }
                    None => return Ok(rejected()),
                }
            }
            _ => return Ok(rejected()),
        };
        Ok(abci::ResponseQuery {
            height,
            value: serde_json::to_vec(&value).map_err(|_| Error::Protocol)?,
            codespace: CODESPACE.to_owned(),
            ..Default::default()
        })
    }
}

fn agreed_time(value: Option<&Timestamp>) -> Result<BlockTime, Error> {
    let value = value.ok_or(Error::Protocol)?;
    BlockTime::from_unix(value.seconds, value.nanos).map_err(|_| Error::Protocol)
}
fn height_i64(value: u64) -> Result<i64, Error> {
    i64::try_from(value).map_err(|_| Error::Protocol)
}
fn block_id(bytes: &[u8]) -> Result<[u8; 32], Error> {
    let id = bytes.try_into().map_err(|_| Error::Protocol)?;
    if id == [0; 32] {
        return Err(Error::Protocol);
    }
    Ok(id)
}
fn bounded_commands(commands: &[Vec<u8>]) -> bool {
    commands.len() <= MAX_BLOCK_COMMANDS
        && commands.iter().all(|tx| tx.len() <= 4096)
        && commands
            .iter()
            .try_fold(0_usize, |total, tx| total.checked_add(tx.len()))
            .is_some_and(|total| total <= MAX_BLOCK_BYTES)
}
fn rejection(error: StoreError) -> Result<CommandFailure, Error> {
    Ok(match error {
        StoreError::Invalid => CommandFailure::Invalid,
        StoreError::Unauthorized => CommandFailure::Unauthorized,
        StoreError::WrongLedger => CommandFailure::WrongLedger,
        StoreError::NotLive => CommandFailure::NotLive,
        StoreError::Conflict => CommandFailure::Conflict,
        StoreError::Replay => CommandFailure::Replay,
        StoreError::Insufficient => CommandFailure::Insufficient,
        StoreError::NotFound => CommandFailure::NotFound,
        StoreError::State => CommandFailure::State,
        StoreError::Capacity => CommandFailure::Capacity,
        other => return Err(other.into()),
    })
}
