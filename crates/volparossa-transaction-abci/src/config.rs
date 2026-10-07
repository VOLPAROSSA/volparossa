//! Explicit, immutable four-validator TEST authority and bounded genesis.
use crate::{
    Error,
    proto::{
        google::protobuf::Duration,
        tendermint::{abci, crypto, types},
    },
};
use ed25519_dalek::VerifyingKey;
use prost::Message as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use volparossa_transaction::{BlockTime, GenesisAccount, MAX_ACCOUNTS, MAX_UNITS};

/// One explicitly funded fictitious account; never a private key or network identity.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Account {
    /// Lowercase hex Ed25519 public key.
    pub public_key: String,
    /// Initial whole TEST units; no later mint endpoint exists.
    pub units: u64,
}

/// Strict app-state JSON and local trusted genesis must describe the same configuration.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    /// Only version one is supported.
    pub version: u32,
    /// Explicit isolated chain identity, beginning with `volparossa-test-`.
    pub chain_id: String,
    /// Nonnegative agreed genesis Unix seconds, not the machine's clock.
    pub seconds: i64,
    /// Agreed nanoseconds within one second.
    pub nanos: i32,
    /// Exactly four distinct lowercase hex Ed25519 validator keys, each power ten.
    pub validators: Vec<String>,
    /// Explicit financial TEST accounts, separate from ordinary peer admission.
    pub accounts: Vec<Account>,
}

impl Genesis {
    /// Validate and canonicalize authority/account order, bounded before deserialization.
    ///
    /// # Errors
    /// Rejects oversized, ambiguous, unknown-field or invalid configuration.
    pub fn from_json(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > 16_384 {
            return Err(Error::Configuration);
        }
        let value: Self = serde_json::from_slice(bytes).map_err(|_| Error::Configuration)?;
        value.normalized()
    }

    pub(crate) fn normalized(mut self) -> Result<Self, Error> {
        if self.version != 1
            || !self.chain_id.starts_with("volparossa-test-")
            || self.chain_id.len() > 50
            || !self
                .chain_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            || self.validators.len() != 4
            || self.accounts.is_empty()
            || self.accounts.len() > MAX_ACCOUNTS
        {
            return Err(Error::Configuration);
        }
        self.time()?;
        self.validators.sort();
        self.accounts
            .sort_by(|a, b| a.public_key.cmp(&b.public_key));
        let mut validators = BTreeSet::new();
        for value in &self.validators {
            if !validators.insert(public_key(value)?) {
                return Err(Error::Configuration);
            }
        }
        let mut accounts = BTreeSet::new();
        let mut supply = 0_u64;
        for value in &self.accounts {
            if !accounts.insert(public_key(&value.public_key)?) {
                return Err(Error::Configuration);
            }
            supply = supply
                .checked_add(value.units)
                .filter(|v| *v <= MAX_UNITS)
                .ok_or(Error::Configuration)?;
        }
        Ok(self)
    }

    pub(crate) fn time(&self) -> Result<BlockTime, Error> {
        BlockTime::from_unix(self.seconds, self.nanos).map_err(|_| Error::Configuration)
    }

    pub(crate) fn accounts(&self) -> Result<Vec<GenesisAccount>, Error> {
        self.accounts
            .iter()
            .map(|a| {
                Ok(GenesisAccount {
                    owner: public_key(&a.public_key)?,
                    units: a.units,
                })
            })
            .collect()
    }

    pub(crate) fn authority(&self) -> Result<[u8; 32], Error> {
        let mut hash = Sha256::new();
        hash.update(b"volparossa/transaction/comet-0.40-test-authority/v1\0");
        hash.update(
            u32::try_from(self.chain_id.len())
                .map_err(|_| Error::Configuration)?
                .to_be_bytes(),
        );
        hash.update(self.chain_id.as_bytes());
        for key in &self.validators {
            hash.update(public_key(key)?);
            hash.update(10_u64.to_be_bytes());
        }
        hash.update(consensus_params().encode_to_vec());
        Ok(hash.finalize().into())
    }

    /// Exact initial validator set; no validator update or dynamic membership is supported.
    ///
    /// # Errors
    /// Rejects malformed public keys.
    pub fn validator_updates(&self) -> Result<Vec<abci::ValidatorUpdate>, Error> {
        self.validators
            .iter()
            .map(|key| {
                Ok(abci::ValidatorUpdate {
                    pub_key: Some(crypto::PublicKey {
                        sum: Some(crypto::public_key::Sum::Ed25519(public_key(key)?.to_vec())),
                    }),
                    power: 10,
                })
            })
            .collect()
    }
}

pub(crate) fn public_key(value: &str) -> Result<[u8; 32], Error> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(Error::Configuration);
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| Error::Configuration)?;
    if bytes == [0; 32] || VerifyingKey::from_bytes(&bytes).is_err() {
        return Err(Error::Configuration);
    }
    Ok(bytes)
}

/// Fixed bounded fixture consensus parameters; no vote extensions or mutable authority.
pub fn consensus_params() -> types::ConsensusParams {
    types::ConsensusParams {
        block: Some(types::BlockParams {
            max_bytes: 98_304,
            max_gas: -1,
        }),
        evidence: Some(types::EvidenceParams {
            max_age_num_blocks: 1000,
            max_age_duration: Some(Duration {
                seconds: 86_400,
                nanos: 0,
            }),
            max_bytes: 8192,
        }),
        validator: Some(types::ValidatorParams {
            pub_key_types: vec!["ed25519".to_owned()],
        }),
        version: Some(types::VersionParams { app: 1 }),
        abci: Some(types::AbciParams {
            vote_extensions_enable_height: 0,
        }),
        authority: Some(types::AuthorityParams {
            authority: String::new(),
        }),
    }
}
