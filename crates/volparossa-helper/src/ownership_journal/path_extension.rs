//! Additive durable ownership; original prepare plans and markers never change.

use super::{
    BTreeSet, ContextRole, DURABLE_WIREGUARD_ALIAS_PREFIX, Decoder, DurableWireguardResource,
    JournalError, OwnershipPhase, OwnershipRecord, WireguardLeaseSpec, nonzero, put_u64,
    routing_context_role,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DurablePathExtension {
    pub(crate) extension_id: [u8; 16],
    pub(crate) path_id: u8,
    pub(crate) setup_expires_at_unix: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct RestartExtension {
    path_id: u8,
    setup: u64,
    hard: u64,
    alias: [u8; 128],
    alias_length: u8,
}

impl RestartExtension {
    pub(super) fn from_resource(resource: &DurableWireguardResource) -> Result<Self, JournalError> {
        let bytes = resource.ownership_alias().as_bytes();
        if bytes.len() > 128 {
            return Err(JournalError::InvalidRecord);
        }
        let mut alias = [0; 128];
        alias[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            path_id: resource.key().0,
            setup: resource.setup_expires_at_unix(),
            hard: resource.hard_expires_at_unix(),
            alias,
            alias_length: u8::try_from(bytes.len()).map_err(|_| JournalError::InvalidRecord)?,
        })
    }

    pub(super) fn resource(
        self,
        context_id: [u8; 16],
        role: volparossa_routing::ContextRole,
    ) -> Result<DurableWireguardResource, JournalError> {
        let endpoint = match role {
            volparossa_routing::ContextRole::Client => volparossa_routing::WireguardRole::Client,
            volparossa_routing::ContextRole::Exit => volparossa_routing::WireguardRole::Exit,
            _ => return Err(JournalError::InvalidRecord),
        };
        let specification =
            WireguardLeaseSpec::derive(context_id, role, u32::from(self.path_id), endpoint as i32)
                .map_err(|_| JournalError::InvalidRecord)?;
        Ok(DurableWireguardResource {
            specification,
            ownership_alias: std::str::from_utf8(&self.alias[..usize::from(self.alias_length)])
                .map_err(|_| JournalError::InvalidRecord)?
                .to_owned(),
            setup_expires_at_unix: nonzero(self.setup)?,
            hard_expires_at_unix: nonzero(self.hard)?,
        })
    }
}

impl OwnershipRecord {
    pub(super) fn validate_extensions(&self) -> Result<(), JournalError> {
        if self.extensions.is_empty() {
            return Ok(());
        }
        if !matches!(
            self.plan.context_role,
            ContextRole::Client | ContextRole::Exit
        ) || self.extensions.len() + self.plan.paths.len() > 8
            || self.phase == OwnershipPhase::Intent
        {
            return Err(JournalError::InvalidRecord);
        }
        let mut paths = self
            .plan
            .paths
            .iter()
            .map(|p| p.path_id)
            .collect::<BTreeSet<_>>();
        let mut ids = BTreeSet::new();
        for extension in &self.extensions {
            if extension.extension_id == [0; 16]
                || !(1..=8).contains(&extension.path_id)
                || !paths.insert(extension.path_id)
                || !ids.insert(extension.extension_id)
                || extension.setup_expires_at_unix == 0
                || extension.setup_expires_at_unix > self.hard_expires_at_unix.get()
            {
                return Err(JournalError::InvalidRecord);
            }
        }
        Ok(())
    }

    pub(super) fn extension_resource(
        &self,
        extension: DurablePathExtension,
    ) -> Result<DurableWireguardResource, JournalError> {
        // This projection is deliberately NOT a new Prepare or a replacement for its plan.
        // A domain-separated marker identifies one new resource under the original owner.
        let mut marker = blake3::Hasher::new_derive_key("VOLPAROSSA additive path ownership v1");
        marker.update(&self.journal_epoch_id.0);
        marker.update(&self.origin_runtime_id.0);
        marker.update(&self.ownership_id.0);
        marker.update(&self.context_id.0);
        marker.update(&self.prepare_operation_digest);
        marker.update(&self.generation.get().to_be_bytes());
        marker.update(&extension.extension_id);
        marker.update(&[extension.path_id]);
        marker.update(&extension.setup_expires_at_unix.to_be_bytes());
        marker.update(&self.hard_expires_at_unix.get().to_be_bytes());
        let role = match self.plan.context_role {
            ContextRole::Client => volparossa_routing::WireguardRole::Client,
            ContextRole::Exit => volparossa_routing::WireguardRole::Exit,
            ContextRole::Relay => return Err(JournalError::InvalidRecord),
        };
        let specification = WireguardLeaseSpec::derive(
            self.context_id.0,
            routing_context_role(self.plan.context_role),
            u32::from(extension.path_id),
            role as i32,
        )
        .map_err(|_| JournalError::InvalidRecord)?;
        let ownership_alias = format!(
            "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{}",
            specification.interface(),
            marker.finalize().to_hex()
        );
        Ok(DurableWireguardResource {
            specification,
            ownership_alias,
            setup_expires_at_unix: nonzero(extension.setup_expires_at_unix)?,
            hard_expires_at_unix: self.hard_expires_at_unix,
        })
    }
}

pub(super) fn encode_extensions(encoded: &mut Vec<u8>, extensions: &[DurablePathExtension]) {
    encoded.push(u8::try_from(extensions.len()).expect("validated extension bound"));
    for extension in extensions {
        encoded.extend_from_slice(&extension.extension_id);
        encoded.push(extension.path_id);
        put_u64(encoded, extension.setup_expires_at_unix);
    }
}

pub(super) fn decode_extensions(
    decoder: &mut Decoder<'_>,
) -> Result<Vec<DurablePathExtension>, JournalError> {
    let count = usize::from(decoder.u8()?);
    if count > 7 {
        return Err(JournalError::Corrupt);
    }
    (0..count)
        .map(|_| {
            Ok(DurablePathExtension {
                extension_id: decoder.take::<16>()?,
                path_id: decoder.u8()?,
                setup_expires_at_unix: decoder.u64()?,
            })
        })
        .collect()
}
