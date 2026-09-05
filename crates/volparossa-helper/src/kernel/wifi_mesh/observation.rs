//! Kernel observations used for conservative same-channel coexistence and peer status.

use std::collections::{BTreeMap, BTreeSet};

use super::super::{KernelError, NLA_TYPE_MASK, attributes, parse_string_attribute};
use super::netlink::{
    IFINDEX, IFNAME, IFTYPE, INTERFACE_COMBINATIONS, MAC, MESH_CONFIG, MESH_POINT,
    SOFTWARE_IFTYPES, STA_INFO, SUPPORTED_IFTYPES, WIPHY, WIPHY_BANDS, WIPHY_FREQ, field, nested,
    number, number_field, required,
};
use super::{MeshPeer, WifiMeshConfig};

#[derive(Debug)]
pub(super) struct Interface {
    pub wiphy: u32,
    pub index: Option<u32>,
    pub name: Option<String>,
    pub kind: u32,
    pub frequency: Option<u32>,
}

impl Interface {
    pub fn parse(data: &[u8]) -> Result<Self, KernelError> {
        let fields = attributes(data)?;
        Ok(Self {
            wiphy: number_field(&fields, WIPHY)?,
            index: field(&fields, IFINDEX)?.map(number).transpose()?,
            name: field(&fields, IFNAME)?
                .map(|value| parse_string_attribute(value, 15))
                .transpose()?,
            kind: number_field(&fields, IFTYPE)?,
            frequency: field(&fields, WIPHY_FREQ)?.map(number).transpose()?,
        })
    }
}

#[derive(Debug, Default)]
pub(super) struct Radio {
    supported: BTreeSet<u32>,
    software: BTreeSet<u32>,
    usable_frequency: bool,
    combinations: Vec<Combination>,
}

#[derive(Debug)]
struct Combination {
    maximum: u32,
    channels: u32,
    limits: Vec<(u32, BTreeSet<u32>)>,
}

impl Radio {
    pub fn parse(records: &[Vec<u8>], wiphy: u32, frequency: u32) -> Result<Self, KernelError> {
        let mut result = Self::default();
        let mut seen = false;
        for record in records {
            let fields = attributes(record)?;
            if number_field(&fields, WIPHY)? != wiphy {
                return Err(KernelError::Malformed);
            }
            seen = true;
            if let Some(value) = field(&fields, SUPPORTED_IFTYPES)? {
                result.supported.extend(types(value)?);
            }
            if let Some(value) = field(&fields, SOFTWARE_IFTYPES)? {
                result.software.extend(types(value)?);
            }
            if let Some(value) = field(&fields, WIPHY_BANDS)? {
                result.read_frequencies(value, frequency)?;
            }
            if let Some(value) = field(&fields, INTERFACE_COMBINATIONS)? {
                for (_, combination) in attributes(value)? {
                    if result.combinations.len() >= 32 {
                        return Err(KernelError::Malformed);
                    }
                    result.combinations.push(Combination::parse(combination)?);
                }
            }
        }
        if !seen || !result.supported.contains(&MESH_POINT) || !result.usable_frequency {
            return Err(KernelError::Invalid);
        }
        Ok(result)
    }

    fn read_frequencies(&mut self, bands: &[u8], requested: u32) -> Result<(), KernelError> {
        for (_, band) in attributes(bands)? {
            let fields = attributes(band)?;
            let Some(frequencies) = field(&fields, 1)? else {
                continue;
            };
            for (_, frequency) in attributes(frequencies)? {
                let fields = attributes(frequency)?;
                if number_field(&fields, 1)? != requested {
                    continue;
                }
                // NL80211_FREQUENCY_ATTR_DISABLED, NO_IR, RADAR, NO_20MHZ.
                // This provider does not initiate DFS/CAC or reinterpret regulatory restrictions.
                if [2, 3, 5, 16]
                    .into_iter()
                    .any(|kind| field(&fields, kind).map_or(true, |value| value.is_some()))
                {
                    return Err(KernelError::Invalid);
                }
                self.usable_frequency = true;
            }
        }
        Ok(())
    }

    pub fn admit(&self, active: &[Interface], frequency: u32) -> Result<(), KernelError> {
        let mut counts = BTreeMap::<u32, u32>::new();
        counts.insert(MESH_POINT, 1);
        for interface in active {
            if self.software.contains(&interface.kind) {
                continue;
            }
            // Even a multi-channel-capable radio may not silently retune an existing participant.
            // Missing channel information is not permission to guess that a managed link is idle.
            if interface.frequency != Some(frequency) {
                return Err(KernelError::Invalid);
            }
            *counts.entry(interface.kind).or_default() += 1;
        }
        if counts.values().sum::<u32>() == 1 {
            return Ok(());
        }
        if self.combinations.iter().any(|value| value.admits(&counts)) {
            Ok(())
        } else {
            Err(KernelError::Invalid)
        }
    }
}

impl Combination {
    fn parse(value: &[u8]) -> Result<Self, KernelError> {
        let fields = attributes(value)?;
        let mut limits = Vec::new();
        for (_, limit) in nested(&fields, 1)? {
            if limits.len() >= 16 {
                return Err(KernelError::Malformed);
            }
            let fields = attributes(limit)?;
            limits.push((number_field(&fields, 1)?, types(required(&fields, 2)?)?));
        }
        Ok(Self {
            maximum: number_field(&fields, 2)?,
            channels: number_field(&fields, 4)?,
            limits,
        })
    }

    fn admits(&self, counts: &BTreeMap<u32, u32>) -> bool {
        self.channels > 0
            && counts.values().sum::<u32>() <= self.maximum
            && counts.keys().all(|kind| {
                self.limits
                    .iter()
                    .filter(|(_, types)| types.contains(kind))
                    .count()
                    == 1
            })
            && self.limits.iter().all(|(maximum, types)| {
                counts
                    .iter()
                    .filter(|(kind, _)| types.contains(kind))
                    .map(|(_, value)| value)
                    .sum::<u32>()
                    <= *maximum
            })
    }
}

fn types(value: &[u8]) -> Result<BTreeSet<u32>, KernelError> {
    let mut result = BTreeSet::new();
    for (kind, value) in attributes(value)? {
        let kind = kind & NLA_TYPE_MASK;
        if !value.is_empty() || kind == 0 || kind > 32 || !result.insert(u32::from(kind)) {
            return Err(KernelError::Malformed);
        }
    }
    Ok(result)
}

pub(super) fn verify_mesh_configuration(
    data: &[u8],
    config: &WifiMeshConfig,
) -> Result<(), KernelError> {
    let fields = attributes(data)?;
    let mesh = nested(&fields, MESH_CONFIG)?;
    // Linux GET_MESH_CONFIG places IFINDEX *inside* this nest, colliding numerically with
    // HOLDING_TIMEOUT. Read only the required, unambiguous configuration keys.
    if required(&mesh, 4)? != config.maximum_peers.to_ne_bytes()
        || required(&mesh, 14)? != [0]
        || required(&mesh, 17)? != [0]
        || required(&mesh, 19)? != [0]
    {
        return Err(KernelError::Invalid);
    }
    Ok(())
}

pub(super) fn peers(
    records: &[Vec<u8>],
    index: u32,
    maximum: u16,
) -> Result<Vec<MeshPeer>, KernelError> {
    if records.len() > usize::from(maximum) {
        return Err(KernelError::Malformed);
    }
    let mut result = Vec::new();
    let mut seen = BTreeSet::new();
    for record in records {
        let fields = attributes(record)?;
        if number_field(&fields, IFINDEX)? != index {
            return Err(KernelError::Malformed);
        }
        let mac: [u8; 6] = required(&fields, MAC)?
            .try_into()
            .map_err(|_| KernelError::Malformed)?;
        if mac == [0; 6] || mac[0] & 1 != 0 || !seen.insert(mac) {
            return Err(KernelError::Malformed);
        }
        let info = nested(&fields, STA_INFO)?;
        let state = required(&info, 6)?;
        if state.len() != 1 || state[0] > 6 {
            return Err(KernelError::Malformed);
        }
        result.push(MeshPeer {
            mac,
            established: state == [4], // NL80211_PLINK_ESTAB, not merely a discovered station.
            rx_bytes: bytes_counter(&info, 23, 2)?,
            tx_bytes: bytes_counter(&info, 24, 3)?,
            rx_packets: u64::from(number_field(&info, 9)?),
            tx_packets: u64::from(number_field(&info, 10)?),
        });
    }
    result.sort_by_key(|peer| peer.mac);
    Ok(result)
}

fn bytes_counter(fields: &[(u16, &[u8])], wide: u16, narrow: u16) -> Result<u64, KernelError> {
    if let Some(value) = field(fields, wide)? {
        return Ok(u64::from_ne_bytes(
            value.try_into().map_err(|_| KernelError::Malformed)?,
        ));
    }
    Ok(u64::from(number_field(fields, narrow)?))
}
