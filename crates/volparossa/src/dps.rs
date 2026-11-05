// SPDX-License-Identifier: GPL-3.0-only
//! Explicit one-shot positioning inputs; no daemon, location override or sharing.

mod gpsd;

use std::{io::Write, net::SocketAddrV4};

use clap::{Subcommand, ValueEnum};

/// Operator assertion about the receiver, not independently established provenance.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum ProvenanceProfile {
    /// Operator asserts WGS84 and receiver-provided ellipsoidal height in altHAE.
    Wgs84ReceiverEllipsoidal,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Explicitly sample one selected local GPSD through an already installed gpspipe.
    ObserveGpsd {
        /// Numeric IPv4 loopback endpoint with an unprivileged port; never starts GPSD.
        #[arg(long)]
        endpoint: SocketAddrV4,
        /// Explicit receiver provenance assertion; JSON alone cannot verify this claim.
        #[arg(long, value_enum)]
        profile: ProvenanceProfile,
        /// Caller-selected comparison radius (1 through 1,000,000 metres), confidence unknown.
        #[arg(long)]
        comparison_radius_metres: f64,
    },
}

pub async fn run(command: Command) -> anyhow::Result<()> {
    let Command::ObserveGpsd {
        endpoint,
        profile,
        comparison_radius_metres,
    } = command;
    let report = gpsd::observe(endpoint, profile, comparison_radius_metres).await?;
    // No raw input, position, device identity, receiver time or opaque IDs are serialized.
    let mut output = std::io::stdout().lock();
    serde_json::to_writer(&mut output, &report)
        .map_err(|_| anyhow::anyhow!("DPS quality output unavailable"))?;
    output
        .write_all(b"\n")
        .map_err(|_| anyhow::anyhow!("DPS quality output unavailable"))?;
    Ok(())
}
