// SPDX-License-Identifier: GPL-3.0-only
//! Fixture-only real DNSSEC collector probe. No alternative trust anchors or AD-bit shortcut.
//! Run against an explicit loopback recursive replay server in a disposable network namespace.

use std::{env, error::Error, fs, net::SocketAddr};

use sha2::{Digest, Sha256};
use volparossa_udp::{
    DnsAnswerSource, DnsQueryType, DnsQuestion, DnsResolutionCounts, DnsResolutionScope,
    ExitResolver,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("usage: dns-cache-proof <loopback-ip:port> <public-dns-name>".into());
    }
    let parent = env::var_os("VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS")
        .ok_or("explicit disposable namespace marker required")?;
    if fs::read_link("/proc/self/ns/net")?.as_os_str() == parent {
        return Err("fixture must not resolve on the parent network".into());
    }
    let recursive: SocketAddr = args[0].parse()?;
    if !recursive.ip().is_loopback() || recursive.port() == 0 {
        return Err("fixture recursive endpoint must be explicit nonzero loopback".into());
    }
    let resolver = ExitResolver::new(Some(recursive), None);
    let scope = DnsResolutionScope::without_peers([0; 32]);
    for (kind, label) in [(DnsQueryType::A, "A"), (DnsQueryType::Aaaa, "AAAA")] {
        let question = DnsQuestion::new(&args[1], kind)?;
        let answer = resolver.resolve(&question, &scope).await?;
        if answer.source() != DnsAnswerSource::UpstreamValidated
            || answer.addresses().is_empty()
            || answer.ttl_seconds() == 0
        {
            return Err("actual builtin-anchor positive validation was not proven".into());
        }
        let bundle = resolver
            .cached_bundle(&question, scope.policy_hash())
            .ok_or("validated proof was not retained")?;
        let cached = resolver.resolve(&question, &scope).await?;
        if cached.source() != DnsAnswerSource::LocalValidated
            || cached.addresses() != answer.addresses()
            || cached.ttl_seconds() > answer.ttl_seconds()
        {
            return Err("local validated reuse was not proven".into());
        }
        let addresses = answer
            .addresses()
            .iter()
            .map(|ip| format!("\"{ip}\""))
            .collect::<Vec<_>>()
            .join(",");
        let digest = Sha256::digest(bundle.encode());
        println!(
            "{{\"schema\":1,\"family\":\"{label}\",\"source\":\"UpstreamValidated\",\"local_reuse\":true,\"builtin_anchors\":true,\"ttl_seconds\":{},\"expires_at_ms\":{},\"proof_sha256\":\"{digest:x}\",\"addresses\":[{addresses}]}}",
            cached.ttl_seconds(),
            bundle.expires_at_unix_ms(),
        );
    }
    if resolver.counts()
        != (DnsResolutionCounts {
            local_validated: 2,
            upstream_validated: 2,
            ..DnsResolutionCounts::default()
        })
    {
        return Err("actual resolution source accounting differs".into());
    }
    Ok(())
}
