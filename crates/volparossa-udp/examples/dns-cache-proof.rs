// SPDX-License-Identifier: GPL-3.0-only
//! Fixture-only real DNSSEC collector probe. No alternative trust anchors or AD-bit shortcut.
//! Run against an explicit loopback recursive replay server in a disposable network namespace.

use std::{
    env,
    error::Error,
    fs,
    io::Write,
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, MetadataExt},
    path::Path,
    time::Duration,
};

use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use volparossa_udp::{
    DnsAnswerSource, DnsQueryType, DnsQuestion, DnsResolutionCounts, DnsResolutionScope,
    ExitResolver, ValidatedDnsAnswer,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "--cache-recovery") {
        if args.len() != 5 {
            return Err(
                "recovery requires endpoint, public name, private socket and coordinator PID"
                    .into(),
            );
        }
        return timeout(Duration::from_secs(35), recovery(&args[1..]))
            .await
            .map_err(|_| "cache recovery total deadline")?;
    }
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

// These fixture-only frames contain no commands, names, addresses or remote text.
const WARM_READY: &[u8] = b"DNS_CACHE_RECOVERY_V1 WARM_READY\n";
const UPSTREAM_DOWN: &[u8] = b"DNS_CACHE_RECOVERY_V1 UPSTREAM_DOWN\n";
const OUTAGE_CHECKED: &[u8] = b"DNS_CACHE_RECOVERY_V1 OUTAGE_CHECKED\n";
const UPSTREAM_RESTORED: &[u8] = b"DNS_CACHE_RECOVERY_V1 UPSTREAM_RESTORED\n";
const PROBE_COMPLETE: &[u8] = b"DNS_CACHE_RECOVERY_V1 PROBE_COMPLETE\n";

async fn expect_frame(stream: &mut UnixStream, expected: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut frame = Vec::with_capacity(128);
    for _ in 0..128 {
        let byte = stream.read_u8().await?;
        frame.push(byte);
        if byte == b'\n' {
            return if frame == expected {
                Ok(())
            } else {
                Err("recovery phase mismatch".into())
            };
        }
    }
    Err("recovery phase frame bound".into())
}

struct Snapshot {
    json: String,
    ttl: u32,
}

fn snapshot(
    resolver: &ExitResolver,
    question: &DnsQuestion,
    scope: &DnsResolutionScope,
    answer: &ValidatedDnsAnswer,
    expected: DnsAnswerSource,
) -> Result<Snapshot, Box<dyn Error>> {
    let ttl = answer.ttl_seconds();
    if answer.source() != expected || answer.addresses().is_empty() || ttl == 0 {
        return Err("recovery validated source absent".into());
    }
    let bundle = resolver
        .cached_bundle(question, scope.policy_hash())
        .ok_or("recovery retained proof absent")?;
    let digest = Sha256::digest(bundle.encode());
    let addresses = answer
        .addresses()
        .iter()
        .map(|ip| format!("\"{ip}\""))
        .collect::<Vec<_>>()
        .join(",");
    let source = match expected {
        DnsAnswerSource::UpstreamValidated => "UpstreamValidated",
        DnsAnswerSource::LocalValidated => "LocalValidated",
        _ => return Err("unexpected recovery source".into()),
    };
    Ok(Snapshot {
        ttl,
        json: format!(
            "{{\"source\":\"{source}\",\"ttl_seconds\":{ttl},\"expires_at_ms\":{},\"proof_sha256\":\"{digest:x}\",\"addresses\":[{addresses}]}}",
            bundle.expires_at_unix_ms()
        ),
    })
}

fn counts_json(counts: DnsResolutionCounts) -> String {
    format!(
        "{{\"local_validated\":{},\"peer_validated\":{},\"upstream_validated\":{},\"trusted_fallback\":{}}}",
        counts.local_validated,
        counts.peer_validated,
        counts.upstream_validated,
        counts.trusted_fallback
    )
}

async fn recovery_control(args: &[String]) -> Result<(UnixStream, SocketAddr), Box<dyn Error>> {
    let parent = env::var_os("VOLPAROSSA_DNS_FIXTURE_PARENT_NETNS")
        .ok_or("explicit disposable namespace marker required")?;
    if fs::read_link("/proc/self/ns/net")?.as_os_str() == parent {
        return Err("fixture must not resolve on the parent network".into());
    }
    let endpoint: SocketAddr = args[0].parse()?;
    let coordinator: i32 = args[3].parse()?;
    if !endpoint.ip().is_loopback()
        || endpoint.port() <= 1024
        || coordinator <= 0
        || args[1] != "iana.org"
    {
        return Err("recovery requires fixed public fixture and loopback endpoint".into());
    }
    let path = Path::new(&args[2]);
    let metadata = fs::symlink_metadata(path)?;
    let directory = fs::symlink_metadata(path.parent().ok_or("recovery socket parent absent")?)?;
    if !path.is_absolute()
        || !metadata.file_type().is_socket()
        || metadata.mode() & 0o777 != 0o600
        || !directory.is_dir()
        || directory.mode() & 0o777 != 0o700
        || metadata.uid() != directory.uid()
    {
        return Err("recovery socket boundary".into());
    }
    let control = UnixStream::connect(path).await?;
    let credential = control.peer_cred()?;
    if credential.pid() != Some(coordinator)
        || credential.uid() != metadata.uid()
        || credential.uid() != fs::metadata("/proc/self")?.uid()
    {
        return Err("recovery coordinator identity".into());
    }
    Ok((control, endpoint))
}

async fn recovery(args: &[String]) -> Result<(), Box<dyn Error>> {
    let (mut control, endpoint) = recovery_control(args).await?;
    // This explicit mode may retry the SAME endpoint, but can never fall through to OS DNS.
    let warm = ExitResolver::new(None, None).with_unbound_fallback(endpoint)?;
    let scope = DnsResolutionScope::without_peers([0; 32]);
    let questions = [
        DnsQuestion::new(&args[1], DnsQueryType::A)?,
        DnsQuestion::new(&args[1], DnsQueryType::Aaaa)?,
    ];
    let mut warm_answers = Vec::new();
    let mut warm_snapshots = Vec::new();
    for question in &questions {
        let answer = warm.resolve(question, &scope).await?;
        warm_snapshots.push(snapshot(
            &warm,
            question,
            &scope,
            &answer,
            DnsAnswerSource::UpstreamValidated,
        )?);
        warm_answers.push(answer);
    }
    control.write_all(WARM_READY).await?;
    expect_frame(&mut control, UPSTREAM_DOWN).await?;
    let mut outage_snapshots = Vec::new();
    for (index, question) in questions.iter().enumerate() {
        let answer = warm.resolve(question, &scope).await?;
        let observed = snapshot(
            &warm,
            question,
            &scope,
            &answer,
            DnsAnswerSource::LocalValidated,
        )?;
        if answer.addresses() != warm_answers[index].addresses()
            || observed.ttl > warm_snapshots[index].ttl
        {
            return Err("recovery local binding or remaining TTL changed".into());
        }
        outage_snapshots.push(observed);
    }
    let warm_counts = warm.counts();
    if warm_counts
        != (DnsResolutionCounts {
            local_validated: 2,
            upstream_validated: 2,
            ..DnsResolutionCounts::default()
        })
    {
        return Err("recovery warm source accounting differs".into());
    }
    let cold = ExitResolver::new(None, None).with_unbound_fallback(endpoint)?;
    for question in &questions {
        if cold.resolve(question, &scope).await.is_ok() {
            return Err("cold resolution succeeded during upstream outage".into());
        }
    }
    let cold_outage_counts = cold.counts();
    if cold_outage_counts != DnsResolutionCounts::default() {
        return Err("cold outage source accounting differs".into());
    }
    control.write_all(OUTAGE_CHECKED).await?;
    expect_frame(&mut control, UPSTREAM_RESTORED).await?;
    let mut recovered_snapshots = Vec::new();
    for (index, question) in questions.iter().enumerate() {
        let answer = cold.resolve(question, &scope).await?;
        let observed = snapshot(
            &cold,
            question,
            &scope,
            &answer,
            DnsAnswerSource::UpstreamValidated,
        )?;
        if answer.addresses() != warm_answers[index].addresses()
            || observed.ttl > warm_snapshots[index].ttl
        {
            return Err("recovery public fixture binding or remaining TTL changed".into());
        }
        recovered_snapshots.push(observed);
    }
    let recovered_counts = cold.counts();
    if recovered_counts
        != (DnsResolutionCounts {
            upstream_validated: 2,
            ..DnsResolutionCounts::default()
        })
    {
        return Err("recovered source accounting differs".into());
    }
    report_recovery(
        &warm_snapshots,
        &outage_snapshots,
        &recovered_snapshots,
        warm_counts,
        cold_outage_counts,
        recovered_counts,
    )?;
    control.write_all(PROBE_COMPLETE).await?;
    control.shutdown().await?;
    Ok(())
}

fn report_recovery(
    warm_snapshots: &[Snapshot],
    outage_snapshots: &[Snapshot],
    recovered_snapshots: &[Snapshot],
    warm_counts: DnsResolutionCounts,
    cold_outage_counts: DnsResolutionCounts,
    recovered_counts: DnsResolutionCounts,
) -> Result<(), Box<dyn Error>> {
    for (index, family) in ["A", "AAAA"].iter().enumerate() {
        println!(
            "{{\"schema\":2,\"family\":\"{family}\",\"builtin_anchors\":true,\"cold_outage_error\":true,\"warm\":{},\"outage\":{},\"recovered\":{}}}",
            warm_snapshots[index].json,
            outage_snapshots[index].json,
            recovered_snapshots[index].json
        );
    }
    println!(
        "{{\"schema\":2,\"accounting\":{{\"warm_counts\":{},\"cold_outage_counts\":{},\"recovered_counts\":{}}}}}",
        counts_json(warm_counts),
        counts_json(cold_outage_counts),
        counts_json(recovered_counts)
    );
    std::io::stdout().flush()?;
    Ok(())
}
