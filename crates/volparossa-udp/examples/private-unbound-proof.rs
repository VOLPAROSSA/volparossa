// SPDX-License-Identifier: GPL-3.0-only
//! Disposable KVM-only probe of the real public resolver and packaged native child.
//! This does not establish a normal Client route or reciprocal deployment privacy.

use std::{
    env,
    error::Error,
    fs,
    io::{Read, Write},
    net::IpAddr,
    time::Duration,
};

use tokio::time::{Instant, sleep, timeout};
use volparossa_udp::{
    DnsAnswerSource, DnsQueryType, DnsQuestion, DnsResolutionScope, DnsResolverError, ExitResolver,
    ValidatedDnsAnswer,
};

fn require_disposable_guest() -> Result<(), Box<dyn Error>> {
    let parent = env::var_os("VOLPAROSSA_PRIVATE_DNS_PARENT_MNTNS")
        .ok_or("explicit disposable mount namespace required")?;
    if fs::read_link("/proc/self/ns/mnt")?.as_os_str() == parent
        || fs::read_to_string("/etc/hostname")?.trim() != "volparossa-alpha"
        || !std::process::Command::new("systemd-detect-virt")
            .args(["--quiet", "--vm"])
            .status()?
            .success()
        || !ExitResolver::private_unbound_assets_installed()
    {
        return Err("disposable guest or private resolver assets unavailable".into());
    }
    Ok(())
}

fn await_observer() -> Result<(), Box<dyn Error>> {
    std::io::stdout().flush()?;
    let mut ack = [0];
    std::io::stdin().read_exact(&mut ack)?;
    if ack != [1] {
        return Err("observer did not confirm the live caller cleanup boundary".into());
    }
    Ok(())
}

const fn error_code(error: DnsResolverError) -> &'static str {
    match error {
        DnsResolverError::InvalidQuestion => "InvalidQuestion",
        DnsResolverError::InvalidScope => "InvalidScope",
        DnsResolverError::InvalidProof => "InvalidProof",
        DnsResolverError::Unavailable => "Unavailable",
        DnsResolverError::NameNotFound => "NameNotFound",
        DnsResolverError::NoData => "NoData",
        DnsResolverError::Bogus => "Bogus",
        DnsResolverError::CleanupUnconfirmed => "CleanupUnconfirmed",
    }
}

async fn positive_result(
    case: &str,
    answer: &ValidatedDnsAnswer,
    resolver: &ExitResolver,
    question: &DnsQuestion,
    scope: &DnsResolutionScope,
    elapsed_ms: u128,
) {
    let (source, secure) = match answer.source() {
        DnsAnswerSource::UpstreamValidated => ("independently_validated", true),
        DnsAnswerSource::PrivateUnbound { dnssec_secure } => ("private_unbound", dnssec_secure),
        _ => ("unexpected_source", false),
    };
    let shareable = resolver
        .cached_bundle(question, scope.policy_hash())
        .is_some();
    let ttl = answer.ttl_seconds();
    let mut local_reuse = false;
    let mut ttl_preserved = false;
    if shareable {
        if let Ok(cached) = resolver.resolve(question, scope).await {
            local_reuse = cached.source() == DnsAnswerSource::LocalValidated
                && cached.addresses() == answer.addresses();
            ttl_preserved = cached.ttl_seconds() > 0 && cached.ttl_seconds() <= ttl;
        }
    }
    let mut unrelated_policy = *scope.policy_hash();
    unrelated_policy[0] ^= 1;
    let policy_bound = !resolver.has_shareable_proof(&unrelated_policy)
        && resolver
            .cached_bundle(question, &unrelated_policy)
            .is_none();
    let native_matches = match case {
        "signed" => {
            source == "independently_validated"
                && secure
                && shareable
                && local_reuse
                && ttl_preserved
                && policy_bound
        }
        "unsigned" => source == "private_unbound" && !secure && !shareable,
        _ => false,
    };
    let sentinel: IpAddr = "93.184.216.34".parse().expect("fixed fixture sentinel");
    let passed = native_matches
        && !answer.addresses().is_empty()
        && !answer.addresses().contains(&sentinel)
        && ttl > 0;
    println!(
        "{{\"case\":\"{case}\",\"case_passed\":{passed},\"verdict\":\"positive\",\"source\":\"{source}\",\"dnssec_secure\":{secure},\"ttl_seconds\":{ttl},\"address_count\":{},\"elapsed_ms\":{elapsed_ms},\"os_sentinel\":true,\"shareable_proof\":{shareable},\"local_cache_reuse\":{local_reuse},\"cache_ttl_not_extended\":{ttl_preserved},\"proof_policy_bound\":{policy_bound}}}",
        answer.addresses().len(),
    );
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    require_disposable_guest()?;
    let args = env::args().skip(1).collect::<Vec<_>>();
    let [case] = args.as_slice() else {
        return Err("one fixed fixture case required".into());
    };
    let name = match case.as_str() {
        "signed" | "timeout" | "cancel" => "iana.org",
        "unsigned" => "neverssl.com",
        "bogus" => "dnssec-failed.org",
        _ => return Err("unknown fixture case".into()),
    };
    // Only the disposable mount namespace has this positive /etc/hosts sentinel.
    // A private failure must not be turned into a seemingly successful OS answer.
    let sentinel: IpAddr = "93.184.216.34".parse()?;
    let os_answers = tokio::net::lookup_host((name, 443))
        .await?
        .map(|address| address.ip())
        .collect::<Vec<_>>();
    if os_answers.is_empty() || os_answers.iter().any(|address| *address != sentinel) {
        return Err("isolated OS-positive fallback sentinel missing".into());
    }
    let resolver = ExitResolver::new(None, None).with_private_unbound_fallback()?;
    let question = DnsQuestion::new(name, DnsQueryType::A)?;
    let scope = DnsResolutionScope::without_peers([0; 32]);
    let started = Instant::now();
    if case == "cancel" {
        let mut pending = Box::pin(resolver.resolve(&question, &scope));
        if let Ok(result) = timeout(Duration::from_millis(500), &mut pending).await {
            let error = result.err().map_or("Positive", error_code);
            println!(
                "{{\"case\":\"cancel\",\"case_passed\":false,\"verdict\":\"unexpected_completion\",\"error\":\"{error}\",\"elapsed_ms\":{},\"os_sentinel\":true}}",
                started.elapsed().as_millis()
            );
            return await_observer();
        }
        drop(pending);
        // The observer separately verifies the exact owned child disappears;
        // keep the caller runtime alive so process-exit is not mistaken for cleanup.
        sleep(Duration::from_secs(1)).await;
        println!(
            "{{\"case\":\"cancel\",\"case_passed\":true,\"verdict\":\"cancelled\",\"elapsed_ms\":{},\"os_sentinel\":true}}",
            started.elapsed().as_millis()
        );
        return await_observer();
    }
    let answer = resolver.resolve(&question, &scope).await;
    let elapsed_ms = started.elapsed().as_millis();
    match answer {
        Ok(answer) => {
            positive_result(case, &answer, &resolver, &question, &scope, elapsed_ms).await;
        }
        Err(error) => {
            let passed = (case == "bogus" && error == DnsResolverError::Bogus)
                || (case == "timeout"
                    && error == DnsResolverError::Unavailable
                    && elapsed_ms <= 5_500);
            let verdict = match error {
                DnsResolverError::Bogus => "bogus",
                DnsResolverError::Unavailable => "unavailable",
                _ => "error",
            };
            let code = error_code(error);
            println!(
                "{{\"case\":\"{case}\",\"case_passed\":{passed},\"verdict\":\"{verdict}\",\"error\":\"{code}\",\"os_sentinel\":true,\"elapsed_ms\":{elapsed_ms}}}"
            );
        }
    }
    await_observer()
}
