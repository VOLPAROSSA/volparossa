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
        if timeout(Duration::from_millis(500), &mut pending)
            .await
            .is_ok()
        {
            return Err("native child was not held for cancellation".into());
        }
        drop(pending);
        // The observer separately verifies the exact owned child disappears;
        // keep the caller runtime alive so process-exit is not mistaken for cleanup.
        sleep(Duration::from_secs(1)).await;
        println!("{{\"case\":\"cancel\",\"verdict\":\"cancelled\",\"os_sentinel\":true}}");
        return await_observer();
    }
    let answer = resolver.resolve(&question, &scope).await;
    let elapsed_ms = started.elapsed().as_millis();
    match (case.as_str(), answer) {
        ("signed" | "unsigned", Ok(answer)) => {
            let secure = case == "signed";
            if answer.source()
                != (DnsAnswerSource::PrivateUnbound {
                    dnssec_secure: secure,
                })
                || answer.addresses().is_empty()
                || answer.addresses().contains(&sentinel)
                || answer.ttl_seconds() == 0
                || resolver
                    .cached_bundle(&question, scope.policy_hash())
                    .is_some()
            {
                return Err("native verdict, address, TTL or proof provenance differs".into());
            }
            println!(
                "{{\"case\":\"{case}\",\"verdict\":\"positive\",\"dnssec_secure\":{secure},\"ttl_seconds\":{},\"address_count\":{},\"elapsed_ms\":{elapsed_ms},\"os_sentinel\":true,\"shareable_proof\":false}}",
                answer.ttl_seconds(),
                answer.addresses().len(),
            );
        }
        ("bogus", Err(DnsResolverError::Bogus)) => println!(
            "{{\"case\":\"bogus\",\"verdict\":\"bogus\",\"os_sentinel\":true,\"elapsed_ms\":{elapsed_ms}}}"
        ),
        ("timeout", Err(DnsResolverError::Unavailable)) if elapsed_ms <= 5_500 => println!(
            "{{\"case\":\"timeout\",\"verdict\":\"unavailable\",\"os_sentinel\":true,\"elapsed_ms\":{elapsed_ms}}}"
        ),
        _ => return Err("actual private resolver result did not match this fixture case".into()),
    }
    await_observer()
}
