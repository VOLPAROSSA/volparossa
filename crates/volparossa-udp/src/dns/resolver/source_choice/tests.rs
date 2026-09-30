//! Controlled source-sequencing test, not proof of real recursive DNS or DNSSEC.

use super::*;
use crate::DnsAnswerSource;

struct PeerAttempt<'a>(&'a Mutex<Vec<&'static str>>);

impl Drop for PeerAttempt<'_> {
    fn drop(&mut self) {
        self.0.lock().unwrap().push("peer ended");
    }
}

fn answer(source: DnsAnswerSource) -> ValidatedDnsAnswer {
    ValidatedDnsAnswer::new(
        vec!["93.184.216.34".parse().unwrap()],
        Instant::now() + Duration::from_secs(30),
        source,
    )
}

async fn peer(events: &Mutex<Vec<&'static str>>, delay: Duration) -> Option<ValidatedDnsAnswer> {
    events.lock().unwrap().push("peer started");
    let _attempt = PeerAttempt(events);
    tokio::time::sleep(delay).await;
    Some(answer(DnsAnswerSource::PeerValidated))
}

async fn unbound(
    events: &Mutex<Vec<&'static str>>,
) -> Result<ValidatedDnsAnswer, DnsResolverError> {
    events.lock().unwrap().push("unbound started");
    tokio::time::sleep(Duration::from_millis(25)).await;
    Ok(answer(DnsAnswerSource::PrivateUnbound {
        dnssec_secure: true,
    }))
}

#[tokio::test]
async fn sequential_private_sources_back_off_reprobe_and_preserve_privacy_scope() {
    let cache = Mutex::new(Cache::default());
    let events = Mutex::new(Vec::new());
    let deadline = || Instant::now() + Duration::from_secs(5);
    let result = resolve(
        &cache,
        true,
        deadline(),
        peer(&events, Duration::from_secs(1)),
        unbound(&events),
    )
    .await
    .unwrap();
    assert!(matches!(
        result.source(),
        DnsAnswerSource::PrivateUnbound { .. }
    ));
    assert_eq!(
        *events.lock().unwrap(),
        ["peer started", "peer ended", "unbound started"]
    );

    // Another uncached question during the cooldown never even polls its peer
    // future: no repeated 500 ms delay and no simultaneously started worker.
    events.lock().unwrap().clear();
    let result = resolve(
        &cache,
        true,
        deadline(),
        peer(&events, Duration::ZERO),
        unbound(&events),
    )
    .await
    .unwrap();
    assert!(matches!(
        result.source(),
        DnsAnswerSource::PrivateUnbound { .. }
    ));
    assert_eq!(*events.lock().unwrap(), ["unbound started"]);

    // Expire only the chooser clock state; no thirty-second sleeping test.
    {
        let mut state = cache.lock().unwrap();
        state.source_choice.peer_retry_at = Some(Instant::now());
        state.source_choice.next_comparison = Some(Instant::now());
    }
    events.lock().unwrap().clear();
    let result = resolve(
        &cache,
        true,
        deadline(),
        peer(&events, Duration::ZERO),
        unbound(&events),
    )
    .await
    .unwrap();
    assert_eq!(result.source(), DnsAnswerSource::PeerValidated);
    assert_eq!(*events.lock().unwrap(), ["peer started", "peer ended"]);
    assert!(result.ttl_seconds() <= 30);

    // A measured fast peer never overrides absent complete exclusion provenance.
    events.lock().unwrap().clear();
    resolve(
        &cache,
        false,
        deadline(),
        peer(&events, Duration::ZERO),
        unbound(&events),
    )
    .await
    .unwrap();
    assert_eq!(*events.lock().unwrap(), ["unbound started"]);
}
