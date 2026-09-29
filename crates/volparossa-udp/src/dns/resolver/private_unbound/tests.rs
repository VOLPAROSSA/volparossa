//! Pure protocol and real owned-process lifecycle tests, not recursive DNS evidence.

use super::*;

fn response(nonce: [u8; 16], status: u8, secure: bool, address: Option<Ipv4Addr>) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8] = status;
    bytes[16..32].copy_from_slice(&nonce);
    if let Some(address) = address {
        bytes[9] = u8::from(secure);
        bytes[10..12].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..16].copy_from_slice(&12_u32.to_be_bytes());
        bytes.extend_from_slice(&address.octets());
    }
    bytes
}

#[test]
fn private_wire_binds_nonce_family_size_ttl_and_validator_verdict() {
    let question = DnsQuestion::new("fixture.test", DnsQueryType::A).unwrap();
    let nonce = [31; 16];
    let encoded = encode_request(&question, nonce).unwrap();
    assert_eq!(&encoded[..8], MAGIC);
    assert_eq!(&encoded[8..12], &[0, 1, 0, 12]);
    assert_eq!(&encoded[12..16], &[0; 4]);
    assert_eq!(&encoded[16..32], &nonce);
    assert_eq!(&encoded[32..], b"fixture.test");
    let origin = Instant::now() - Duration::from_secs(2);
    for secure in [false, true] {
        let bytes = response(nonce, 0, secure, Some(Ipv4Addr::new(93, 184, 216, 34)));
        let answer = decode_reply(&question, nonce, &bytes, origin).unwrap();
        assert_eq!(
            answer.addresses(),
            ["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert!(answer.ttl_seconds() <= 10);
        assert_eq!(
            answer.source(),
            DnsAnswerSource::PrivateUnbound {
                dnssec_secure: secure
            }
        );
        assert!(decode_reply(&question, [32; 16], &bytes, origin).is_err());
        let v6 = DnsQuestion::new("fixture.test", DnsQueryType::Aaaa).unwrap();
        assert!(decode_reply(&v6, nonce, &bytes, origin).is_err());
        let mut zero = bytes.clone();
        zero[12..16].fill(0);
        assert!(decode_reply(&question, nonce, &zero, origin).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode_reply(&question, nonce, &trailing, origin).is_err());
    }
    for (status, expected) in [
        (1, DnsResolverError::Unavailable),
        (2, DnsResolverError::NameNotFound),
        (3, DnsResolverError::NoData),
        (4, DnsResolverError::Bogus),
        (5, DnsResolverError::InvalidProof),
    ] {
        assert_eq!(
            decode_reply(
                &question,
                nonce,
                &response(nonce, status, false, None),
                origin
            )
            .err(),
            Some(expected)
        );
    }
    assert!(
        decode_reply(
            &question,
            nonce,
            &response(nonce, 0, false, Some(Ipv4Addr::LOCALHOST)),
            origin
        )
        .is_err()
    );
    assert!(decode_reply(&question, nonce, &vec![0; MAX_REPLY_BYTES + 1], origin).is_err());
}

#[tokio::test]
async fn owned_timeout_and_cancel_reap_before_completion_without_network() {
    for cancel in [false, true] {
        let mut child = Command::new("/usr/bin/sleep")
            .arg("30")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let (mut reply, result) = oneshot::channel();
        let deadline = Instant::now() + Duration::from_millis(700);
        if cancel {
            drop(result);
        }
        let answer = supervise(&mut child, b"inert lifecycle fixture", deadline, &mut reply).await;
        assert_eq!(answer.err(), Some(DnsResolverError::Unavailable));
        assert!(Instant::now() < deadline);
        assert!(child.try_wait().unwrap().is_some());
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "exact owned child reaped"
        );
    }
}

#[tokio::test]
async fn reaped_output_is_required_even_when_the_pipe_closes_without_data() {
    let mut child = Command::new("/usr/bin/true")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    let (mut reply, _result) = oneshot::channel();
    let result = supervise(
        &mut child,
        &[],
        Instant::now() + Duration::from_secs(1),
        &mut reply,
    )
    .await;
    if let Ok((bytes, received)) = result {
        assert!(
            decode_reply(
                &DnsQuestion::new("fixture.test", DnsQueryType::A).unwrap(),
                [1; 16],
                &bytes,
                received
            )
            .is_err()
        );
    }
    assert!(child.try_wait().unwrap().is_some());
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}
