// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/gpl-3.0.html>
//
// Full details available at https://saorsalabs.com/licenses

//! Regression tests for ant-quic#270 (x0x#505): PQC handshakes must not rely on IP
//! fragmentation.
//!
//! Before the fix, three cooperating defects made PQC-negotiating endpoints emit
//! 4096-byte UDP datagrams during (and after) the handshake:
//!
//! 1. `PqcState::min_initial_size()` returned `max(handshake_mtu, 4096)` whenever the peer
//!    advertised ML-KEM/ML-DSA, and every padding-required datagram was padded to it.
//! 2. `PacketBuilder::pad_to` raised the packet minimum past the builder's datagram
//!    capacity without a cap, and `finish()` blindly grew and encrypted the buffer.
//! 3. `read_crypto` reset `MtuDiscovery` to 4096 mid-handshake whenever PQC was detected in
//!    CRYPTO bytes, raising `path.current_mtu()` without any probe.
//!
//! On paths that drop non-initial IP fragments (e.g. Oracle Cloud) the handshake never
//! completed. RFC 9000 §14 requires datagrams to fit 1200 bytes until a larger PLPMTU is
//! validated by DPLPMTUD probes, which only run after the handshake.
//!
//! These tests drive a full client↔server handshake through the low-level state machines
//! (no sockets — loopback MTUs would hide the defect) and assert the invariant at the
//! `Transmit` boundary.

use std::{
    io::Cursor,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};

use bytes::{Bytes, BytesMut};

use super::ConnectionSide;
use crate::{
    ClientConfig, Connection, ConnectionError, ConnectionHandle, ConnectionId, EndpointConfig,
    Event, ServerConfig, TransportConfig, TransportErrorCode,
    crypto::{
        pqc::PqcConfig,
        rustls::{QuicClientConfig, QuicServerConfig, configured_provider_with_pqc},
    },
    endpoint::{DatagramEvent, Endpoint},
    frame::{self, FrameStruct},
    packet::{
        FixedLengthConnectionIdParser, Header, InitialHeader, PacketNumber, ProtectedHeader,
        SpaceId,
    },
};

/// Smallest allowed maximum datagram size (RFC 9000 §14); the crate's `MIN_INITIAL_SIZE`.
const MIN_INITIAL_SIZE: usize = 1200;

const SERVER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4433);

#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

fn generate_test_cert() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = cert.cert.into();
    let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (cert_der, key_der)
}

fn server_config() -> Arc<ServerConfig> {
    let (cert, key) = generate_test_cert();
    let provider = configured_provider_with_pqc(Some(&PqcConfig::default()));

    let mut server_crypto = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    server_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut config =
        ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_crypto).unwrap()));
    // Default transport: initial MTU 1200, PQC algorithms advertised (ML-KEM-768/ML-DSA-65).
    config.transport_config(Arc::new(TransportConfig::default()));
    Arc::new(config)
}

fn client_config() -> ClientConfig {
    let provider = configured_provider_with_pqc(Some(&PqcConfig::default()));
    let mut client_crypto = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    client_crypto.alpn_protocols = vec![b"test".to_vec()];

    let mut config =
        ClientConfig::new(Arc::new(QuicClientConfig::try_from(client_crypto).unwrap()));
    config.transport_config(Arc::new(TransportConfig::default()));
    config
}

struct Peer {
    endpoint: Endpoint,
    conn: Option<Connection>,
    handle: Option<ConnectionHandle>,
    connected: bool,
}

/// Feed one datagram into `peer`'s endpoint and route everything it produces.
fn ingress(now: crate::Instant, data: BytesMut, from_addr: SocketAddr, peer: &mut Peer) {
    let mut scratch = Vec::new();
    match peer
        .endpoint
        .handle(now, from_addr, None, None, data, &mut scratch)
    {
        Some(DatagramEvent::ConnectionEvent(_, event)) => {
            if let Some(conn) = peer.conn.as_mut() {
                conn.handle_event(event);
            }
        }
        Some(DatagramEvent::NewConnection(incoming)) => {
            let (handle, conn) = peer
                .endpoint
                .accept(incoming, now, &mut scratch, None)
                .expect("accept first client Initial");
            peer.handle = Some(handle);
            peer.conn = Some(conn);
        }
        Some(DatagramEvent::Response(_)) | None => {}
    }
}

/// Poll `peer`'s connection for transmits and events, delivering each datagram to `other`.
/// Returns whether anything happened. Records every transmitted datagram size.
fn pump(now: crate::Instant, peer: &mut Peer, other: &mut Peer, sizes: &mut Vec<usize>) -> bool {
    let mut progress = false;

    // Connection → endpoint events (identifier retirement, drain, …)
    let handle = peer.handle.unwrap();
    while let Some(event) = peer.conn.as_mut().unwrap().poll_endpoint_events() {
        if let Some(response) = peer.endpoint.handle_event(handle, event) {
            if let Some(conn) = peer.conn.as_mut() {
                conn.handle_event(response);
            }
        }
        progress = true;
    }

    // Application events
    while let Some(event) = peer.conn.as_mut().unwrap().poll() {
        if matches!(event, Event::Connected) {
            peer.connected = true;
        }
        progress = true;
    }

    // Transmits → deliver to the other side
    {
        let conn = peer.conn.as_mut().unwrap();
        let mut buf = Vec::with_capacity(65_536);
        while let Some(transmit) = conn.poll_transmit(now, 1, &mut buf) {
            sizes.push(transmit.size);
            let datagram = BytesMut::from(&buf[..transmit.size]);
            ingress(now, datagram, transmit.destination, other);
            buf.clear();
            progress = true;
        }
    }

    progress
}

/// Drive the pair until both report `Connected` or the round budget is exhausted, advancing
/// the simulated clock by 25 ms whenever a round makes no progress (loss/PTO timers).
fn drive_to_connected(client: &mut Peer, server: &mut Peer) -> (Vec<usize>, crate::Instant) {
    let mut now = crate::Instant::now();
    let mut sizes = Vec::new();
    for _ in 0..400 {
        let mut progress = false;
        progress |= pump(now, client, server, &mut sizes);
        progress |= pump(now, server, client, &mut sizes);
        if client.connected && server.connected {
            return (sizes, now);
        }
        if !progress {
            now += crate::Duration::from_millis(25);
            for peer in [&mut *client, &mut *server] {
                if let Some(conn) = peer.conn.as_mut() {
                    if conn.poll_timeout().is_some_and(|deadline| deadline <= now) {
                        conn.handle_timeout(now);
                    }
                }
            }
        }
    }
    (sizes, now)
}

fn make_peer_pair() -> (Peer, Peer) {
    let server = Peer {
        // allow_mtud = false: no DPLPMTUD probes may authorize >1200-byte datagrams, which
        // is exactly the environment a fragment-filtering path presents pre-validation.
        endpoint: Endpoint::new(
            Arc::new(EndpointConfig::default()),
            Some(server_config()),
            false,
            None,
        ),
        conn: None,
        handle: None,
        connected: false,
    };
    let mut client = Peer {
        endpoint: Endpoint::new(Arc::new(EndpointConfig::default()), None, false, None),
        conn: None,
        handle: None,
        connected: false,
    };
    let (handle, conn) = client
        .endpoint
        .connect(
            crate::Instant::now(),
            client_config(),
            SERVER_ADDR,
            "localhost",
        )
        .expect("initiate client connection");
    client.handle = Some(handle);
    client.conn = Some(conn);
    (client, server)
}

/// The core regression: a full PQC handshake over a 1200-byte path. Before the fix the
/// server padded its first ack-eliciting Initial to 4096 bytes and the client's subsequent
/// Handshake flights went out up to 4096 bytes after `MtuDiscovery` was reset mid-flight.
#[test]
fn pqc_handshake_datagrams_stay_within_1200_bytes() {
    let (mut client, mut server) = make_peer_pair();
    let (sizes, _) = drive_to_connected(&mut client, &mut server);

    assert!(
        client.connected && server.connected,
        "PQC handshake must complete over a 1200-byte path; got {} datagrams",
        sizes.len()
    );
    assert!(
        sizes.len() > 4,
        "expected a multi-flight PQC handshake, saw only {} datagrams",
        sizes.len()
    );

    // RFC 9000 §14: nothing above the smallest allowed maximum datagram size before
    // PLPMTU validation. This is the assertion that fails on the pre-fix code with
    // 4096-byte padded Initials.
    let offenders: Vec<usize> = sizes
        .iter()
        .copied()
        .filter(|&size| size > MIN_INITIAL_SIZE)
        .collect();
    assert_eq!(
        offenders,
        Vec::<usize>::new(),
        "datagrams exceeded 1200 bytes during PQC handshake"
    );

    // RFC 9000 §14.1: the client's first Initial datagram must be padded to at least 1200.
    assert_eq!(
        sizes.first(),
        Some(&MIN_INITIAL_SIZE),
        "client's first Initial must be padded to exactly 1200 bytes"
    );

    // PQC negotiation must not have raised the unvalidated path MTU on either side.
    assert_eq!(
        client.conn.as_ref().unwrap().current_mtu(),
        MIN_INITIAL_SIZE as u16
    );
    assert_eq!(
        server.conn.as_ref().unwrap().current_mtu(),
        MIN_INITIAL_SIZE as u16
    );
}

/// `PqcState::min_initial_size` clamps the PQC floor to the current validated PLPMTU.
#[test]
fn pqc_min_initial_size_is_clamped_to_path_mtu() {
    use crate::MIN_INITIAL_SIZE;
    use crate::transport_parameters::{PqcAlgorithms, TransportParameters};

    use super::PqcState;

    let mut state = PqcState::new();
    let mut params = TransportParameters::default();
    params.pqc_algorithms = Some(PqcAlgorithms {
        ml_kem_768: true,
        ml_dsa_65: true,
    });
    state.update_from_peer_params(&params);
    assert!(state.enabled && state.using_pqc && state.handshake_mtu == 4096);

    // During the handshake the path MTU is the unvalidated 1200-byte default.
    assert_eq!(state.min_initial_size(MIN_INITIAL_SIZE), MIN_INITIAL_SIZE);
    // Only a validated larger PLPMTU admits larger PQC padding.
    assert_eq!(state.min_initial_size(1500), 1500);
    assert_eq!(state.min_initial_size(4096), 4096);
    // A path MTU below the RFC floor still yields the floor, never less.
    assert_eq!(state.min_initial_size(576), MIN_INITIAL_SIZE);

    // Without PQC the answer is always the RFC minimum.
    let plain = PqcState::new();
    assert_eq!(plain.min_initial_size(1500), MIN_INITIAL_SIZE);
}

/// `PacketBuilder::pad_to` must never raise a packet's minimum past the datagram capacity,
/// whatever the caller requests. This is the backstop that makes every other policy bug
/// harmless.
#[test]
fn packet_builder_pad_to_is_capped_at_datagram_capacity() {
    use super::packet_builder::PacketBuilder;

    // Build a real builder through the production constructor over a 1200-byte datagram
    // buffer, mirroring `poll_transmit`'s single-datagram path.
    let (mut client, _server) = make_peer_pair();
    let conn = client.conn.as_mut().unwrap();
    let mut buf = Vec::with_capacity(MIN_INITIAL_SIZE);
    let buf_capacity = MIN_INITIAL_SIZE;
    let mut builder = PacketBuilder::new(
        crate::Instant::now(),
        crate::packet::SpaceId::Initial,
        conn.rem_cids.active(),
        &mut buf,
        buf_capacity,
        0,
        true,
        conn,
    )
    .expect("build Initial packet");

    // The pre-fix bug: request the PQC 4096-byte floor.
    builder.pad_to(4096);
    assert!(
        builder.min_size <= builder.max_size,
        "pad_to must not raise min_size past max_size ({} > {})",
        builder.min_size,
        builder.max_size
    );

    let (len, _padded) = builder.finish(conn, &mut buf);
    assert!(
        buf.len() <= buf_capacity,
        "encrypted datagram {} exceeds buffer capacity {buf_capacity}",
        buf.len()
    );
    assert_eq!(len, buf.len());
    // And it is a compliant Initial: padded to exactly 1200 bytes.
    assert_eq!(buf.len(), MIN_INITIAL_SIZE);
    // Sanity: the padded datagram starts with an Initial long header (both header bits set).
    assert_eq!(buf[0] & 0xc0, 0xc0);
}

/// Off-path responses must preserve the challenge, not let zero padding become its payload.
#[test]
fn off_path_response_echoes_token_and_validates_peer_path() {
    let (mut client, mut server) = make_peer_pair();
    let (_, now) = drive_to_connected(&mut client, &mut server);
    assert!(client.connected && server.connected);
    let candidate = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4444);
    let token = 0x0123_4567_89ab_cdef;

    let client_conn = client.conn.as_mut().unwrap();
    client_conn.nat_traversal = None;
    assert_ne!(candidate, client_conn.path.remote);
    client_conn.path_responses = super::paths::PathResponses::default();
    client_conn.path_responses.push(0, token, candidate);
    let mut buf = Vec::with_capacity(65_536);
    let transmit = client_conn.poll_transmit(now, 1, &mut buf).unwrap();
    assert_eq!(transmit.destination, candidate);
    assert_eq!(transmit.size, MIN_INITIAL_SIZE);
    assert_eq!(transmit.segment_size, None);

    // Feed the actual encrypted datagram through the peer's endpoint and connection.
    // Its outstanding nonzero token is the oracle, independent of sender-side counters.
    let server_conn = server.conn.as_mut().unwrap();
    server_conn.path.challenge = Some(token);
    server_conn.path.validated = false;
    let source = server_conn.path.remote;
    ingress(
        now,
        BytesMut::from(&buf[..transmit.size]),
        source,
        &mut server,
    );
    let server_conn = server.conn.as_ref().unwrap();
    assert_eq!(
        server_conn.path.challenge, None,
        "peer must accept echoed token"
    );
    assert!(server_conn.path.validated);
}

/// A coordinated punch must be a finished, authenticated packet before it is returned.
#[test]
fn coordinated_path_challenge_is_padded_and_decoded_by_peer() {
    use super::nat_traversal::{CoordinationPhase, NatTraversalState, PunchTarget};

    let (mut client, mut server) = make_peer_pair();
    let (_, now) = drive_to_connected(&mut client, &mut server);
    assert!(client.connected && server.connected);
    let token = 0xfedc_ba98_7654_3210;
    let client_conn = client.conn.as_mut().unwrap();
    let destination = client_conn.path.remote;
    let mut nat = NatTraversalState::new(4, crate::Duration::from_secs(10));
    nat.prime_passive_coordination_target(
        crate::VarInt::from_u32(1),
        PunchTarget {
            remote_addr: destination,
            remote_sequence: crate::VarInt::from_u32(1),
            challenge: token,
        },
        now,
    )
    .unwrap();
    assert_eq!(
        nat.get_coordination_phase(),
        Some(CoordinationPhase::Preparing)
    );
    client_conn.nat_traversal = Some(nat);
    let now = now + crate::Duration::from_millis(500);
    let mut buf = Vec::with_capacity(65_536);
    let transmit = client_conn.poll_transmit(now, 1, &mut buf).unwrap();
    assert_eq!(transmit.destination, destination);
    assert_eq!(transmit.segment_size, None);
    assert_eq!(
        client_conn
            .nat_traversal
            .as_ref()
            .unwrap()
            .get_coordination_phase(),
        Some(CoordinationPhase::Validating)
    );

    let server_conn = server.conn.as_mut().unwrap();
    server_conn.path_responses = super::paths::PathResponses::default();
    let source = server_conn.path.remote;
    ingress(
        now,
        BytesMut::from(&buf[..transmit.size]),
        source,
        &mut server,
    );
    assert_eq!(
        server
            .conn
            .as_mut()
            .unwrap()
            .path_responses
            .pop_on_path(source),
        Some(token),
        "peer must authenticate and decode the coordinated challenge"
    );
    assert_eq!(transmit.size, MIN_INITIAL_SIZE);
}

/// GHSA-wppq-2f6r-wfvm: a Retry whose token leaves no room for a CRYPTO or
/// CONNECTION_CLOSE frame must close the connection instead of building an Initial.
/// The limit is quinn-proto 0.11.19's `max(Crypto::SIZE_BOUND + 1, ConnectionClose::SIZE_BOUND)`.
/// Impact on this tree was not confirmed before the port.
#[test]
fn oversized_retry_token_is_rejected() {
    // Token lengths from quinn-proto 0.11.19's `oversized_retry_token`: 64 still fits a
    // 1200-byte Initial; 1200 does not. The boundary in between depends on header size.
    for (token_len, fits) in [(64usize, true), (1200, false)] {
        let (mut client, _server) = make_peer_pair();
        let now = crate::Instant::now();
        let mut buf = Vec::new();
        let transmit = client
            .conn
            .as_mut()
            .unwrap()
            .poll_transmit(now, 1, &mut buf)
            .expect("client Initial");
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&buf[..transmit.size]);
        let ProtectedHeader::Initial(initial) = ProtectedHeader::decode(
            &mut Cursor::new(bytes),
            &FixedLengthConnectionIdParser::new(0),
            crate::DEFAULT_SUPPORTED_VERSIONS,
            true,
        )
        .expect("client Initial header") else {
            panic!("expected an Initial packet");
        };

        let header = Header::Retry {
            src_cid: ConnectionId::new(&[1; 20]),
            dst_cid: initial.src_cid,
            version: initial.version,
        };
        let mut retry = Vec::new();
        header.encode(&mut retry);
        retry.resize(retry.len() + token_len, 0);
        let tag = server_config()
            .crypto
            .retry_tag(initial.version, &initial.dst_cid, &retry);
        retry.extend_from_slice(&tag);

        let Some(DatagramEvent::ConnectionEvent(_, event)) = client.endpoint.handle(
            now,
            SERVER_ADDR,
            None,
            None,
            BytesMut::from(&retry[..]),
            &mut buf,
        ) else {
            panic!("Retry must be routed to the client connection");
        };
        client.conn.as_mut().unwrap().handle_event(event);

        let now = now + crate::Duration::from_secs(1);
        let crypto_before = client.conn.as_ref().unwrap().stats().frame_tx.crypto;
        buf.clear();
        buf.shrink_to_fit();
        let sent = client
            .conn
            .as_mut()
            .unwrap()
            .poll_transmit(now, 1, &mut buf)
            .is_some();
        assert_eq!(sent, fits, "token {token_len}");
        if fits {
            assert!(client.conn.as_ref().unwrap().stats().frame_tx.crypto > crypto_before);
            assert!(buf.len() <= MIN_INITIAL_SIZE);
        } else {
            assert!(
                buf.capacity() < 64 * 1024,
                "poll_transmit retained {} bytes after a {}-byte Retry token",
                buf.capacity(),
                token_len
            );
            assert!(buf.is_empty());
            let conn = client.conn.as_mut().unwrap();
            let mut lost = None;
            while let Some(event) = conn.poll() {
                if let Event::ConnectionLost { reason } = event {
                    lost = Some(reason);
                }
            }
            match lost {
                Some(ConnectionError::TransportError(err))
                    if err.code == TransportErrorCode::PROTOCOL_VIOLATION => {}
                other => panic!("expected PROTOCOL_VIOLATION, got {other:?}"),
            }
            assert!(conn.poll_transmit(now, 1, &mut buf).is_none());
        }
    }
}

/// Bytes of an Initial header with a token of `token_len`, using the same layout
/// `PacketBuilder` writes (empty buffer, so the header starts at 0).
fn encoded_initial_header_len(
    src_cid: ConnectionId,
    dst_cid: ConnectionId,
    version: u32,
    packet_number: u64,
    largest_acked: u64,
    token_len: usize,
) -> usize {
    let header = Header::Initial(InitialHeader {
        src_cid,
        dst_cid,
        token: Bytes::from(vec![0u8; token_len]),
        number: PacketNumber::new(packet_number, largest_acked),
        version,
    });
    let mut encoded = Vec::new();
    header.encode(&mut encoded);
    encoded.len()
}

/// Token length that leaves exactly `frame_space` bytes between the encoded Initial
/// header and the AEAD tag. The caller checks that `max_size >= min_size`, which is
/// the other arm of the same `if`.
fn token_len_leaving_frame_space(
    src_cid: ConnectionId,
    dst_cid: ConnectionId,
    version: u32,
    packet_number: u64,
    largest_acked: u64,
    sample_size: usize,
    tag_len: usize,
    mtu: usize,
    frame_space: usize,
) -> usize {
    let max_size = mtu - tag_len;
    // 64 shares the two-byte token-length varint with the lengths this derives.
    let overhead =
        encoded_initial_header_len(src_cid, dst_cid, version, packet_number, largest_acked, 64)
            - 64;
    let token_len = max_size - frame_space - overhead;
    let header_len = encoded_initial_header_len(
        src_cid,
        dst_cid,
        version,
        packet_number,
        largest_acked,
        token_len,
    );
    assert_eq!(
        max_size.saturating_sub(header_len),
        frame_space,
        "token {token_len} produced header {header_len}, not {frame_space} bytes of frame space"
    );
    let number = PacketNumber::new(packet_number, largest_acked);
    let min_size = Ord::max(
        header_len + (sample_size + 4).saturating_sub(number.len() + tag_len),
        dst_cid.len() + 6,
    );
    assert!(
        max_size >= min_size,
        "token {token_len} has max_size {max_size} < min_size {min_size}; only the frame-space check may decide this case"
    );
    token_len
}

fn required_initial_frame_space() -> usize {
    // Same expression as `PacketBuilder::new`. 25 in this tree: Crypto::SIZE_BOUND is 17.
    Ord::max(
        frame::Crypto::SIZE_BOUND + 1,
        frame::ConnectionClose::SIZE_BOUND,
    )
}

/// GHSA-wppq-2f6r-wfvm frame-space arm, on its own.
///
/// A Retry token that leaves exactly `required_frame_space` bytes still carries a CRYPTO
/// frame. One byte less closes with PROTOCOL_VIOLATION. Both lengths satisfy
/// `max_size >= min_size`, so deleting the 25-byte comparison makes the short case pass.
#[test]
fn retry_token_frame_space_boundary() {
    let required = required_initial_frame_space();
    assert_eq!(required, 25, "quinn-proto 0.11.19 frame-space cap");

    for frame_space in [required, required - 1] {
        let (mut client, _server) = make_peer_pair();
        let now = crate::Instant::now();
        let mut buf = Vec::new();
        let transmit = client
            .conn
            .as_mut()
            .unwrap()
            .poll_transmit(now, 1, &mut buf)
            .expect("client Initial");
        let mut bytes = BytesMut::new();
        bytes.extend_from_slice(&buf[..transmit.size]);
        let ProtectedHeader::Initial(initial) = ProtectedHeader::decode(
            &mut Cursor::new(bytes),
            &FixedLengthConnectionIdParser::new(0),
            crate::DEFAULT_SUPPORTED_VERSIONS,
            true,
        )
        .expect("client Initial header") else {
            panic!("expected an Initial packet");
        };

        let (token_len, src_cid, packet_number) = {
            let conn = client.conn.as_ref().unwrap();
            let crypto = conn.spaces[SpaceId::Initial]
                .crypto
                .as_ref()
                .expect("initial keys");
            let packet_number = conn.spaces[SpaceId::Initial].next_packet_number;
            let token_len = token_len_leaving_frame_space(
                conn.handshake_cid,
                ConnectionId::new(&[1; 20]),
                conn.version,
                packet_number,
                0,
                crypto.header.local.sample_size(),
                crypto.packet.local.tag_len(),
                usize::from(conn.current_mtu()),
                frame_space,
            );
            (token_len, conn.handshake_cid, packet_number)
        };

        let header = Header::Retry {
            src_cid: ConnectionId::new(&[1; 20]),
            dst_cid: initial.src_cid,
            version: initial.version,
        };
        let mut retry = Vec::new();
        header.encode(&mut retry);
        retry.resize(retry.len() + token_len, 0);
        let tag = server_config()
            .crypto
            .retry_tag(initial.version, &initial.dst_cid, &retry);
        retry.extend_from_slice(&tag);
        let Some(DatagramEvent::ConnectionEvent(_, event)) = client.endpoint.handle(
            now,
            SERVER_ADDR,
            None,
            None,
            BytesMut::from(&retry[..]),
            &mut buf,
        ) else {
            panic!("Retry must be routed to the client connection");
        };
        client.conn.as_mut().unwrap().handle_event(event);

        {
            let conn = client.conn.as_ref().unwrap();
            assert_eq!(conn.handshake_cid, src_cid);
            assert_eq!(conn.rem_cids.active(), ConnectionId::new(&[1; 20]));
            assert_eq!(
                conn.spaces[SpaceId::Initial].next_packet_number,
                packet_number
            );
            assert!(conn.spaces[SpaceId::Initial].largest_acked_packet.is_none());
            assert!(conn.retry_src_cid.is_some());
        }

        let now = now + crate::Duration::from_secs(1);
        let crypto_before = client.conn.as_ref().unwrap().stats().frame_tx.crypto;
        buf.clear();
        buf.shrink_to_fit();
        let sent = client
            .conn
            .as_mut()
            .unwrap()
            .poll_transmit(now, 1, &mut buf);
        if frame_space == required {
            let transmit = sent.expect("exactly 25 bytes of frame space still sends");
            assert!(client.conn.as_ref().unwrap().stats().frame_tx.crypto > crypto_before);
            assert!(buf.len() <= MIN_INITIAL_SIZE);
            let ProtectedHeader::Initial(sent_initial) = ProtectedHeader::decode(
                &mut Cursor::new(BytesMut::from(&buf[..transmit.size])),
                &FixedLengthConnectionIdParser::new(0),
                crate::DEFAULT_SUPPORTED_VERSIONS,
                true,
            )
            .expect("sent Initial header") else {
                panic!("expected an Initial packet");
            };
            assert_eq!(sent_initial.token_pos.len(), token_len);
            let mut lost = false;
            while let Some(event) = client.conn.as_mut().unwrap().poll() {
                if matches!(event, Event::ConnectionLost { .. }) {
                    lost = true;
                }
            }
            assert!(!lost, "a token that leaves exactly 25 bytes must not close");
        } else {
            assert!(sent.is_none(), "24 bytes of frame space must not send");
            assert!(
                buf.capacity() < 64 * 1024,
                "poll_transmit retained {} bytes",
                buf.capacity()
            );
            assert!(buf.is_empty());
            let conn = client.conn.as_mut().unwrap();
            let mut lost = None;
            while let Some(event) = conn.poll() {
                if let Event::ConnectionLost { reason } = event {
                    lost = Some(reason);
                }
            }
            match lost {
                Some(ConnectionError::TransportError(err))
                    if err.code == TransportErrorCode::PROTOCOL_VIOLATION => {}
                other => panic!("expected PROTOCOL_VIOLATION, got {other:?}"),
            }
            assert!(conn.poll_transmit(now, 1, &mut buf).is_none());
        }
    }
}

/// A cached NEW_TOKEN that fails the frame-space check is discarded. The client sends
/// the Initial without it and stays open. The same length in a Retry is fatal.
#[test]
fn oversized_cached_new_token_is_dropped() {
    let (mut client, _server) = make_peer_pair();
    let frame_space = required_initial_frame_space() - 1;
    let token_len = {
        let conn = client.conn.as_ref().unwrap();
        let crypto = conn.spaces[SpaceId::Initial]
            .crypto
            .as_ref()
            .expect("initial keys");
        assert!(conn.retry_src_cid.is_none());
        token_len_leaving_frame_space(
            conn.handshake_cid,
            conn.rem_cids.active(),
            conn.version,
            conn.spaces[SpaceId::Initial].next_packet_number,
            conn.spaces[SpaceId::Initial]
                .largest_acked_packet
                .unwrap_or(0),
            crypto.header.local.sample_size(),
            crypto.packet.local.tag_len(),
            usize::from(conn.current_mtu()),
            frame_space,
        )
    };
    match &mut client.conn.as_mut().unwrap().side {
        ConnectionSide::Client { token, .. } => *token = Bytes::from(vec![0u8; token_len]),
        ConnectionSide::Server { .. } => panic!("expected a client connection"),
    }

    let now = crate::Instant::now();
    let mut buf = Vec::new();
    let crypto_before = client.conn.as_ref().unwrap().stats().frame_tx.crypto;
    let transmit = client
        .conn
        .as_mut()
        .unwrap()
        .poll_transmit(now, 1, &mut buf)
        .expect("cached NEW_TOKEN is dropped and the Initial is sent");
    assert!(client.conn.as_ref().unwrap().stats().frame_tx.crypto > crypto_before);
    assert!(transmit.size <= MIN_INITIAL_SIZE);
    assert!(buf.capacity() < 64 * 1024);
    let ProtectedHeader::Initial(initial) = ProtectedHeader::decode(
        &mut Cursor::new(BytesMut::from(&buf[..transmit.size])),
        &FixedLengthConnectionIdParser::new(0),
        crate::DEFAULT_SUPPORTED_VERSIONS,
        true,
    )
    .expect("sent Initial header") else {
        panic!("expected an Initial packet");
    };
    assert_eq!(initial.token_pos.len(), 0, "cached token must not be sent");
    let mut lost = false;
    while let Some(event) = client.conn.as_mut().unwrap().poll() {
        if matches!(event, Event::ConnectionLost { .. }) {
            lost = true;
        }
    }
    assert!(!lost);
}
