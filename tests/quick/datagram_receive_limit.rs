//! A datagram whose payload is the maximum the peer advertised must be
//! delivered, and the connection must stay open.
//!
//! `datagram_receive_buffer_size` is advertised as `max_datagram_frame_size`.
//! With `Some(1024)` the largest payload a peer will send is 1024 minus the
//! DATAGRAM frame bound (9), i.e. 1015 bytes. Charging the in-memory datagram
//! overhead against that same limit rejects this legal payload as
//! `PROTOCOL_VIOLATION("oversized datagram")` and closes the connection.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use ant_quic::{
    TransportConfig,
    config::{ClientConfig, ServerConfig},
    high_level::{Endpoint, SendDatagramError},
};
use bytes::Bytes;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::time::timeout;

fn gen_self_signed_cert() -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
        .expect("generate self-signed");
    let cert_der = CertificateDer::from(cert.cert);
    let key_der = PrivateKeyDer::Pkcs8(cert.signing_key.serialize_der().into());
    (vec![cert_der], key_der)
}

/// `Some(1024)` on the receiver. The sender transmits `max_datagram_size()`
/// bytes — the largest payload that fits the advertised limit — and the
/// receiver delivers it with both connections still open.
#[tokio::test]
async fn advertised_datagram_limit_delivers_max_legal_payload() {
    let (chain, key) = gen_self_signed_cert();
    let mut server_transport = TransportConfig::default();
    server_transport.datagram_receive_buffer_size(Some(1024));
    let mut server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    server_cfg.transport_config(Arc::new(server_transport));

    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let server_addr: SocketAddr = server.local_addr().unwrap();

    let accept = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("accept timeout")
            .expect("accept failed");
        timeout(Duration::from_secs(10), inc)
            .await
            .expect("handshake timeout")
            .expect("handshake failed")
    });

    let mut roots = rustls::RootCertStore::empty();
    for cert in chain {
        roots.add(cert).unwrap();
    }
    let client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_cfg);

    let connecting = client
        .connect(server_addr, "localhost")
        .expect("start connect");
    let client_conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("connect timeout")
        .expect("connect failed");
    let server_conn = accept.await.expect("accept task");

    // Advertised max_datagram_frame_size is 1024. The sender's max legal
    // payload subtracts the 9-byte DATAGRAM frame bound.
    let max = client_conn
        .max_datagram_size()
        .expect("peer advertised datagram support");
    assert_eq!(
        max, 1015,
        "max legal payload against a 1024-byte advertised datagram limit"
    );

    let payload = Bytes::from(vec![0x5Au8; max]);
    client_conn
        .send_datagram(payload.clone())
        .expect("send max legal datagram");

    let received = timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("timed out waiting for the datagram")
        .expect("datagram was not delivered");
    assert_eq!(received, payload);

    let follow = Bytes::from_static(b"still-open");
    client_conn
        .send_datagram(follow.clone())
        .expect("send follow-up datagram");
    let follow_received = timeout(Duration::from_secs(5), server_conn.read_datagram())
        .await
        .expect("timed out waiting for the follow-up datagram")
        .expect("follow-up datagram was not delivered");
    assert_eq!(follow_received, follow);

    assert!(
        server_conn.close_reason().is_none(),
        "server closed after a legal datagram: {:?}",
        server_conn.close_reason()
    );
    assert!(
        client_conn.close_reason().is_none(),
        "client closed after a legal datagram: {:?}",
        client_conn.close_reason()
    );
}

/// RFC 9221 §3: a peer that advertises `max_datagram_frame_size` 0 does not
/// support DATAGRAM frames. The sender must report that instead of sending an
/// empty DATAGRAM frame, which the peer has to treat as a protocol violation.
#[tokio::test]
async fn zero_advertised_datagram_limit_disables_send() {
    let (chain, key) = gen_self_signed_cert();
    let mut server_transport = TransportConfig::default();
    server_transport.datagram_receive_buffer_size(Some(0));
    let mut server_cfg = ServerConfig::with_single_cert(chain.clone(), key).expect("server cfg");
    server_cfg.transport_config(Arc::new(server_transport));

    let server = Endpoint::server(server_cfg, ([127, 0, 0, 1], 0).into()).expect("server ep");
    let server_addr: SocketAddr = server.local_addr().unwrap();

    let accept = tokio::spawn(async move {
        let inc = timeout(Duration::from_secs(10), server.accept())
            .await
            .expect("accept timeout")
            .expect("accept failed");
        timeout(Duration::from_secs(10), inc)
            .await
            .expect("handshake timeout")
            .expect("handshake failed")
    });

    let mut roots = rustls::RootCertStore::empty();
    for cert in chain {
        roots.add(cert).unwrap();
    }
    let client_cfg = ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    let mut client = Endpoint::client(([127, 0, 0, 1], 0).into()).expect("client ep");
    client.set_default_client_config(client_cfg);

    let connecting = client
        .connect(server_addr, "localhost")
        .expect("start connect");
    let client_conn = timeout(Duration::from_secs(10), connecting)
        .await
        .expect("connect timeout")
        .expect("connect failed");
    let server_conn = accept.await.expect("accept task");

    assert_eq!(
        client_conn.max_datagram_size(),
        None,
        "a peer limit of 0 means no DATAGRAM support"
    );
    assert!(
        matches!(
            client_conn.send_datagram(Bytes::new()),
            Err(SendDatagramError::UnsupportedByPeer)
        ),
        "an empty datagram must not be sent to a peer that advertised 0"
    );
    assert!(server_conn.close_reason().is_none());
    assert!(client_conn.close_reason().is_none());
}
