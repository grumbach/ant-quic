// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Direct-stage budget regressions for PeerId-carrying dials (ant-quic #304,
//! x0x #1110, residual of #292).
//!
//! A loopback UDP gate sits between the dialer and the target. While the gate
//! is closed it holds every datagram from the dialer, so the QUIC handshake
//! cannot complete before the test opens the gate. The gate opens after
//! [`GATE_HOLD`], which is longer than the adaptive direct-stage budget
//! (4 x 333 ms + 750 ms = 2.082 s at the default initial RTT). This is a
//! controlled model of a slow handshake under CPU contention: the handshake
//! cannot finish early, and the caller's establishment budget is much longer
//! than the hold. The result does not depend on scheduler luck.
//!
//! In "reject first" mode the gate answers the first connection attempt with
//! a Version Negotiation packet that lists only a reserved version. The
//! dialer then fails that attempt fast, which models a direct pre-pass that
//! fails for a transient reason before the fallback ladder re-dials.
//!
//! All sockets bind to 127.0.0.1 with OS-assigned ports.

#![cfg(feature = "network-discovery")]

use super::*;
use crate::bootstrap_cache::BootstrapCacheConfig;
use crate::config::nat_timeouts::TimeoutConfig;
use std::net::Ipv4Addr;
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// Longer than the 2.082 s adaptive direct-stage budget.
const GATE_HOLD: Duration = Duration::from_secs(3);
/// The caller's establishment budget for dials whose handshake can finish.
const ESTABLISHMENT_BUDGET: Duration = Duration::from_secs(12);
/// The establishment budget for dials to a target that never answers.
const SILENT_BUDGET: Duration = Duration::from_secs(5);
/// The adaptive direct-stage budget at the default 333 ms initial RTT.
const ADAPTIVE_DIRECT_BUDGET: Duration = Duration::from_millis(2_082);
/// Scheduling slack for the upper bounds below.
const BOUND_SLACK: Duration = Duration::from_millis(1_500);
const MAX_HELD_DATAGRAMS: usize = 512;
/// A reserved QUIC version (RFC 9000 section 15) that no endpoint supports.
const RESERVED_VERSION: u32 = 0x0a1a_2a3a;

async fn isolated_endpoint(establishment_budget: Duration) -> (P2pEndpoint, tempfile::TempDir) {
    let cache = tempfile::tempdir().expect("private bootstrap cache directory");
    let mut timeouts = TimeoutConfig::default();
    timeouts.nat_traversal.connection_establishment_timeout = establishment_budget;
    let config = P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .mdns_enabled(false)
        .nat(crate::NatConfig {
            enable_relay_fallback: false,
            ..Default::default()
        })
        .port_mapping_enabled(false)
        .bootstrap_cache(
            BootstrapCacheConfig::builder()
                .cache_dir(cache.path())
                .persist(false)
                .build(),
        )
        .timeouts(timeouts)
        .build()
        .expect("isolated loopback config");
    let endpoint = timeout(Duration::from_secs(10), P2pEndpoint::new(config))
        .await
        .expect("endpoint binds within 10 s")
        .expect("endpoint binds");
    (endpoint, cache)
}

fn accept_pump(endpoint: &P2pEndpoint) -> JoinHandle<()> {
    let endpoint = endpoint.clone();
    tokio::spawn(async move { while endpoint.accept().await.is_some() {} })
}

fn loopback_addr(endpoint: &P2pEndpoint) -> SocketAddr {
    let addr = endpoint.local_addr().expect("endpoint is bound");
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
}

/// The destination and source connection IDs of a QUIC long-header packet.
fn long_header_cids(datagram: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *datagram.first()?;
    if first & 0x80 == 0 {
        return None;
    }
    let dcid_len = usize::from(*datagram.get(5)?);
    let dcid = datagram.get(6..6 + dcid_len)?;
    let scid_len = usize::from(*datagram.get(6 + dcid_len)?);
    let scid = datagram.get(7 + dcid_len..7 + dcid_len + scid_len)?;
    Some((dcid, scid))
}

/// A Version Negotiation packet (RFC 9000 section 17.2.1) for the client
/// connection that sent `client_dcid`/`client_scid`. It lists only a reserved
/// version, so the client fails the attempt with `VersionMismatch`.
fn version_negotiation(client_dcid: &[u8], client_scid: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(11 + client_dcid.len() + client_scid.len());
    packet.push(0xc0);
    packet.extend_from_slice(&0u32.to_be_bytes());
    packet.push(u8::try_from(client_scid.len()).expect("QUIC CIDs are at most 20 bytes"));
    packet.extend_from_slice(client_scid);
    packet.push(u8::try_from(client_dcid.len()).expect("QUIC CIDs are at most 20 bytes"));
    packet.extend_from_slice(client_dcid);
    packet.extend_from_slice(&RESERVED_VERSION.to_be_bytes());
    packet
}

/// Loopback UDP gate between one dialer and one target.
struct HandshakeGate {
    addr: SocketAddr,
    open: watch::Sender<bool>,
    held: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    forwarder: JoinHandle<()>,
}

impl HandshakeGate {
    async fn spawn(target: SocketAddr, reject_first_connection: bool) -> Self {
        let front = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("gate front socket binds");
        let back = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("gate back socket binds");
        let addr = front.local_addr().expect("gate front address");
        let (open, mut open_rx) = watch::channel(false);
        let held = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));
        let held_count = Arc::clone(&held);
        let rejected_count = Arc::clone(&rejected);

        let forwarder = tokio::spawn(async move {
            let mut dialer: Option<SocketAddr> = None;
            let mut queue: Vec<Vec<u8>> = Vec::new();
            let mut is_open = false;
            let mut rejected_dcid: Option<Vec<u8>> = None;
            let mut from_dialer = vec![0u8; 65_535];
            let mut from_target = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    received = front.recv_from(&mut from_dialer) => {
                        let Ok((len, source)) = received else { break };
                        dialer = Some(source);
                        let datagram = &from_dialer[..len];
                        if let Some((dcid, scid)) = long_header_cids(datagram) {
                            if reject_first_connection && rejected_dcid.is_none() {
                                rejected_dcid = Some(dcid.to_vec());
                            }
                            if rejected_dcid.as_deref() == Some(dcid) {
                                rejected_count.fetch_add(1, Ordering::SeqCst);
                                let reply = version_negotiation(dcid, scid);
                                let _ = front.send_to(&reply, source).await;
                                continue;
                            }
                        }
                        if is_open {
                            let _ = back.send_to(datagram, target).await;
                        } else if queue.len() < MAX_HELD_DATAGRAMS {
                            held_count.fetch_add(1, Ordering::SeqCst);
                            queue.push(datagram.to_vec());
                        }
                    }
                    received = back.recv_from(&mut from_target) => {
                        let Ok((len, _)) = received else { break };
                        if let Some(dialer) = dialer {
                            let _ = front.send_to(&from_target[..len], dialer).await;
                        }
                    }
                    changed = open_rx.changed(), if !is_open => {
                        if changed.is_err() {
                            break;
                        }
                        if *open_rx.borrow_and_update() {
                            is_open = true;
                            for datagram in queue.drain(..) {
                                let _ = back.send_to(&datagram, target).await;
                            }
                        }
                    }
                }
            }
        });

        Self {
            addr,
            open,
            held,
            rejected,
            forwarder,
        }
    }

    fn open(&self) {
        self.open.send_replace(true);
    }

    fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }

    fn rejected(&self) -> usize {
        self.rejected.load(Ordering::SeqCst)
    }
}

impl Drop for HandshakeGate {
    fn drop(&mut self) {
        self.forwarder.abort();
    }
}

struct GatedDial<T> {
    returned_while_gated: bool,
    /// Time from the dial start until the dial returned.
    elapsed: Duration,
    result: Result<T, EndpointError>,
}

/// Run `dial` as a task that also reports when it returned.
fn spawn_timed_dial<T, F>(
    started: tokio::time::Instant,
    dial: F,
) -> JoinHandle<(Duration, Result<T, EndpointError>)>
where
    T: Send + 'static,
    F: std::future::Future<Output = Result<T, EndpointError>> + Send + 'static,
{
    tokio::spawn(async move {
        let result = dial.await;
        (started.elapsed(), result)
    })
}

/// Hold the gate closed for [`GATE_HOLD`], record whether the dial already
/// returned, then open the gate and wait for the dial (bounded).
async fn finish_after_gate<T: Send + 'static>(
    gate: &HandshakeGate,
    started: tokio::time::Instant,
    dial: JoinHandle<(Duration, Result<T, EndpointError>)>,
) -> GatedDial<T> {
    tokio::time::sleep_until(started + GATE_HOLD).await;
    let returned_while_gated = dial.is_finished();
    gate.open();
    let (elapsed, result) = timeout(ESTABLISHMENT_BUDGET + BOUND_SLACK, dial)
        .await
        .expect("dial stays bounded by the establishment budget")
        .expect("dial task joins");
    GatedDial {
        returned_while_gated,
        elapsed,
        result,
    }
}

async fn shutdown_all(endpoints: [&P2pEndpoint; 2]) {
    for endpoint in endpoints {
        let _ = timeout(Duration::from_secs(10), endpoint.shutdown()).await;
    }
}

/// #304: a PeerId dial through the fallback ladder, with no hole-punch
/// coordinator and no relay, must not abort its direct handshake at the
/// adaptive 2.082 s budget while the caller's establishment budget remains.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fallback_peer_dial_survives_slow_direct_handshake() {
    let (dialer, _dialer_cache) = isolated_endpoint(ESTABLISHMENT_BUDGET).await;
    let (target, _target_cache) = isolated_endpoint(ESTABLISHMENT_BUDGET).await;
    let _dialer_accept = accept_pump(&dialer);
    let _target_accept = accept_pump(&target);
    let target_id = target.peer_id();
    let gate = HandshakeGate::spawn(loopback_addr(&target), false).await;
    let gate_addr = gate.addr;

    let started = tokio::time::Instant::now();
    let dial = {
        let dialer = dialer.clone();
        spawn_timed_dial(started, async move {
            dialer
                .connect_with_fallback(Some(gate_addr), None, None, Some(target_id))
                .await
        })
    };
    let outcome = finish_after_gate(&gate, started, dial).await;

    assert!(
        gate.held() > 0,
        "the dialer must send its handshake into the closed gate"
    );
    match outcome.result {
        Ok((connection, method)) => {
            assert!(!outcome.returned_while_gated);
            assert_eq!(connection.peer_id, target_id);
            assert_eq!(method, ConnectionMethod::DirectIPv4);
        }
        Err(error) => panic!(
            "PeerId fallback dial returned after {:?} (while gated: {}) with \
             `{error}`; its handshake could finish after {GATE_HOLD:?} and the \
             caller's {ESTABLISHMENT_BUDGET:?} budget had not expired",
            outcome.elapsed, outcome.returned_while_gated
        ),
    }

    shutdown_all([&dialer, &target]).await;
}

/// #304 on the downstream (x0x) entry point: when the direct pre-pass of
/// `connect_peer_with_addrs` fails fast, the fallback ladder re-dials the
/// target. That re-dial must also get the caller's remaining budget, not the
/// adaptive 2.082 s budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_dial_redial_after_fast_prepass_failure_survives_slow_handshake() {
    let (dialer, _dialer_cache) = isolated_endpoint(ESTABLISHMENT_BUDGET).await;
    let (target, _target_cache) = isolated_endpoint(ESTABLISHMENT_BUDGET).await;
    let _dialer_accept = accept_pump(&dialer);
    let _target_accept = accept_pump(&target);
    let target_id = target.peer_id();
    let gate = HandshakeGate::spawn(loopback_addr(&target), true).await;
    let gate_addr = gate.addr;

    let started = tokio::time::Instant::now();
    let dial = {
        let dialer = dialer.clone();
        spawn_timed_dial(started, async move {
            dialer
                .connect_peer_with_addrs(target_id, vec![gate_addr])
                .await
        })
    };
    let outcome = finish_after_gate(&gate, started, dial).await;

    assert!(
        gate.rejected() > 0,
        "the gate must reject the pre-pass attempt with Version Negotiation"
    );
    assert!(
        gate.held() > 0,
        "the fallback re-dial must send its handshake into the closed gate"
    );
    match outcome.result {
        Ok(connection) => {
            assert!(!outcome.returned_while_gated);
            assert_eq!(connection.peer_id, target_id);
        }
        Err(error) => panic!(
            "PeerId dial returned after {:?} (while gated: {}) with `{error}`; \
             the fallback re-dial could finish after {GATE_HOLD:?} and the caller's \
             {ESTABLISHMENT_BUDGET:?} budget had not expired",
            outcome.elapsed, outcome.returned_while_gated
        ),
    }

    shutdown_all([&dialer, &target]).await;
}

/// Guard for the main downstream path: the direct pre-pass of
/// `connect_peer_with_addrs` gives a slow handshake the full establishment
/// budget. This passed before #304 and must keep passing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_dial_prepass_survives_slow_handshake() {
    let (dialer, _dialer_cache) = isolated_endpoint(ESTABLISHMENT_BUDGET).await;
    let (target, _target_cache) = isolated_endpoint(ESTABLISHMENT_BUDGET).await;
    let _dialer_accept = accept_pump(&dialer);
    let _target_accept = accept_pump(&target);
    let target_id = target.peer_id();
    let gate = HandshakeGate::spawn(loopback_addr(&target), false).await;
    let gate_addr = gate.addr;

    let started = tokio::time::Instant::now();
    let dial = {
        let dialer = dialer.clone();
        spawn_timed_dial(started, async move {
            dialer
                .connect_peer_with_addrs(target_id, vec![gate_addr])
                .await
        })
    };
    let outcome = finish_after_gate(&gate, started, dial).await;

    assert!(
        gate.held() > 0,
        "the dialer must send its handshake into the closed gate"
    );
    match outcome.result {
        Ok(connection) => {
            assert!(!outcome.returned_while_gated);
            assert_eq!(connection.peer_id, target_id);
        }
        Err(error) => panic!(
            "PeerId pre-pass dial returned after {:?} (while gated: {}) with `{error}`",
            outcome.elapsed, outcome.returned_while_gated
        ),
    }

    shutdown_all([&dialer, &target]).await;
}

/// Boundedness guard: a PeerId dial to a target that never answers ends with
/// an error. The pre-pass uses the establishment budget once; the fallback
/// re-dial after that must not wait a second full budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn peer_dial_to_silent_target_stays_bounded_by_the_dial_budget() {
    let (dialer, _dialer_cache) = isolated_endpoint(SILENT_BUDGET).await;
    let (target, _target_cache) = isolated_endpoint(SILENT_BUDGET).await;
    let _dialer_accept = accept_pump(&dialer);
    let target_id = target.peer_id();
    // The gate never opens.
    let gate = HandshakeGate::spawn(loopback_addr(&target), false).await;

    let started = tokio::time::Instant::now();
    let result = timeout(
        SILENT_BUDGET * 3,
        dialer.connect_peer_with_addrs(target_id, vec![gate.addr]),
    )
    .await
    .expect("dial to a silent target must end");
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "a dial to a silent target must fail, got {result:?}"
    );
    assert!(
        elapsed < SILENT_BUDGET + ADAPTIVE_DIRECT_BUDGET + BOUND_SLACK,
        "a dial to a silent target took {elapsed:?}; the pre-pass owns the \
         {SILENT_BUDGET:?} dial budget and the fallback re-dial may add at most \
         the adaptive {ADAPTIVE_DIRECT_BUDGET:?} direct budget"
    );

    shutdown_all([&dialer, &target]).await;
}

/// Boundedness guard: a fallback-ladder PeerId dial to a target that never
/// answers ends with an error within the establishment budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fallback_peer_dial_to_silent_target_stays_bounded() {
    let (dialer, _dialer_cache) = isolated_endpoint(SILENT_BUDGET).await;
    let (target, _target_cache) = isolated_endpoint(SILENT_BUDGET).await;
    let _dialer_accept = accept_pump(&dialer);
    let target_id = target.peer_id();
    // The gate never opens.
    let gate = HandshakeGate::spawn(loopback_addr(&target), false).await;

    let started = tokio::time::Instant::now();
    let result = timeout(
        SILENT_BUDGET * 3,
        dialer.connect_with_fallback(Some(gate.addr), None, None, Some(target_id)),
    )
    .await
    .expect("dial to a silent target must end");
    let elapsed = started.elapsed();

    assert!(
        result.is_err(),
        "a dial to a silent target must fail, got {:?}",
        result.map(|(connection, method)| (connection.peer_id, method))
    );
    assert!(
        elapsed < SILENT_BUDGET + BOUND_SLACK,
        "a fallback dial to a silent target took {elapsed:?}; the establishment \
         budget is {SILENT_BUDGET:?}"
    );

    shutdown_all([&dialer, &target]).await;
}
