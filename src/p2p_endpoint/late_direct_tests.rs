//! Deterministic #304 overlap tests. A gate retains the real Connecting,
//! while paused Tokio time crosses the unchanged direct-stage cutoff.
//! The punch gate only parks the stage; it never supplies a fake result.

#![allow(clippy::expect_used)]

use super::*;
use crate::bootstrap_cache::BootstrapCacheConfig;
use crate::config::nat_timeouts::TimeoutConfig;
use crate::high_level::Connection;
use tokio::task::JoinHandle;

#[derive(Default)]
pub(super) struct DialGate {
    pub handshake_entered: Notify,
    pub handshake_cancelled: CancellationToken,
    pub handshake_release: Notify,
    pub punch_entered: Notify,
    pub punch_release: Notify,
    pub punch_deadline: ParkingMutex<Option<tokio::time::Instant>>,
}

struct Fixture {
    dialer: P2pEndpoint,
    target: P2pEndpoint,
    coordinator: P2pEndpoint,
    gate: Arc<DialGate>,
    // Keep Tokio from auto-advancing while real loopback I/O is pending.
    // Only each test's explicit advance moves the clock.
    clock_driver: JoinHandle<()>,
    _caches: Vec<tempfile::TempDir>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.clock_driver.abort();
    }
}

async fn endpoint() -> (P2pEndpoint, tempfile::TempDir) {
    let cache = tempfile::tempdir().expect("private cache");
    let mut timeouts = TimeoutConfig::default();
    timeouts.nat_traversal.connection_establishment_timeout = Duration::from_secs(12);
    let config = P2pConfig::builder()
        .bind_addr("127.0.0.1:0".parse::<SocketAddr>().expect("loopback"))
        .mdns_enabled(false)
        .port_mapping_enabled(false)
        .bootstrap_cache(
            BootstrapCacheConfig::builder()
                .cache_dir(cache.path())
                .persist(false)
                .build(),
        )
        .timeouts(timeouts)
        .build()
        .expect("config");
    (P2pEndpoint::new(config).await.expect("endpoint"), cache)
}

fn addr(endpoint: &P2pEndpoint) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], endpoint.local_addr().expect("bound").port()))
}

impl Fixture {
    async fn new() -> Self {
        let (dialer, a_cache) = endpoint().await;
        let (target, b_cache) = endpoint().await;
        let (coordinator, c_cache) = endpoint().await;
        dialer
            .connect_addr(addr(&coordinator))
            .await
            .expect("live coordinator");
        coordinator.accept().await.expect("coordinator accepts");
        let gate = Arc::new(DialGate::default());
        *dialer.late_direct_gate.lock() = Some(Arc::clone(&gate));
        tokio::time::pause();
        let clock_driver = tokio::spawn(async {
            loop {
                tokio::task::yield_now().await;
            }
        });
        Self {
            dialer,
            target,
            coordinator,
            gate,
            clock_driver,
            _caches: vec![a_cache, b_cache, c_cache],
        }
    }

    fn strategy(&self) -> StrategyConfig {
        StrategyConfig {
            ipv4_timeout: Duration::from_secs(2),
            ipv6_timeout: Duration::from_secs(2),
            holepunch_timeout: Duration::from_secs(4),
            relay_timeout: Duration::ZERO,
            max_holepunch_rounds: 1,
            relay_enabled: false,
            coordinator: Some(addr(&self.coordinator)),
            ..Default::default()
        }
    }

    fn dial(
        &self,
        caller_budget: Duration,
    ) -> JoinHandle<Result<(PeerConnection, ConnectionMethod), EndpointError>> {
        let node = self.dialer.clone();
        let target = addr(&self.target);
        let peer = self.target.peer_id();
        let strategy = self.strategy();
        let deadline = tokio::time::Instant::now() + caller_budget;
        tokio::spawn(async move {
            node.connect_with_fallback_within(
                Some(target),
                None,
                Some(strategy),
                Some(peer),
                Some(deadline),
            )
            .await
        })
    }

    async fn cross_cutoff(&self) -> Connection {
        self.gate.handshake_entered.notified().await;
        // The peer completes its side of the real handshake. The dialer's
        // Connecting is still owned by the parked direct attempt.
        self.target
            .accept()
            .await
            .expect("direct arrives at target");
        let remote_direct = self
            .target
            .inner
            .get_connection(&self.dialer.peer_id())
            .expect("lookup")
            .expect("direct at target");
        assert!(remote_direct.close_reason().is_none());
        let before = tokio::time::Instant::now();
        // Tokio timers round to millisecond ticks. Cross the cutoff by one
        // tick instead of depending on the fractional clock origin.
        tokio::time::advance(Duration::from_millis(2_001)).await;
        self.gate.punch_entered.notified().await;
        assert_eq!(
            tokio::time::Instant::now(),
            before + Duration::from_millis(2_001)
        );
        assert_eq!(
            *self.gate.punch_deadline.lock(),
            Some(before + Duration::from_millis(6_001)),
            "punch keeps its original four-second budget"
        );
        assert!(
            remote_direct.close_reason().is_none(),
            "stage cutoff must not close direct"
        );
        remote_direct
    }

    async fn close(&self) {
        tokio::time::resume();
        self.dialer.shutdown().await;
        self.target.shutdown().await;
        self.coordinator.shutdown().await;
    }
}

#[tokio::test]
async fn late_direct_completes_after_coordinator_stage_cutoff() {
    let f = Fixture::new().await;
    let dial = f.dial(Duration::from_secs(12));
    let remote = f.cross_cutoff().await;
    assert!(!dial.is_finished(), "owned handshake is still pending");
    tokio::time::advance(Duration::from_secs(1)).await;
    f.gate.handshake_release.notify_one();
    let (peer, method) = tokio::select! {
        biased;
        () = f.gate.handshake_cancelled.cancelled() => panic!("cutoff cancelled the owned direct handshake"),
        result = dial => result.expect("join").expect("late direct succeeds"),
    };
    assert_eq!(peer.peer_id, f.target.peer_id());
    assert_eq!(peer.traversal_method, TraversalMethod::Direct);
    assert_eq!(method, ConnectionMethod::DirectIPv4);
    assert!(remote.close_reason().is_none());
    assert_eq!(
        f.dialer
            .inner
            .open_lifecycle_entries_for_test(&peer.peer_id)
            .len(),
        1
    );
    assert_eq!(
        f.target
            .inner
            .open_lifecycle_entries_for_test(&f.dialer.peer_id())
            .len(),
        1
    );
    assert_eq!(
        f.dialer
            .inner
            .get_endpoint()
            .expect("quic")
            .open_connections(),
        2,
        "one coordinator and one target connection"
    );
    f.close().await;
}

#[tokio::test]
async fn punch_winner_closes_the_owned_late_direct_loser() {
    let f = Fixture::new().await;
    let dial = f.dial(Duration::from_secs(12));
    let remote_direct = f.cross_cutoff().await;
    let peer = f.target.peer_id();
    // Use the production hole-punch handshake and registration path. The
    // coordinator transport itself is irrelevant to the two-path race.
    f.dialer
        .inner
        .attempt_hole_punch_candidate_for_test(peer, addr(&f.target))
        .expect("punch");
    loop {
        let notified = f.dialer.inner.connection_notify().notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if f.dialer
            .inner
            .get_connection(&peer)
            .expect("lookup")
            .is_some()
        {
            break;
        }
        notified.await;
    }
    f.target.accept().await.expect("punch arrives at target");
    f.gate.punch_release.notify_one();
    let (connected, method) = dial.await.expect("join").expect("punch succeeds");
    assert_eq!(connected.peer_id, peer);
    assert_eq!(connected.traversal_method, TraversalMethod::HolePunch);
    assert_eq!(
        method,
        ConnectionMethod::HolePunched {
            coordinator: addr(&f.coordinator)
        }
    );
    remote_direct.closed().await;
    // QUIC retains closed routes for its draining period. Advance the
    // existing establishment window, then let the driver deliver Drained.
    tokio::time::advance(Duration::from_secs(12)).await;
    tokio::task::yield_now().await;
    let winner = f
        .dialer
        .inner
        .get_connection(&peer)
        .expect("lookup")
        .expect("winner");
    assert!(
        winner.close_reason().is_none(),
        "loser cleanup leaves punch open"
    );
    assert_eq!(
        f.dialer.inner.open_lifecycle_entries_for_test(&peer).len(),
        1
    );
    assert_eq!(
        f.target
            .inner
            .open_lifecycle_entries_for_test(&f.dialer.peer_id())
            .len(),
        1
    );
    assert_eq!(
        f.dialer
            .inner
            .get_endpoint()
            .expect("quic")
            .open_connections(),
        2,
        "no orphan direct connection"
    );
    f.close().await;
}

#[tokio::test]
async fn late_direct_is_cancelled_at_the_original_caller_deadline() {
    let f = Fixture::new().await;
    let started = tokio::time::Instant::now();
    let dial = f.dial(Duration::from_secs(5));
    let remote = f.cross_cutoff().await;
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(matches!(
        dial.await.expect("join"),
        Err(EndpointError::Timeout)
    ));
    assert_eq!(
        tokio::time::Instant::now(),
        started + Duration::from_millis(5_001)
    );
    remote.closed().await;
    // QUIC retains closed routes for its draining period. Advance the
    // existing establishment window, then let the driver deliver Drained.
    tokio::time::advance(Duration::from_secs(12)).await;
    tokio::task::yield_now().await;
    assert!(!f.dialer.inner.is_peer_connected(&f.target.peer_id()));
    assert_eq!(
        f.dialer
            .inner
            .get_endpoint()
            .expect("quic")
            .open_connections(),
        1
    );
    f.close().await;
}

#[tokio::test]
async fn cancelling_the_dial_closes_the_owned_late_direct() {
    let f = Fixture::new().await;
    let dial = f.dial(Duration::from_secs(12));
    let remote = f.cross_cutoff().await;
    dial.abort();
    assert!(dial.await.expect_err("cancelled task").is_cancelled());
    remote.closed().await;
    // QUIC retains closed routes for its draining period. Advance the
    // existing establishment window, then let the driver deliver Drained.
    tokio::time::advance(Duration::from_secs(12)).await;
    tokio::task::yield_now().await;
    assert!(!f.dialer.inner.is_peer_connected(&f.target.peer_id()));
    assert_eq!(
        f.dialer
            .inner
            .get_endpoint()
            .expect("quic")
            .open_connections(),
        1
    );
    f.close().await;
}

/// Both results are ready before the selector runs. The punched connection
/// has already passed the lifecycle arbiter; the unregistered direct result
/// must be dropped even though it has completed its handshake.
#[tokio::test]
async fn ready_punch_winner_closes_an_already_completed_direct_result() {
    let f = Fixture::new().await;
    let peer = f.target.peer_id();
    let direct = f
        .dialer
        .attempt_direct_handshake(addr(&f.target))
        .await
        .expect("direct handshake");
    let direct_weak = direct.weak_handle();
    f.target.accept().await.expect("direct accepted");
    let remote_direct = f
        .target
        .inner
        .get_connection(&f.dialer.peer_id())
        .expect("lookup")
        .expect("direct");
    f.dialer
        .inner
        .attempt_hole_punch_candidate_for_test(peer, addr(&f.target))
        .expect("punch");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(12);
    let punched = f
        .dialer
        .await_hole_punch_outcome(addr(&f.target), peer, deadline)
        .await
        .expect("punch registered");
    f.target.accept().await.expect("punch accepted");
    let method = ConnectionMethod::HolePunched {
        coordinator: addr(&f.coordinator),
    };
    let result = f
        .dialer
        .race_late_direct(
            std::future::ready(Ok((direct, addr(&f.target)))),
            std::future::ready(Ok((punched, method.clone()))),
            Some(peer),
            deadline,
        )
        .await
        .expect("ready punch wins");
    assert_eq!(result.1, method);
    assert!(
        !direct_weak.is_alive(),
        "completed direct loser must be closed"
    );
    remote_direct.closed().await;
    tokio::time::advance(Duration::from_secs(12)).await;
    tokio::task::yield_now().await;
    assert_eq!(
        f.dialer.inner.open_lifecycle_entries_for_test(&peer).len(),
        1
    );
    assert_eq!(
        f.target
            .inner
            .open_lifecycle_entries_for_test(&f.dialer.peer_id())
            .len(),
        1
    );
    assert_eq!(
        f.dialer
            .inner
            .get_endpoint()
            .expect("quic")
            .open_connections(),
        2
    );
    assert!(
        f.dialer
            .inner
            .get_connection(&peer)
            .expect("lookup")
            .expect("punch winner")
            .close_reason()
            .is_none()
    );
    f.close().await;
}
