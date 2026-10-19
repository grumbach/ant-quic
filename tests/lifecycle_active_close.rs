#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, ConnectionError, P2pEndpoint};
use std::time::{Duration, Instant};
use support::{
    CONNECT_TIMEOUT, RETIREMENT_WAIT, connect_pair, make_isolated_node_with_keypair, make_node,
    normalize_local_addr, ordered_keypairs, reset_lifecycle_events, spawn_accept_loop, test_guard,
    wait_until,
};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn peer_shutdown_cleans_up_remote_view_without_waiting_for_reaper() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let a = make_node(vec![]).await;
    let b = make_node(vec![]).await;
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());
    let (_, b_id, _) = connect_pair(&a, &b).await;

    let start = Instant::now();
    b.shutdown().await;

    let mut cleanup_elapsed = None;
    wait_until(Duration::from_millis(2200), || {
        let is_cleaned_up = a
            .get_quic_connection(&b_id)
            .expect("connection lookup during cleanup wait")
            .is_none();
        if is_cleaned_up {
            cleanup_elapsed = Some(start.elapsed());
        }
        is_cleaned_up
    })
    .await;

    let cleanup_elapsed = match cleanup_elapsed {
        Some(elapsed) => elapsed,
        None => start.elapsed(),
    };
    assert!(
        cleanup_elapsed < Duration::from_secs(2),
        "disconnect cleanup should be driven by reader exit, not the 30s stale reaper"
    );

    a.shutdown().await;
    accept_a.abort();
    accept_b.abort();
}

/// How long a follower is watched for a retirement it must never make: more
/// than Q plus the executor's passes.
const FOLLOWER_KEEPS_FOR: Duration = Duration::from_secs(40);

fn assert_superseded_application_close(close_reason: &ConnectionError, view: &str) {
    let code = match close_reason {
        ConnectionError::ApplicationClosed(frame) => {
            ConnectionCloseReason::from_app_error_code(frame.error_code)
        }
        _ => None,
    };
    assert_eq!(
        code,
        Some(ConnectionCloseReason::Superseded),
        "{view}: expected an application close with the Superseded code, got {close_reason:?}"
    );
}

/// Complete the inbound accept as well as the outbound dial. A winner-map
/// entry alone does not prove that the accepted connection has a reader.
async fn connect_and_accept(from: &P2pEndpoint, to: &P2pEndpoint) {
    let addr = normalize_local_addr(to.local_addr().expect("bound addr"));
    timeout(CONNECT_TIMEOUT, async {
        let (connected, accepted) = tokio::join!(from.connect_addr(addr), to.accept());
        assert_eq!(connected.expect("connect").peer_id, to.peer_id());
        assert_eq!(accepted.expect("accept").peer_id, from.peer_id());
    })
    .await
    .expect("connect and accept timeout");
}

/// #307: retain C1 before opening its replacement. B and B' share an identity
/// and both dial A, so C2 is in the same initiator family and always wins.
/// Await each accept so C1 has a reader before it is superseded, and C2 has
/// one before retirement is observed. Only the ADR-017 arbiter may retire C1.
///
/// Simultaneous dials can return two views of the winner, not the loser. The
/// later cross-family fixture also let random exporter ids choose rejection
/// of C2 instead of superseding C1, so a pass did not prove retirement.
async fn run_superseded_close_reason(a_is_arbiter: bool) {
    let (arbiter_key, follower_key) = ordered_keypairs();
    let (a_key, b_key) = if a_is_arbiter {
        (arbiter_key, follower_key)
    } else {
        (follower_key, arbiter_key)
    };
    let a = make_isolated_node_with_keypair(a_key).await;
    let b = make_isolated_node_with_keypair(b_key.clone()).await;
    let a_id = a.peer_id();
    let b_id = b.peer_id();

    // Hold both views of C1 while it is the only connection and A reads it.
    connect_and_accept(&b, &a).await;
    let a_view_c1 = a
        .get_quic_connection(&b_id)
        .expect("a lookup")
        .expect("A view of C1");
    let b_view_c1 = b
        .get_quic_connection(&a_id)
        .expect("b lookup")
        .expect("B view of C1");

    // C2, opened by B' (a second endpoint with B's identity).
    let b2 = make_isolated_node_with_keypair(b_key).await;
    assert_eq!(b2.peer_id(), b_id, "B' must have B's identity");
    connect_and_accept(&b2, &a).await;
    let b2_view_c2 = b2
        .get_quic_connection(&a_id)
        .expect("B' lookup")
        .expect("B' view of C2");

    let a_live = a
        .get_quic_connection(&b_id)
        .expect("a lookup")
        .expect("A keeps the winner live");
    assert_ne!(
        a_live.stable_id(),
        a_view_c1.stable_id(),
        "the fixture must supersede C1, not merely reject a newcomer"
    );
    if a_is_arbiter {
        // Await the actual remote close, not a local lifecycle notification.
        let close_reason = timeout(RETIREMENT_WAIT, b_view_c1.closed())
            .await
            .expect("the arbiter must retire C1");
        assert_superseded_application_close(&close_reason, "B view of C1");
    } else {
        // C1 lost and A is the follower: A never retires C1.
        assert!(
            timeout(FOLLOWER_KEEPS_FOR, b_view_c1.closed())
                .await
                .is_err(),
            "the follower A must not retire C1: {:?}",
            b_view_c1.close_reason()
        );
        let payload = b"#307: B to the follower A on C1";
        b.send(&a_id, payload).await.expect("B sends on C1");
        let received = timeout(CONNECT_TIMEOUT, async {
            loop {
                match a.recv().await {
                    Ok((peer, data)) if peer == b_id && data == payload => return true,
                    Ok(_) => continue,
                    Err(_) => return false,
                }
            }
        })
        .await
        .unwrap_or(false);
        assert!(received, "the follower A still reads C1");
    }

    assert!(a_live.close_reason().is_none(), "A keeps C2 open");
    assert!(b2_view_c2.close_reason().is_none(), "B' keeps C2 open");

    a.shutdown().await;
    b.shutdown().await;
    b2.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_connection_surfaces_close_reason_quickly() {
    run_superseded_close_reason(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_connection_is_kept_open_by_the_follower() {
    run_superseded_close_reason(false).await;
}
