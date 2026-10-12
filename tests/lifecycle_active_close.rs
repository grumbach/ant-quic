#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use ant_quic::{ConnectionCloseReason, ConnectionError, PeerLifecycleEvent};
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

/// Upper bound for the peer of a rejected newcomer to observe its close. The
/// registrar rejects and closes it at registration.
const REJECTED_CLOSE_WAIT: Duration = Duration::from_secs(20);

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

/// #307, role-aware for ADR-017. A opens C1 to B and both ends register it;
/// then B' (a second endpoint with B's identity) opens C2 to A. C1 and C2
/// have different initiators, so A picks the winner by the shared
/// TLS-exporter connection id, as in a simultaneous open, and the winner
/// changes from run to run. Both outcomes are checked, and they differ:
///
/// - C2 loses: A rejects it at registration and closes it at once with the
///   reserved Superseded code, whatever A's role is. B' reports the close.
/// - C1 loses: C1 is an admitted, superseded connection. Only the arbiter of
///   the pair retires it. If A is the arbiter, B sees C1 closed with the
///   Superseded code once A has evidence that B' reads C2. If A is the
///   follower, A never retires C1: it stays open and A still reads it.
///
/// The previous version dialled from both sides at once and held the two
/// handles `get_quic_connection` returned; when the winner registered first
/// on both sides, both handles were the winner and the test timed out. Here
/// the order is fixed and A is the only endpoint that holds both
/// connections.
async fn run_superseded_close_reason(a_is_arbiter: bool) {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let (arbiter_key, follower_key) = ordered_keypairs();
    let (a_key, b_key) = if a_is_arbiter {
        (arbiter_key, follower_key)
    } else {
        (follower_key, arbiter_key)
    };
    let a = make_isolated_node_with_keypair(a_key).await;
    let b = make_isolated_node_with_keypair(b_key.clone()).await;
    let a_addr = normalize_local_addr(a.local_addr().expect("a addr"));
    let b_addr = normalize_local_addr(b.local_addr().expect("b addr"));
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());

    // C1, opened by A. Wait until both ends have registered it.
    timeout(CONNECT_TIMEOUT, a.connect_addr(b_addr))
        .await
        .expect("C1 connect timeout")
        .expect("C1 connect");
    wait_until(CONNECT_TIMEOUT, || {
        a.get_quic_connection(&b_id).ok().flatten().is_some()
            && b.get_quic_connection(&a_id).ok().flatten().is_some()
    })
    .await;
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
    let accept_b2 = spawn_accept_loop(b2.clone());
    let mut b2_events = b2.subscribe_peer_events(&a_id);
    timeout(CONNECT_TIMEOUT, b2.connect_addr(a_addr))
        .await
        .expect("C2 connect timeout")
        .expect("C2 connect");
    // If A has already closed C2, the lookup can miss. B's peer event below
    // still reports the close.
    let b2_view_c2 = b2.get_quic_connection(&a_id).ok().flatten();

    // Which connection did A keep? Either B' sees the rejection of C2, or
    // A's winner moves to C2.
    let mut b2_closed_reason = None;
    wait_until(REJECTED_CLOSE_WAIT, || {
        while let Ok(event) = b2_events.try_recv() {
            if let PeerLifecycleEvent::Closed { reason, .. } = event {
                b2_closed_reason.get_or_insert(reason);
            }
        }
        b2_closed_reason.is_some()
            || a.get_quic_connection(&b_id)
                .ok()
                .flatten()
                .is_some_and(|live| live.stable_id() != a_view_c1.stable_id())
    })
    .await;
    let a_live = a
        .get_quic_connection(&b_id)
        .expect("a lookup")
        .expect("A keeps the winner live");
    if a_live.stable_id() == a_view_c1.stable_id() {
        // C2 lost: A rejected it at registration and closed it at once.
        println!("#307 outcome (a_is_arbiter={a_is_arbiter}): C1 won, C2 rejected");
        assert_eq!(
            b2_closed_reason,
            Some(ConnectionCloseReason::Superseded),
            "B' must report the Superseded close of the rejected C2"
        );
        if let Some(b2_view_c2) = b2_view_c2 {
            let close_reason = b2_view_c2.close_reason().expect("C2 closed");
            assert_superseded_application_close(&close_reason, "B' view of C2");
        }
        assert!(
            b_view_c1.close_reason().is_none(),
            "C1 won, so B must keep it"
        );
    } else if a_is_arbiter {
        // C1 lost and A is the arbiter: A retires C1.
        println!("#307 outcome (arbiter A): C2 won, C1 superseded and retired");
        wait_until(RETIREMENT_WAIT, || b_view_c1.close_reason().is_some()).await;
        let close_reason = b_view_c1.close_reason().expect("C1 closed");
        assert_superseded_application_close(&close_reason, "B view of C1");
        assert_eq!(b2_closed_reason, None, "C2 won, so B' must keep it");
        assert!(
            b2_view_c2.is_some_and(|c2| c2.close_reason().is_none()),
            "C2 won, so B' keeps it open"
        );
    } else {
        // C1 lost and A is the follower: A never retires C1.
        println!("#307 outcome (follower A): C2 won, C1 superseded and kept");
        tokio::time::sleep(FOLLOWER_KEEPS_FOR).await;
        assert!(
            b_view_c1.close_reason().is_none(),
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
        assert_eq!(b2_closed_reason, None, "C2 won, so B' must keep it");
    }

    a.shutdown().await;
    b.shutdown().await;
    b2.shutdown().await;
    accept_a.abort();
    accept_b.abort();
    accept_b2.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_connection_surfaces_close_reason_quickly() {
    run_superseded_close_reason(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn superseded_connection_is_kept_open_by_the_follower() {
    run_superseded_close_reason(false).await;
}
