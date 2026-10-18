//! #235 — redial must succeed while the peer still holds the previous connection.
//!
//! Scenario (filed against 0.27.3x): after the dialer closes its side, every
//! `connect_addr` to the same host timed out (~12 s) even though the peer was
//! still listening and delivering data over the stale connection. The
//! hypothesis was that a new QUIC Initial from the same source port was routed
//! to the stale server-side record by 4-tuple and dropped.
//!
//! Current master demultiplexes Initial packets by destination CID
//! (`ConnectionIndex`), not by 4-tuple, and lifecycle work since #229 / #240 /
//! #241 / #326 / #337 / #340 lets a fresh inbound replace a draining peer.
//! This test pins the end-to-end behaviour: one side closes, the dialer
//! redials immediately while the holder still has the old connection in its
//! QUIC connection table (including draining), and the handshake completes.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use support::{
    CONNECT_TIMEOUT, connect_pair, make_node, normalize_local_addr, reset_lifecycle_events,
    spawn_accept_loop, test_guard, wait_until,
};
use tokio::time::timeout;

const PAYLOAD: &[u8] = b"#235-stale-redial";
/// Repeat the scenario several times: the original failure was timing-sensitive
/// across ten consecutive redials.
const ROUNDS: usize = 8;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn redial_succeeds_while_peer_holds_stale_connection() {
    let _guard = test_guard().await;
    reset_lifecycle_events();

    let a = make_node(vec![]).await;
    let b = make_node(vec![]).await;
    let b_addr = normalize_local_addr(b.local_addr().expect("b addr"));
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    let accept_a = spawn_accept_loop(a.clone());
    let accept_b = spawn_accept_loop(b.clone());

    let (_, _, _) = connect_pair(&a, &b).await;
    wait_until(CONNECT_TIMEOUT, || {
        a.get_quic_connection(&b_id).ok().flatten().is_some()
            && b.get_quic_connection(&a_id).ok().flatten().is_some()
    })
    .await;

    for round in 0..ROUNDS {
        let stale_on_b = b
            .get_quic_connection(&a_id)
            .expect("b lookup before close")
            .expect("b must hold a live connection before dialer close");
        let stale_stable_id = stale_on_b.stable_id();

        // Keep the holder busy on the stale connection (B→A traffic while A is
        // already tearing down), matching the production symptom.
        let holder = stale_on_b.clone();
        let hold_task = tokio::spawn(async move {
            for _ in 0..64 {
                match holder.open_uni().await {
                    Ok(mut send) => {
                        let _ = send.write_all(PAYLOAD).await;
                        let _ = send.finish();
                    }
                    Err(_) => break,
                }
                tokio::task::yield_now().await;
            }
        });

        // Dialer closes its side only. Do not wait for B to finish draining —
        // that is the stale-hold window the issue described.
        a.disconnect(&b_id)
            .await
            .unwrap_or_else(|err| panic!("round {round}: dialer disconnect: {err}"));

        wait_until(CONNECT_TIMEOUT, || {
            a.get_quic_connection(&b_id).ok().flatten().is_none()
        })
        .await;

        // `quic_open_connections` counts the proto slab, including draining
        // entries. Lifecycle `get_quic_connection` can already be None while
        // the stale QUIC connection is still indexed — the #235 failure mode.
        let open_on_b = b.quic_open_connections();
        assert!(
            open_on_b >= 1,
            "round {round}: B must still hold/drain the previous QUIC connection when redial starts \
             (quic_open_connections={open_on_b})"
        );

        let redial = timeout(CONNECT_TIMEOUT, a.connect_addr(b_addr))
            .await
            .unwrap_or_else(|_| panic!("round {round}: redial timed out (issue #235)"))
            .unwrap_or_else(|err| panic!("round {round}: redial failed: {err}"));
        assert_eq!(
            redial.peer_id, b_id,
            "round {round}: redial must reach the same peer"
        );

        wait_until(CONNECT_TIMEOUT, || {
            a.get_quic_connection(&b_id).ok().flatten().is_some()
                && b.get_quic_connection(&a_id).ok().flatten().is_some()
        })
        .await;

        let fresh_on_b = b
            .get_quic_connection(&a_id)
            .expect("b lookup after redial")
            .expect("b must expose the replacement connection");
        assert_ne!(
            fresh_on_b.stable_id(),
            stale_stable_id,
            "round {round}: redial must install a new connection on the holder, not reuse the stale handle"
        );

        a.send(&b_id, PAYLOAD)
            .await
            .unwrap_or_else(|err| panic!("round {round}: a→b send after redial: {err}"));
        b.send(&a_id, PAYLOAD)
            .await
            .unwrap_or_else(|err| panic!("round {round}: b→a send after redial: {err}"));

        hold_task.abort();
        let _ = hold_task.await;
    }

    a.shutdown().await;
    b.shutdown().await;
    accept_a.abort();
    accept_b.abort();
}
