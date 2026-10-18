//! #255 — measure what a Closed connection generation retains.
//!
//! A counting global allocator tracks live heap bytes in this test binary.
//! Two loopback nodes churn connect → traffic → disconnect cycles; after a
//! warm-up phase (caches, lazily grown maps) the live-heap delta across the
//! measured cycles, divided by the cycle count, is what each Closed
//! generation leaves behind. Unlike RSS this is immune to allocator
//! retention, so a non-zero slope is a real reference that outlives Close.
//!
//! Findings on master 13330425 (macOS, `MallocStackLogging` +
//! `malloc_history -allBySize`): before rustls' 256-entry server session
//! cache fills, ~5 KB/cycle is that bounded cache. After it fills, ~1.6
//! KB/cycle stays and grows linearly. Nearly all of it is
//! `NatTraversalEvent`s (`ConnectionLost` with its formatted close reason,
//! from `NatTraversalEndpoint::handle_connection`) queued on the unbounded
//! `event_rx`. Only `NatTraversalEndpoint::poll()` drains that queue, and
//! `P2pEndpoint` calls it only while waiting on a hole punch. Draining
//! `poll()` every second flattens the slope to ~0.

#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use ant_quic::P2pEndpoint;
use support::{make_node, normalize_local_addr, spawn_accept_loop, test_guard};
use tokio::time::{sleep, timeout};

struct CountingAlloc;

static LIVE_BYTES: AtomicIsize = AtomicIsize::new(0);

// SAFETY: every method forwards to `System` unchanged and only adjusts a counter.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded verbatim to the system allocator.
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        // SAFETY: forwarded verbatim to the system allocator.
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            LIVE_BYTES.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarded verbatim to the system allocator.
        unsafe { System.dealloc(ptr, layout) };
        LIVE_BYTES.fetch_sub(layout.size() as isize, Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: forwarded verbatim to the system allocator.
        let new = unsafe { System.realloc(ptr, layout, new_size) };
        if !new.is_null() {
            LIVE_BYTES.fetch_add(
                new_size as isize - layout.size() as isize,
                Ordering::Relaxed,
            );
        }
        new
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

fn live_bytes() -> isize {
    LIVE_BYTES.load(Ordering::Relaxed)
}

const SENDS_PER_CYCLE: usize = 10;
const PAYLOAD: &[u8] = &[0x5a; 8192];

async fn wait_closed(nodes: &[&P2pEndpoint]) {
    let _ = timeout(Duration::from_secs(10), async {
        loop {
            let mut done = true;
            for n in nodes {
                if n.stats().await.active_connections != 0 || n.quic_open_connections() != 0 {
                    done = false;
                }
            }
            if done {
                return;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
}

async fn cycle(a: &P2pEndpoint, b: &P2pEndpoint, b_addr: std::net::SocketAddr) {
    let a_id = a.peer_id();
    let b_id = b.peer_id();
    timeout(Duration::from_secs(10), a.connect_addr(b_addr))
        .await
        .expect("connect timeout")
        .expect("connect failed");
    sleep(Duration::from_millis(50)).await;
    for _ in 0..SENDS_PER_CYCLE {
        a.send(&b_id, PAYLOAD).await.expect("a->b send");
        b.send(&a_id, PAYLOAD).await.expect("b->a send");
    }
    a.disconnect(&b_id).await.expect("disconnect");
    wait_closed(&[a, b]).await;
}

fn spawn_recv_drain(node: Arc<P2pEndpoint>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move { while node.recv().await.is_ok() {} })
}

/// Settle background tasks, then sample the live heap.
async fn settled_live_bytes() -> isize {
    sleep(Duration::from_millis(500)).await;
    live_bytes()
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Churn one node pair: `warmup` cycles, then `stages` stages of `per_stage`
/// cycles, sampling the settled live heap after each stage. Returns the
/// per-stage growth in bytes.
async fn staged_growth(warmup: usize, stages: usize, per_stage: usize) -> Vec<isize> {
    let b = make_node(vec![]).await;
    let b_addr = normalize_local_addr(b.local_addr().expect("b bound"));
    let a = make_node(vec![b_addr]).await;
    let tasks = [
        spawn_accept_loop(a.clone()),
        spawn_accept_loop(b.clone()),
        // Drain delivered payloads so the application channel is not counted.
        spawn_recv_drain(a.clone()),
        spawn_recv_drain(b.clone()),
    ];

    for _ in 0..warmup {
        cycle(&a, &b, b_addr).await;
    }
    let mut last = settled_live_bytes().await;
    println!("[#255 retention] warmup={warmup} live={last}");
    let mut growth = Vec::with_capacity(stages);
    for stage in 1..=stages {
        for _ in 0..per_stage {
            cycle(&a, &b, b_addr).await;
        }
        let now = settled_live_bytes().await;
        let delta = now - last;
        println!(
            "[#255 retention] stage={stage} cycles={per_stage} live={now} delta={delta} \
             per_cycle={} | A: open={} conn_map={} activity={} rdr_handles={} \
             | B: open={} conn_map={} activity={} rdr_handles={}",
            delta / per_stage as isize,
            a.quic_open_connections(),
            a.connected_peers_map_len().await,
            a.peer_activity_count().await,
            a.reader_handle_count().await,
            b.quic_open_connections(),
            b.connected_peers_map_len().await,
            b.peer_activity_count().await,
            b.reader_handle_count().await,
        );
        growth.push(delta);
        last = now;
    }
    for task in tasks {
        task.abort();
    }
    growth
}

/// Measurement harness (prints, asserts nothing). Tunables:
/// `ANT_QUIC_RETENTION_WARMUP` (default 300 — past rustls' 256-entry
/// server session cache), `_STAGES` (3), `_PER_STAGE` (100),
/// `ANT_QUIC_RETENTION_PAUSE=<secs>` to hold the process for
/// `malloc_history` (`MallocStackLogging=1`).
///
/// Run: `cargo test --test connection_close_retention -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn closed_generation_retention_measurement() {
    let _guard = test_guard().await;
    staged_growth(
        env_usize("ANT_QUIC_RETENTION_WARMUP", 300),
        env_usize("ANT_QUIC_RETENTION_STAGES", 3),
        env_usize("ANT_QUIC_RETENTION_PER_STAGE", 100),
    )
    .await;
    if let Ok(secs) = std::env::var("ANT_QUIC_RETENTION_PAUSE") {
        println!("[#255 pause] pid={}", std::process::id());
        sleep(Duration::from_secs(secs.parse().unwrap_or(120))).await;
    }
}
