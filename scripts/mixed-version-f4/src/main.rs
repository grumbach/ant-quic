//! ADR-017 F4 mixed-version gate for ant-quic 0.27.58.
//!
//! A NEW arbiter A (the combined release/0.27.58 tree) and an OLD follower B
//! (crates.io 0.27.57), in one process, on loopback, with production timing
//! (Q = 30 s, P = 3 s, B's own 5 s supersede timer).
//!
//! Schedule (ADR-017 F4, Codex round 2): B dials L to A, and A registers the
//! inbound L. B's own finalize of L is held: the `connect_addr` future is
//! polled once (the QUIC handshake then completes in the background) and not
//! again until t = d. B then dials W, so A registers W at t = 0 and L becomes
//! Superseded at A. B registers W and sends on it (A's E3(a)). At t = d B
//! finalizes L late: L becomes B's winner, B routes to L and starts its own
//! 5 s timer on W. A, the arbiter, keeps B's earlier request on W as E3(a);
//! from t = 30 s it can retire the quiet L. If B's timer closes W at about the
//! same time, both connections can close.
//!
//! Variants:
//! - `none`: B sends nothing after it finalizes L (L stays quiet).
//! - `window`: B sends one message at a random time t_s in [29.95, 30.10] s
//!   (around A's claim, inside the F4 window), on its route at that time.
//! - `coincide`: B finalizes L at d in [25.005, 25.035] s, so its own 5 s timer
//!   on W fires at about the time A completes L (the F4 total-loss case).
//!
//! Per iteration the harness records every message B sends (time, route,
//! result) and every message A receives; A's retirement events (tracing:
//! "retirement claimed/completed/aborted"); the close times of L and W at B;
//! and, after the first close, the time until B's application delivery
//! resumes (the application re-dials when B has no connection). Then it checks:
//! (a) every lost message (send returned Ok, never received) was sent inside
//!     the ADR-017 F4 window, from the measured boundaries: on L, from A's
//!     claim (less CLAIM_SLACK, 1 ms) to B's observation of L's close (plus
//!     SEND_SLACK, 1 ms); or on W at or after B's own close of W (less one
//!     watcher interval). Any other loss is a violation;
//! (b) delivery resumes within RECOVERY_BOUND;
//! (c) whether the pair was ever left with no connection (total disconnect),
//!     and that every total disconnect is the F4 coincidence: B's own timer
//!     closed W within F4_COINCIDENCE of A completing L. The watcher observes
//!     a close late only, so the measured gap may exceed F4_COINCIDENCE by one
//!     close-watcher interval on the late side, and not on the early side;
//! (d) at the end both directions deliver, and both ends have the same number
//!     of open connections.
//!
//! The run passes only if every requested iteration completed: a setup error,
//! a failed iteration task, or an empty run fails it. Before the run, a self
//! test checks the window predicate with losses just outside each boundary,
//! and the completeness rule.
//!
//! Usage: `mixed-version-f4 [iterations per variant] [concurrency] [seed]
//! [close watcher ms]` (defaults 200, 16, 3130258, 1).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use std::task::Poll;
use std::time::Duration;

use rand::{Rng, SeedableRng};
use tokio::time::{Instant, sleep, timeout};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::SubscriberExt;

const Q_END: Duration = Duration::from_secs(30);
const WATCH_UNTIL: Duration = Duration::from_secs(40);
const RECOVERY_BOUND: Duration = Duration::from_secs(15);
/// Slack at the claim end of the F4 window. A lost stream reached A after A
/// stopped L's reader, which is after the claim; it was opened at most one
/// one-way delay before it arrived, and A's claim event is logged just after
/// the claim. Both are well under 1 ms on loopback.
const CLAIM_SLACK: Duration = Duration::from_millis(1);
/// Slack at the close end of the F4 window. B's observation of L's close
/// (the watcher) is never earlier than B's processing of it; a send that B
/// started before that processing returns at most one `send` call later
/// (well under 1 ms on loopback).
const SEND_SLACK: Duration = Duration::from_millis(1);
const SEND_INTERVAL: Duration = Duration::from_millis(250);
/// ADR-017 F4: a total loss needs B's own timer to close W within about one
/// round trip of A's retirement of L. Loopback, with scheduling: 5 ms. See
/// `total_disconnect_is_f4_coincidence` for the one-sided measurement slack.
const F4_COINCIDENCE: Duration = Duration::from_millis(5);

// ---------------------------------------------------------------- tracing

#[derive(Clone, Debug)]
struct RetireEvent {
    prefix: String,
    kind: &'static str,
    at: Instant,
}

static EVENTS: LazyLock<Mutex<Vec<RetireEvent>>> = LazyLock::new(|| Mutex::new(Vec::new()));

struct Capture;

impl<S: tracing::Subscriber> Layer<S> for Capture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        #[derive(Default)]
        struct Fields {
            message: String,
            peer: String,
        }
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                match field.name() {
                    "message" => self.message = format!("{value:?}"),
                    "peer_id" => self.peer = format!("{value:?}"),
                    _ => {}
                }
            }
            fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
                match field.name() {
                    "message" => self.message = value.to_string(),
                    "peer_id" => self.peer = value.to_string(),
                    _ => {}
                }
            }
        }
        let mut fields = Fields::default();
        event.record(&mut fields);
        let kind = if fields.message.contains("retirement claimed") {
            "claimed"
        } else if fields.message.contains("retirement completed") {
            "completed"
        } else if fields.message.contains("retirement aborted") {
            "aborted"
        } else {
            return;
        };
        if let Ok(mut events) = EVENTS.lock() {
            events.push(RetireEvent {
                prefix: fields.peer.trim_matches('"').to_string(),
                kind,
                at: Instant::now(),
            });
        }
    }
}

// ------------------------------------------------------------------ nodes

fn lo(addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), addr.port())
    } else {
        addr
    }
}

macro_rules! node {
    ($krate:ident, $keypair:expr) => {{
        let (pk, sk) = $keypair;
        $krate::P2pEndpoint::new(
            $krate::P2pConfig::builder()
                .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .nat($krate::NatConfig {
                    enable_relay_fallback: false,
                    ..Default::default()
                })
                .pqc($krate::PqcConfig::default())
                .mdns_enabled(false)
                .keypair(pk, sk)
                .build()
                .map_err(|e| format!("config: {e:?}"))?,
        )
        .await
        .map(Arc::new)
        .map_err(|e| format!("node: {e:?}"))?
    }};
}

static PREFIXES: LazyLock<Mutex<HashSet<[u8; 2]>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

type NewKeys = (new::MlDsaPublicKey, new::MlDsaSecretKey);
type OldKeys = (old::MlDsaPublicKey, old::MlDsaSecretKey);

/// A (new) gets the greater PeerId, so it is the arbiter. B's 2-byte prefix is
/// unique in this run (A's retirement logs name the peer by it).
fn keys() -> Result<(NewKeys, [u8; 32], OldKeys, [u8; 32]), String> {
    loop {
        let b = old::generate_ml_dsa_keypair().map_err(|e| format!("{e:?}"))?;
        let b_id = old::derive_peer_id_from_public_key(&b.0).0;
        if b_id[0] > 0xE0 {
            continue;
        }
        if !PREFIXES
            .lock()
            .map_err(|_| "prefix lock".to_string())?
            .insert([b_id[0], b_id[1]])
        {
            continue;
        }
        loop {
            let a = new::generate_ml_dsa_keypair().map_err(|e| format!("{e:?}"))?;
            let a_id = new::derive_peer_id_from_public_key(&a.0).0;
            if a_id > b_id {
                return Ok((a, a_id, b, b_id));
            }
        }
    }
}

// -------------------------------------------------------------- iteration

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Variant {
    /// B sends nothing after it finalizes L; d in [22, 30] s.
    None,
    /// B sends one message at t_s in [29.95, 30.10] s, around A's claim, on
    /// its route at that time; d in [26, 29.5] s.
    Window,
    /// B's own 5 s timer on W is aimed at A's retirement of L: d in
    /// [25.005, 25.035] s, so the timer fires at about 30.02 s, when A completes
    /// L (the total-loss interleaving of ADR-017 F4).
    Coincide,
}

#[derive(Clone, Debug)]
struct Params {
    index: usize,
    variant: Variant,
    d: Duration,
    t_s: Option<Duration>,
    /// The close watcher's interval (1 ms; 100 ms for the coarse run).
    close_poll: Duration,
}

#[derive(Clone, Debug)]
struct SendRecord {
    seq: u32,
    at: Duration,
    route: Option<usize>,
    ok: bool,
}

#[derive(Debug, Default)]
struct Outcome {
    class: String,
    claim_at: Option<Duration>,
    completed_at: Option<Duration>,
    aborted: bool,
    finalize_at: Duration,
    b_kept_w_at_finalize: bool,
    b_l_close: Option<(Duration, String)>,
    b_w_close: Option<(Duration, String)>,
    sent_ok: usize,
    send_errors: usize,
    lost: Vec<(u32, Duration, &'static str)>,
    lost_outside_window: Vec<(u32, Duration, &'static str)>,
    /// For each lost message: (route, after A's claim in us, before B saw
    /// the route close in us).
    lost_detail: Vec<String>,
    /// For each lost message: (us after A's claim, us before B saw the route
    /// close).
    loss_margins_us: Vec<(i128, i128)>,
    window_sends: usize,
    total_disconnect: bool,
    redials: usize,
    recovery: Option<Duration>,
    final_a_to_b: bool,
    final_b_to_a: bool,
    open_a: usize,
    open_b: usize,
}

fn encode(index: usize, seq: u32) -> Vec<u8> {
    format!("f4 {index} {seq}").into_bytes()
}

fn decode(data: &[u8]) -> Option<u32> {
    std::str::from_utf8(data)
        .ok()?
        .split_whitespace()
        .nth(2)?
        .parse()
        .ok()
}

/// The ADR-017 F4 window, from the measured boundaries only. A lost send
/// (`send` returned Ok, A never received it) is inside the window when it
/// went on L after A's claim and before B saw L close, or on W at or after
/// B's own timer closed W. `close_poll` is the watcher's interval: B's close
/// of W can be seen up to one interval late.
fn loss_in_f4_window(
    at: Duration,
    route: LossRoute,
    claim: Option<Duration>,
    l_close_seen: Option<Duration>,
    w_close_seen: Option<Duration>,
    close_poll: Duration,
) -> bool {
    match route {
        LossRoute::L => match (claim, l_close_seen) {
            (Some(claim), Some(close)) => at + CLAIM_SLACK >= claim && at <= close + SEND_SLACK,
            _ => false,
        },
        LossRoute::W => w_close_seen.is_some_and(|close| at + close_poll >= close),
        LossRoute::Other => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LossRoute {
    L,
    W,
    Other,
}

/// Check (c): a total disconnect is the F4 coincidence when B's own close of W
/// happened within F4_COINCIDENCE of A completing L. `gap_us` is the measured
/// gap (B's observed close of W minus A's completion of L). The watcher only
/// ever observes a close late, by at most one `close_poll`, so the measured
/// gap can exceed the true gap by up to `close_poll` and is never smaller.
/// The allowance is therefore one-sided:
/// `-F4_COINCIDENCE <= gap <= F4_COINCIDENCE + close_poll`.
fn total_disconnect_is_f4_coincidence(gap_us: Option<i128>, close_poll: Duration) -> bool {
    let lower = -(F4_COINCIDENCE.as_micros() as i128);
    let upper = (F4_COINCIDENCE + close_poll).as_micros() as i128;
    gap_us.is_some_and(|gap| gap >= lower && gap <= upper)
}

/// Negative and positive controls for the window predicate, for check (c)
/// and for the completeness rule. The gate does not run if one of them fails.
fn self_test() -> Result<(), String> {
    let ms = Duration::from_millis;
    let poll = ms(1);
    let claim = Some(ms(30_000));
    let l_close = Some(ms(30_025));
    let w_close = Some(ms(30_100));
    let cases: [(&str, Duration, LossRoute, bool); 9] = [
        ("L, 50 ms before the claim", ms(29_950), LossRoute::L, false),
        ("L, 2 ms before the claim", ms(29_998), LossRoute::L, false),
        (
            "L, 1 ms before the claim (slack)",
            ms(29_999),
            LossRoute::L,
            true,
        ),
        ("L, between claim and close", ms(30_010), LossRoute::L, true),
        (
            "L, 2 ms after B saw L close",
            ms(30_027),
            LossRoute::L,
            false,
        ),
        (
            "L, 50 ms after B saw L close",
            ms(30_075),
            LossRoute::L,
            false,
        ),
        (
            "W, 50 ms before B closed W",
            ms(30_050),
            LossRoute::W,
            false,
        ),
        ("W, after B closed W", ms(30_100), LossRoute::W, true),
        ("other route", ms(30_010), LossRoute::Other, false),
    ];
    for (name, at, route, expected) in cases {
        let got = loss_in_f4_window(at, route, claim, l_close, w_close, poll);
        if got != expected {
            return Err(format!(
                "window control '{name}': got {got}, expected {expected}"
            ));
        }
    }
    if loss_in_f4_window(ms(30_010), LossRoute::L, None, l_close, w_close, poll) {
        return Err("window control: a loss with no claim must be outside".into());
    }
    // Check (c): the late-observation allowance applies above only.
    let coincidence_cases: [(&str, Option<i128>, u64, bool); 10] = [
        (
            "100 ms watcher, W closed 50 ms before L completed",
            Some(-50_000),
            100,
            false,
        ),
        (
            "1 ms watcher, W closed 5.5 ms before L completed",
            Some(-5_500),
            1,
            false,
        ),
        (
            "1 ms watcher, W closed 4 ms before L completed",
            Some(-4_000),
            1,
            true,
        ),
        (
            "100 ms watcher, W closed 5 ms before L completed",
            Some(-5_000),
            100,
            true,
        ),
        (
            "1 ms watcher, W seen 5.9 ms after L completed",
            Some(5_900),
            1,
            true,
        ),
        (
            "1 ms watcher, W seen 6.5 ms after L completed",
            Some(6_500),
            1,
            false,
        ),
        (
            "100 ms watcher, W seen 104 ms after L completed",
            Some(104_000),
            100,
            true,
        ),
        (
            "100 ms watcher, W seen 106 ms after L completed",
            Some(106_000),
            100,
            false,
        ),
        ("no measured gap", None, 1, false),
        ("gap 0", Some(0), 1, true),
    ];
    for (name, gap, poll_ms, expected) in coincidence_cases {
        let got = total_disconnect_is_f4_coincidence(gap, ms(poll_ms));
        if got != expected {
            return Err(format!(
                "check (c) control '{name}': got {got}, expected {expected}"
            ));
        }
    }
    let complete = |requested: usize, completed: usize, failed: usize| {
        requested > 0 && completed == requested && failed == 0
    };
    if complete(0, 0, 0) || complete(600, 599, 0) || complete(600, 600, 1) || !complete(600, 600, 0)
    {
        return Err("completeness control failed".into());
    }
    Ok(())
}

async fn iteration(p: Params) -> Result<Outcome, String> {
    let (a_kp, a_id, b_kp, b_id) = keys()?;
    let prefix = format!("{:02x}{:02x}", b_id[0], b_id[1]);
    let a = node!(new, a_kp);
    let b = node!(old, b_kp);
    let a_peer_at_b = old::PeerId(a_id);
    let b_peer_at_a = new::PeerId(b_id);
    let a_addr = lo(a.local_addr().ok_or("A has no local address")?);

    let a_accepts = Arc::new(AtomicUsize::new(0));
    {
        let a = Arc::clone(&a);
        let accepts = Arc::clone(&a_accepts);
        tokio::spawn(async move {
            while a.accept().await.is_some() {
                accepts.fetch_add(1, Ordering::SeqCst);
            }
        });
    }
    {
        let b = Arc::clone(&b);
        tokio::spawn(async move { while b.accept().await.is_some() {} });
    }
    let received: Arc<Mutex<HashMap<u32, Instant>>> = Arc::new(Mutex::new(HashMap::new()));
    {
        let a = Arc::clone(&a);
        let received = Arc::clone(&received);
        tokio::spawn(async move {
            while let Ok((peer, data)) = a.recv().await {
                if peer.0 == b_id
                    && let Some(seq) = decode(&data)
                    && let Ok(mut map) = received.lock()
                {
                    map.entry(seq).or_insert_with(Instant::now);
                }
            }
        });
    }
    let b_got_from_a = Arc::new(AtomicUsize::new(0));
    {
        let b = Arc::clone(&b);
        let got = Arc::clone(&b_got_from_a);
        tokio::spawn(async move {
            while let Ok((peer, data)) = b.recv().await {
                if peer.0 == a_id && data.starts_with(b"a->b") {
                    got.fetch_add(1, Ordering::SeqCst);
                }
            }
        });
    }

    // L: start B's dial, then hold the future (B does not finalize L).
    let l_dialer = Arc::clone(&b);
    let mut l_future = Box::pin(async move { l_dialer.connect_addr(a_addr).await });
    let mut l_started = false;
    for _ in 0..5 {
        let polled = std::future::poll_fn(|cx| Poll::Ready(l_future.as_mut().poll(cx))).await;
        if let Poll::Ready(result) = polled {
            return Err(format!("L finalized at once: {result:?}"));
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && a_accepts.load(Ordering::SeqCst) < 1 {
            sleep(Duration::from_millis(10)).await;
        }
        if a_accepts.load(Ordering::SeqCst) >= 1 {
            l_started = true;
            break;
        }
    }
    if !l_started {
        return Err("A never accepted L".into());
    }

    // W: B dials again and registers it; A registers W, L is Superseded at A.
    timeout(Duration::from_secs(10), b.connect_addr(a_addr))
        .await
        .map_err(|_| "W connect timeout".to_string())?
        .map_err(|e| format!("W connect: {e:?}"))?;
    let deadline = Instant::now() + Duration::from_secs(5);
    while a_accepts.load(Ordering::SeqCst) < 2 {
        if Instant::now() >= deadline {
            return Err("A never accepted W".into());
        }
        sleep(Duration::from_millis(10)).await;
    }
    let t0 = Instant::now();
    let b_w = b
        .get_quic_connection(&a_peer_at_b)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("no W at B")?;

    let mut out = Outcome::default();
    let mut sends: Vec<SendRecord> = Vec::new();
    let mut seq: u32 = 0;
    let route_of = |b: &old::P2pEndpoint| {
        b.get_quic_connection(&a_peer_at_b)
            .ok()
            .flatten()
            .map(|c| c.stable_id())
    };

    // B sends on W (its winner) until d; the last pause ends exactly at d.
    while t0.elapsed() < p.d {
        let route = route_of(&b);
        let ok = b.send(&a_peer_at_b, &encode(p.index, seq)).await.is_ok();
        sends.push(SendRecord {
            seq,
            at: t0.elapsed(),
            route,
            ok,
        });
        seq += 1;
        let left = p.d.saturating_sub(t0.elapsed());
        if left.is_zero() {
            break;
        }
        sleep(left.min(SEND_INTERVAL)).await;
    }

    // B finalizes L late.
    timeout(Duration::from_secs(10), &mut l_future)
        .await
        .map_err(|_| "L finalize timeout".to_string())?
        .map_err(|e| format!("L finalize: {e:?}"))?;
    out.finalize_at = t0.elapsed();
    let b_l = b
        .get_quic_connection(&a_peer_at_b)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("no winner at B after the finalize")?;
    out.b_kept_w_at_finalize = b_l.stable_id() == b_w.stable_id();
    let l_id = b_l.stable_id();
    let w_id = b_w.stable_id();

    // A watcher records when B first sees L and W closed (every `close_poll`).
    let close_poll = p.close_poll;
    type Seen = Option<(Duration, String)>;
    let closes: Arc<Mutex<(Seen, Seen)>> = Arc::new(Mutex::new((None, None)));
    let watcher_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let closes = Arc::clone(&closes);
        let stop = Arc::clone(&watcher_stop);
        let (b_l, b_w) = (b_l.clone(), b_w.clone());
        tokio::spawn(async move {
            while !stop.load(Ordering::SeqCst) {
                let now = t0.elapsed();
                if let Ok(mut seen) = closes.lock() {
                    if seen.0.is_none()
                        && let Some(reason) = b_l.close_reason()
                    {
                        seen.0 = Some((now, format!("{reason:?}")));
                    }
                    if seen.1.is_none()
                        && let Some(reason) = b_w.close_reason()
                    {
                        seen.1 = Some((now, format!("{reason:?}")));
                    }
                    if seen.0.is_some() && seen.1.is_some() {
                        break;
                    }
                }
                sleep(close_poll).await;
            }
        });
    }
    let read_closes = |out: &mut Outcome| {
        if let Ok(seen) = closes.lock() {
            out.b_l_close = seen.0.clone();
            out.b_w_close = seen.1.clone();
        }
    };

    // Watch until the first close at B (or WATCH_UNTIL); the window variant
    // sends one message at t_s.
    let mut window_sent = false;
    let event_at = loop {
        let now = t0.elapsed();
        let _ = now;
        read_closes(&mut out);
        if let Some(t_s) = p.t_s
            && !window_sent
            && now >= t_s
        {
            window_sent = true;
            let route = route_of(&b);
            let ok = b.send(&a_peer_at_b, &encode(p.index, seq)).await.is_ok();
            sends.push(SendRecord {
                seq,
                at: t0.elapsed(),
                route,
                ok,
            });
            seq += 1;
        }
        if out.b_l_close.is_some() || out.b_w_close.is_some() || now >= WATCH_UNTIL {
            break now;
        }
        sleep(Duration::from_millis(2)).await;
    };

    // Recovery: application sends every 100 ms; re-dial when B has no
    // connection or a send fails.
    let recovery_start = t0.elapsed();
    let first_recovery_seq = seq;
    let recovery_deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let now = t0.elapsed();
        let _ = now;
        read_closes(&mut out);
        let delivered = received.lock().ok().and_then(|map| {
            map.iter()
                .filter(|(s, _)| **s >= first_recovery_seq)
                .map(|(_, at)| *at)
                .min()
        });
        if let Some(at) = delivered {
            out.recovery = Some(at.saturating_duration_since(t0).saturating_sub(event_at));
            break;
        }
        if Instant::now() >= recovery_deadline {
            break;
        }
        let route = route_of(&b);
        if route.is_none() {
            out.total_disconnect = true;
            out.redials += 1;
            let _ = timeout(Duration::from_secs(10), b.connect_addr(a_addr)).await;
            continue;
        }
        let ok = b.send(&a_peer_at_b, &encode(p.index, seq)).await.is_ok();
        sends.push(SendRecord {
            seq,
            at: t0.elapsed(),
            route,
            ok,
        });
        seq += 1;
        if !ok {
            out.redials += 1;
            let _ = timeout(Duration::from_secs(10), b.connect_addr(a_addr)).await;
        }
        sleep(Duration::from_millis(100)).await;
    }
    let _ = recovery_start;

    // Let the old timer and the arbiter settle, then the final checks.
    let settle_until =
        (out.finalize_at + Duration::from_secs(7)).max(event_at + Duration::from_secs(8));
    while t0.elapsed() < settle_until {
        let now = t0.elapsed();
        let _ = now;
        read_closes(&mut out);
        sleep(Duration::from_millis(5)).await;
    }
    read_closes(&mut out);
    watcher_stop.store(true, Ordering::SeqCst);
    if out.b_l_close.is_some() && out.b_w_close.is_some() {
        // Both of the pair's connections closed (a new dial may have followed).
        out.total_disconnect = true;
    }
    let final_seq = seq;
    let route = route_of(&b);
    let ok = b
        .send(&a_peer_at_b, &encode(p.index, final_seq))
        .await
        .is_ok();
    sends.push(SendRecord {
        seq: final_seq,
        at: t0.elapsed(),
        route,
        ok,
    });
    let _ = a.send(&b_peer_at_a, b"a->b final").await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let b_to_a = received
            .lock()
            .map(|m| m.contains_key(&final_seq))
            .unwrap_or(false);
        let a_to_b = b_got_from_a.load(Ordering::SeqCst) > 0;
        if b_to_a && a_to_b {
            break;
        }
        sleep(Duration::from_millis(20)).await;
    }
    sleep(Duration::from_millis(500)).await;
    out.final_b_to_a = received
        .lock()
        .map(|m| m.contains_key(&final_seq))
        .unwrap_or(false);
    out.final_a_to_b = b_got_from_a.load(Ordering::SeqCst) > 0;
    out.open_a = a.quic_open_connections();
    out.open_b = b.quic_open_connections();

    // A's retirement events for B.
    if let Ok(events) = EVENTS.lock() {
        for event in events.iter().filter(|event| event.prefix == prefix) {
            let at = event.at.saturating_duration_since(t0);
            match event.kind {
                "claimed" => {
                    out.claim_at.get_or_insert(at);
                }
                "completed" => {
                    out.completed_at.get_or_insert(at);
                }
                _ => out.aborted = true,
            }
        }
    }

    // (a) losses and the F4 window.
    let received = received.lock().map(|m| m.clone()).unwrap_or_default();
    let l_close_seen = out.b_l_close.as_ref().map(|(at, _)| *at);
    let w_close_seen = out.b_w_close.as_ref().map(|(at, _)| *at);
    for send in &sends {
        if !send.ok {
            out.send_errors += 1;
            continue;
        }
        out.sent_ok += 1;
        let route = if send.route == Some(l_id) && l_id != w_id {
            LossRoute::L
        } else if send.route == Some(w_id) {
            LossRoute::W
        } else {
            LossRoute::Other
        };
        let in_window = loss_in_f4_window(
            send.at,
            route,
            out.claim_at,
            l_close_seen,
            w_close_seen,
            p.close_poll,
        );
        if in_window {
            out.window_sends += 1;
        }
        if received.contains_key(&send.seq) {
            continue;
        }
        let route_name = match route {
            LossRoute::L => "L",
            LossRoute::W => "W",
            LossRoute::Other => "other",
        };
        out.lost.push((send.seq, send.at, route_name));
        let after_claim = out
            .claim_at
            .map(|claim| send.at.as_micros() as i128 - claim.as_micros() as i128);
        let close_seen = if route == LossRoute::L {
            l_close_seen
        } else {
            w_close_seen
        };
        let before_close =
            close_seen.map(|close| close.as_micros() as i128 - send.at.as_micros() as i128);
        if let (Some(after), Some(before)) = (after_claim, before_close) {
            out.loss_margins_us.push((after, before));
        }
        out.lost_detail.push(format!(
            "seq={} route={route_name} after_claim_us={after_claim:?} before_close_seen_us={before_close:?}",
            send.seq
        ));
        if !in_window {
            out.lost_outside_window
                .push((send.seq, send.at, route_name));
        }
    }

    out.class = match (
        out.claim_at.is_some(),
        out.b_l_close.is_some(),
        out.b_w_close.is_some(),
    ) {
        _ if out.total_disconnect => "total-disconnect",
        (true, true, false) => "A retired L; pair kept W",
        (false, false, true) => "B closed W; pair kept L",
        (false, false, false) => "no close",
        (true, _, true) => "A claimed, W closed",
        _ => "other",
    }
    .to_string();

    a.shutdown().await;
    b.shutdown().await;
    Ok(out)
}

fn percentile(sorted: &[Duration], q: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let index = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[index.min(sorted.len() - 1)]
}

#[tokio::main(flavor = "multi_thread", worker_threads = 8)]
async fn main() {
    let filter = tracing_subscriber::filter::Targets::new()
        .with_target("ant_quic::p2p_endpoint", tracing::Level::INFO);
    let subscriber = tracing_subscriber::registry().with(Capture.with_filter(filter));
    if tracing::subscriber::set_global_default(subscriber).is_err() {
        eprintln!("tracing subscriber already set");
        std::process::exit(2);
    }

    let mut args = std::env::args().skip(1);
    let per_variant: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(200);
    let concurrency: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(16);
    let seed: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(313_0258);
    let close_poll_ms: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(1);
    let close_poll = Duration::from_millis(close_poll_ms.max(1));
    println!(
        "f4gate: {per_variant} iterations per variant, concurrency {concurrency}, seed {seed}, close watcher {} ms",
        close_poll.as_millis()
    );
    if let Err(e) = self_test() {
        println!("F4 RESULT: SELF-TEST FAILED: {e}");
        std::process::exit(3);
    }
    println!("self-test: window and completeness controls pass");
    if per_variant == 0 || concurrency == 0 {
        println!(
            "F4 RESULT: NOTHING TO RUN (iterations per variant and concurrency must be at least 1)"
        );
        std::process::exit(1);
    }
    let requested = per_variant * 3;

    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let mut params = Vec::new();
    for index in 0..per_variant * 3 {
        let variant = match index % 3 {
            0 => Variant::None,
            1 => Variant::Window,
            _ => Variant::Coincide,
        };
        let (d, t_s) = match variant {
            Variant::None => (Duration::from_millis(rng.gen_range(22_000..=30_000)), None),
            Variant::Window => (
                Duration::from_millis(rng.gen_range(26_000..=29_500)),
                Some(Duration::from_micros(
                    rng.gen_range(29_950_000..=30_100_000),
                )),
            ),
            Variant::Coincide => (
                Duration::from_micros(rng.gen_range(25_005_000..=25_035_000)),
                None,
            ),
        };
        params.push(Params {
            index,
            variant,
            d,
            t_s,
            close_poll,
        });
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = tokio::task::JoinSet::new();
    for p in params {
        let semaphore = Arc::clone(&semaphore);
        tasks.spawn(async move {
            let _permit = semaphore.acquire_owned().await;
            // Negative control for the completeness rule: F4_INJECT_TASK_PANIC
            // names one iteration index whose task fails.
            if std::env::var("F4_INJECT_TASK_PANIC")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                == Some(p.index)
            {
                panic!("injected task failure for iteration {}", p.index);
            }
            let result = iteration(p.clone()).await;
            (p, result)
        });
    }

    let mut results = Vec::new();
    let mut task_failures = 0usize;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok((p, result)) => {
                match &result {
                    Ok(o) => println!(
                        "iter {:3} {:?} d={:.4}s fin={:.4}s t_s={:?} class=[{}] claim={:?} done={:?} L-close={:?} W-close={:?} gapWdone_us={:?} lost={} lost_outside={} window_sends={} recovery_us={:?} redials={} final b->a={} a->b={} open A={} B={} b_kept_w={} errors={} lost_detail={:?}",
                        p.index,
                        p.variant,
                        p.d.as_secs_f64(),
                        o.finalize_at.as_secs_f64(),
                        p.t_s.map(|t| t.as_secs_f64()),
                        o.class,
                        o.claim_at.map(|t| t.as_secs_f64()),
                        o.completed_at.map(|t| t.as_secs_f64()),
                        o.b_l_close.as_ref().map(|(t, r)| (
                            t.as_secs_f64(),
                            r.chars().take(60).collect::<String>()
                        )),
                        o.b_w_close.as_ref().map(|(t, r)| (
                            t.as_secs_f64(),
                            r.chars().take(60).collect::<String>()
                        )),
                        match (o.b_w_close.as_ref(), o.completed_at) {
                            (Some((w, _)), Some(done)) =>
                                Some(w.as_micros() as i128 - done.as_micros() as i128),
                            _ => None,
                        },
                        o.lost.len(),
                        o.lost_outside_window.len(),
                        o.window_sends,
                        o.recovery.map(|t| t.as_micros()),
                        o.redials,
                        o.final_b_to_a,
                        o.final_a_to_b,
                        o.open_a,
                        o.open_b,
                        o.b_kept_w_at_finalize,
                        o.send_errors,
                        o.lost_detail,
                    ),
                    Err(e) => println!("iter {:3} {:?} SETUP ERROR: {e}", p.index, p.variant),
                }
                results.push((p, result));
            }
            Err(e) => {
                task_failures += 1;
                println!("ITERATION TASK FAILED: {e}");
            }
        }
    }

    // Summary.
    let mut violations = Vec::new();
    let mut classes: HashMap<(String, String), usize> = HashMap::new();
    let mut loss_hist: HashMap<(String, usize), usize> = HashMap::new();
    let mut recoveries: Vec<Duration> = Vec::new();
    let mut setup_errors = 0;
    let mut total_disconnect_rows: Vec<String> = Vec::new();
    let mut total_disconnects = 0;
    let mut window_sends_total = 0;
    let mut lost_total = 0;
    for (p, result) in &results {
        let variant = format!("{:?}", p.variant);
        let o = match result {
            Ok(o) => o,
            Err(_) => {
                setup_errors += 1;
                continue;
            }
        };
        *classes
            .entry((variant.clone(), o.class.clone()))
            .or_default() += 1;
        *loss_hist
            .entry((variant.clone(), o.lost.len()))
            .or_default() += 1;
        lost_total += o.lost.len();
        window_sends_total += o.window_sends;
        if o.total_disconnect {
            total_disconnects += 1;
        }
        if !o.lost_outside_window.is_empty() {
            violations.push(format!(
                "iter {} (a): lost outside the F4 window: {:?}",
                p.index, o.lost_outside_window
            ));
        }
        if o.lost.len() > o.window_sends {
            violations.push(format!(
                "iter {} (a): lost {} > window sends {}",
                p.index,
                o.lost.len(),
                o.window_sends
            ));
        }
        match o.recovery {
            Some(r) => {
                recoveries.push(r);
                if r > RECOVERY_BOUND {
                    violations.push(format!(
                        "iter {} (b): recovery {:?} > {:?}",
                        p.index, r, RECOVERY_BOUND
                    ));
                }
            }
            None => violations.push(format!("iter {} (b): delivery never resumed", p.index)),
        }
        if o.total_disconnect {
            // (c) ADR-017 F4 allows a total loss only when B's own timer closes
            // W at about the time A completes L. Any other total loss is worse
            // than F4.
            let gap_us = match (o.b_w_close.as_ref(), o.completed_at) {
                (Some((w, _)), Some(done)) => {
                    Some(w.as_micros() as i128 - done.as_micros() as i128)
                }
                _ => None,
            };
            total_disconnect_rows.push(format!(
                "iter {} {:?} d={:.4}s gapWdone_us={gap_us:?} recovery_us={:?} redials={}",
                p.index,
                p.variant,
                p.d.as_secs_f64(),
                o.recovery.map(|r| r.as_micros()),
                o.redials
            ));
            if !total_disconnect_is_f4_coincidence(gap_us, close_poll) {
                violations.push(format!(
                    "iter {} (c): total disconnect outside the F4 coincidence (gap {gap_us:?} us)",
                    p.index
                ));
            }
        }
        if !(o.final_a_to_b && o.final_b_to_a) {
            violations.push(format!(
                "iter {} (d): final delivery a->b={} b->a={}",
                p.index, o.final_a_to_b, o.final_b_to_a
            ));
        }
        if o.open_a != o.open_b {
            violations.push(format!(
                "iter {} (d): open connections A={} B={}",
                p.index, o.open_a, o.open_b
            ));
        }
    }
    recoveries.sort();
    println!("==== SUMMARY");
    println!(
        "iterations: {} (setup errors: {setup_errors})",
        results.len()
    );
    let mut class_rows: Vec<_> = classes.into_iter().collect();
    class_rows.sort();
    for ((variant, class), count) in class_rows {
        println!("class {variant:6} {class:28} {count}");
    }
    let mut loss_rows: Vec<_> = loss_hist.into_iter().collect();
    loss_rows.sort();
    for ((variant, lost), count) in loss_rows {
        println!("lost-per-iteration {variant:6} {lost} -> {count} iterations");
    }
    println!(
        "lost total {lost_total}; F4-window sends total {window_sends_total}; total disconnects {total_disconnects}"
    );
    for row in &total_disconnect_rows {
        println!("total-disconnect {row}");
    }
    println!(
        "recovery us: n={} min={} p50={} p90={} p99={} max={}",
        recoveries.len(),
        recoveries.first().map(|d| d.as_micros()).unwrap_or(0),
        percentile(&recoveries, 0.5).as_micros(),
        percentile(&recoveries, 0.9).as_micros(),
        percentile(&recoveries, 0.99).as_micros(),
        recoveries.last().map(|d| d.as_micros()).unwrap_or(0),
    );
    let margins: Vec<(i128, i128)> = results
        .iter()
        .filter_map(|(_, r)| r.as_ref().ok())
        .flat_map(|o| o.loss_margins_us.iter().copied())
        .collect();
    if !margins.is_empty() {
        println!(
            "loss margins us: after A's claim min={} max={}; before B saw the route close min={} max={}",
            margins.iter().map(|m| m.0).min().unwrap_or(0),
            margins.iter().map(|m| m.0).max().unwrap_or(0),
            margins.iter().map(|m| m.1).min().unwrap_or(0),
            margins.iter().map(|m| m.1).max().unwrap_or(0),
        );
    }
    let completed = results.iter().filter(|(_, r)| r.is_ok()).count();
    println!(
        "completeness: requested {requested}, completed {completed}, setup errors {setup_errors}, failed tasks {task_failures}"
    );
    if completed != requested || task_failures != 0 {
        violations.push(format!(
            "completeness: requested {requested}, completed {completed}, failed tasks {task_failures}"
        ));
    }
    for v in &violations {
        println!("VIOLATION {v}");
    }
    let _ = Q_END;
    if violations.is_empty() && setup_errors == 0 {
        println!("F4 RESULT: ALL CHECKS PASS");
    } else {
        println!(
            "F4 RESULT: {} VIOLATIONS, {setup_errors} SETUP ERRORS, {task_failures} FAILED TASKS",
            violations.len()
        );
        std::process::exit(1);
    }
}
