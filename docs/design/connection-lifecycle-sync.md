# ant-quic D — Connection Lifecycle Sync

**Status**: Design — pending review
**Target release**: ant-quic 0.27.0
**Motivation**: saorsa-labs/ant-quic#166 VPS follow-up — residual delivery
failures on the 6-node bootstrap mesh when connections churn.
**Scope**: transport-layer correctness. No new application-facing API
(those belong to the separately-scoped B work).

## Problem

On a churning mesh (hole-punch replacing connections, idle timeouts,
simultaneous reconnects), sender and receiver can disagree about which
`Connection` is the live one for a given `peer_id`:

1. Receiver's reader task exits (idle timeout) → `cleanup_connection`
   fires locally → quinn's idle timeout closes the connection silently
   on the wire.
2. Sender's `inner.get_connection(peer_id)` still returns the cached
   `Connection`. The sender's quinn has no reason to know the peer
   cleaned up until its own idle timer fires.
3. Sender calls `open_uni() + write_all() + finish() + stopped()`. The
   stream FIN is ACKed by the receiver's quinn transport layer (auto-ACK
   on packet delivery — does not require the application reader).
4. `send_stream.stopped()` resolves `Ok`. `P2pEndpoint::send` returns
   `Ok(())`.
5. Data sits in the receiver's quinn receive buffer, undrained by any
   application-layer reader, until the connection fully closes.
6. From the consumer's perspective, `send` succeeded but the peer
   never processed the bytes.

This is observable on the x0x VPS bootstrap mesh (6 nodes across
DO/Hetzner/Vultr) after any churn event. It is not observable in the
2-peer localhost reproducer because local connections don't idle out
during a short test window.

## Goal

Establish a single canonical live connection per `peer_id` at all
times, and make that property observable to the sender's write path
so writes into a superseded connection fail fast rather than silently
succeed.

## Non-goals

- Peer-to-peer synchronisation of the generation counter. Generations
  stay local to each endpoint.
- Coordinator-mediated connection reconciliation.
- Any change to `P2pEndpoint` public API surface — this is an internal
  refactor. (Application-facing liveness primitives are the separate
  B work at `docs/design/app-liveness-api.md`.)
- Changes to quinn's own connection lifecycle. Everything here sits on
  top of quinn.

## Design

### Connection state machine

Every `Connection` tracked by the endpoint carries explicit state:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    /// Actively serving reads and writes. `get_connection(peer_id)`
    /// returns this one (at most one per peer_id).
    Live,
    /// Superseded by a newer connection to the same peer_id. Reader
    /// task is still draining any in-flight stream but will not accept
    /// new ones. Write path MUST NOT pick this connection. Actively
    /// closing in the background.
    Superseded { replaced_by_generation: u64 },
    /// `close()` has been initiated (locally or by peer); waiting for
    /// quinn to finalise.
    Closing { reason: CloseReason },
    /// Fully closed; entry retained briefly for diagnostics then evicted.
    Closed { reason: CloseReason, closed_at: Instant },
}
```

Transitions (local, deterministic):

```
     accept_connection / dial_succeeded
              │
              ▼
          ┌─Live─┐ ◄────────────────────────────┐
          │      │                              │
          │      │ new connection to same peer  │  (winner
          │      │ wins deterministic race      │   only)
          │      ▼                              │
          │  ┌─Superseded─┐                     │
          │  │            │                     │
          │  │ active close completes           │
          │  │ (local initiated)                │
          │  ▼                                  │
          └─Closing──────▶ Closed               │
              ▲                                 │
              │                                 │
              │  peer-initiated close / idle    │
              │  timeout / transport error      │
              └─────────────────────────────────┘
```

### Deterministic replacement rule

When a new authenticated connection `C_new` arrives for a `peer_id`
that already has a `Live` connection `C_old`, both endpoints
independently resolve the race as follows:

1. Compare `(C_new.generation, C_new.established_at_unix_ms, tiebreaker_hash)`
   with `(C_old.generation, C_old.established_at_unix_ms, tiebreaker_hash)`.
2. **Winner** = higher generation. Ties broken by newer
   `established_at_unix_ms`. Further ties broken by
   `blake3(local_peer_id || remote_peer_id || connection_id)` —
   this hash is computed identically on both endpoints, so they agree
   on the winner without exchanging any lifecycle messages.
3. Winner becomes `Live`. Loser transitions to
   `Superseded { replaced_by_generation: winner_generation }`, then to
   `Closing { reason: CloseReason::Superseded }`, then `Closed`.
4. The active close uses an ant-quic-reserved QUIC application error
   code — see *Close codes* below — so the peer's quinn surfaces a
   distinguishable error when it processes the close frame.

Both endpoints perform the same comparison on the same inputs, so they
arrive at the same winner without any inter-endpoint generation sync.
The peer's `Superseded` state does not need to match the winner's
`generation` value — only the outcome (which connection is live)
matters.

### `get_connection(peer_id)` semantics

- Returns `Some(conn)` **only** when there is exactly one `Live`
  connection for `peer_id`. Otherwise `None`.
- `Superseded`, `Closing`, `Closed` entries are never returned.
- When `get_connection` returns `Some`, the caller may still hit a
  race where the connection transitions between the lookup and the
  subsequent `open_uni()`. Callers are expected to handle `open_uni`
  errors — they were already doing this for non-lifecycle errors.

### Sender-side fast-fail

Today's flow:

```rust
let connection = self.inner.get_connection(peer_id)?...;
let mut send_stream = connection.open_uni().await?;   // can succeed on a superseded conn
send_stream.write_all(data).await?;
send_stream.finish()?;
send_stream.stopped().await?;                         // auto-ACK'd by transport
```

Post-fix: `get_connection` returns the `Live` connection (per above).
In addition, before each send we check `Connection::close_reason()`.
If the connection entered `Closing` between lookup and send, we get an
immediate error instead of proceeding with a write that will be
silently eaten.

```rust
let connection = self.inner.get_connection(peer_id)?...;
if let Some(reason) = connection.close_reason() {
    return Err(EndpointError::ConnectionClosed { reason });
}
// open_uni + write + finish + stopped unchanged
```

### Close codes

Define a small reserved range in ant-quic's QUIC application error code
namespace (0x4E-5B-00–0x4E-5B-FF — ASCII "N[":

| Code | Name | Meaning |
|---|---|---|
| `0x4E5B00` | `Superseded` | This connection was replaced by a newer one to the same peer. |
| `0x4E5B01` | `ReaderExit` | The receiver's reader task exited (idle / cooperative cancel) and is not coming back. |
| `0x4E5B02` | `PeerShutdown` | The remote endpoint is shutting down. |
| `0x4E5B03` | `Banned` | Receiver-side trust policy rejected this peer. |
| `0x4E5B04` | `LifecycleCleanup` | Generic cleanup — should be rare; prefer a specific code. |

These codes are carried in the QUIC `CONNECTION_CLOSE` frame's
application error code. Sender's close-reason detection maps these
back to `CloseReason` enum variants so callers can distinguish "peer
gone" from "peer banned me".

### Observability

All state transitions emit structured tracing at `info` level with
consistent fields:

```
target: ant_quic::p2p_endpoint::lifecycle
fields:
  peer_id = <hex prefix 8>
  generation = <u64>
  from_state, to_state = Live|Superseded|Closing|Closed
  reason = <CloseReason>
  connection_id = <quinn connection id>
```

Metrics counters (Prometheus-style names, off by default behind a
feature flag):

- `ant_quic_connection_live_total{peer_id}` — current gauge
- `ant_quic_connection_transitions_total{from, to, reason}` — counter
- `ant_quic_connection_supersede_total{winner}` — counter
- `ant_quic_connection_close_code_total{code}` — counter

Internal tracing always-on; metrics behind `features = ["metrics"]`.

## Acceptance criteria

These are the tests we must pass before tagging 0.27.0:

1. **Uniqueness** — `tests/lifecycle_canonical_live.rs`: under 100
   rapid reconnect cycles from N=8 peers against a single receiver,
   `get_connection(peer_id)` returns exactly one connection at every
   observation point, and its `generation` is monotonically
   non-decreasing.

2. **Active close on cleanup** — `tests/lifecycle_active_close.rs`:
   when the receiver's reader task exits (simulated idle timeout),
   the sender observes a `close_reason` containing `ReaderExit`
   within 2× RTT, not the default idle-close timeout (~30s).

3. **Sender fast-fail on superseded** — `tests/lifecycle_sender_stale.rs`:
   with generation-race set up so A's `C_old` loses to `C_new`,
   a write on `C_old` returns `EndpointError::ConnectionClosed
   { reason: Superseded }` rather than a silent `Ok`.

4. **Deterministic replacement under race** —
   `tests/lifecycle_simultaneous_replace.rs`: two peers simultaneously
   open connections to each other; after the race resolves, both
   endpoints' `get_connection(peer_id)` returns connections that
   share the same `connection_id` on both sides (i.e. they agree on
   which connection won).

5. **Observability** — all five transitions emit the tracing event
   with the documented fields; verified by a tracing-subscriber test
   harness.

## Test plan

- **Unit**: state-machine transitions, winner-hash determinism, close
  code mapping — all in `src/p2p_endpoint.rs` module tests.
- **Integration (single-process)**: the four regression tests above
  using two `P2pEndpoint` instances on localhost.
- **Integration (two-process)**: `tests/lifecycle_interprocess.rs`
  spawns two `ant-quic` test binaries in separate processes with
  artificial idle-timeout reduction, exercises the churn pattern.
- **VPS**: runs as part of x0x's `e2e_vps.sh` once x0x picks up the
  release. No VPS tests in ant-quic itself.

## Rollout

1. Implement on branch `claude/d-connection-lifecycle-sync`.
2. PR to master, merge after review + all acceptance-criteria tests
   pass.
3. Tag `v0.27.0`. Release-notes call out the close codes and the
   `get_connection` tightening (superseded connections no longer
   returned — minor behaviour change for consumers that relied on
   the lax semantics).
4. x0x and saorsa-gossip pick up via caret-compatible version bump in
   their own release cycles. No action required in those repos — the
   change is internally additive.

## Open questions

- **Close-reason observability in quinn**: we rely on quinn's
  `Connection::close_reason()` returning the application error code
  promptly after the peer sends `CONNECTION_CLOSE`. Need to verify
  the quinn version currently vendored exposes this without additional
  polling. If not, add a small polling task.
- **Default `idle_timeout`**: current default is quinn's default
  (30s). Consider reducing to 15s so the `Superseded` path is the
  normal cleanup route rather than idle-close. Deferred decision —
  default stays as-is for 0.27.0 unless testing reveals a reason to
  change it.

## Addendum (#313 Part 2, 2026-10-12): custody and retirement

The "Deterministic replacement rule" above describes a generation-first
comparator. The code compares the TLS-exporter `connection_id` for
connections from different initiators, and `(generation, established_at, …)`
for connections from the same initiator. Both ends agree on the first case.
They can disagree on the second, because each end orders its own
generations. This addendum describes how ant-quic keeps custody of every
connection and retires superseded ones without that agreement.

### Custody (slice R1)

- Every connection is in the lifecycle. Hole-punch and accepted-coordination
  winners, which were raw winner-map inserts, now go through the registrar
  with their old winner choice: hole-punch keeps first-wins (a duplicate is
  closed), and an accepted-coordination winner always takes the slot (the
  connection it displaces becomes Superseded; nothing is closed).
- A dial is bound to its authenticated identity before anything is published
  (a mismatch closes only the new candidate).
- A registration of a connection that is already tracked creates nothing: a
  Live one keeps its generation; a Superseded, Closing or Closed one is
  refused and not closed.
- A winner-map insert never orphans an untracked value: it is adopted as
  Superseded.
- Entries of origin `Raw` keep the close behaviour they had while untracked
  (no reader pre-cancel, no `NoReader` close, no reader-exit close while open,
  no ACK-v2 liveness-timeout close). Only an explicit `disconnect(peer)` now
  also closes them.
- A Live entry of origin `Raw` never rejects a newcomer (master had no Live
  entry to compare with): the newcomer takes the route and the Raw entry
  becomes Superseded, still open.

### Retirement (slice R2, ADR-017)

The Superseded → Closing step is no longer a 5 s timer at the end that
registered the replacement. It follows ADR-017 (single arbiter,
evidence-gated):

```
 Live ──supersede──▶ Superseded ──claim (arbiter, E0-E4)──▶ Retiring
   ▲                    │  ▲                                  │   │
   │   repromote/follow │  └────────abort (winner died)───────┘   │
   └────────────────────┘                             complete (drain done)
                                                                  ▼
                                                    Closing ──▶ Closed
```

- **Obligation.** Every transition to Superseded records an obligation epoch
  in the lifecycle entry, independent of `accept` delivery. Repromotion clears
  it; a new Superseded period gets a new epoch.
- **Arbiter.** For each peer pair, the end with the greater PeerId retires;
  the other end (the follower) never does. Neither end pre-cancels a reader
  that starts late on a superseded connection: it reads the connection until
  the arbiter's drain stops it, and a reader exit never retires.
- **Claim.** The arbiter's executor claims a Superseded connection L only if:
  its winner W is open, Live and read locally (E1); a probe pinned to W in W's
  current Live period was answered at most 3 s before (E2); the follower sent
  a request stream on W in that period, no stream arrived on L for Q = 30 s,
  no relay stream or relay session runs on L (our own CONNECT-UDP handshake
  counts from the moment it selects L), and W has been Live for at least Q
  (E3); and L's obligation epoch matches (E4). The reader, activity
  and relay evidence is checked again under locks at the claim.
- **Drain and completion.** The claim moves L to `Retiring`. The executor
  stops L's reader at its next accept boundary (only while the claim still
  holds; the exit of that reader cleans up nothing), waits for its in-flight
  uni reads and served relay streams, our ACK waiters on L and unacknowledged
  send data (bounded by `stream_read_deadline`), then closes L with the
  `Superseded` code. If W dies first, it aborts: L becomes Superseded again
  (or is repromoted at once) and its reader restarts. The restart owns L's
  reader until a reader that accepts streams runs, L closes, or the endpoint
  shuts down: it never gives up while L is open, it waits for the stopped
  reader to exit (and aborts it after 5 s if it still waits inside a
  stream), and it keeps L marked as restart-pending meanwhile, so neither
  repromotion nor the #368 janitor closes it as readerless. This covers
  Raw connections too, which have no #368 backstop.
- **Follow.** A follower that receives the arbiter's probe on a Superseded
  connection X probes X itself; when that probe is answered it makes X its
  Live winner. Its probe is also the arbiter's E3 evidence.
- Without ACK-v2 on W, nothing is retired.

Safety argument, residual bounds (F1-F6) and mixed-version behaviour:
`docs/adr/ADR-017-single-arbiter-connection-retirement.md`.

### ADR-017 F4 mixed-version evidence (0.27.58 release gate)

ADR-017 is Accepted and frozen, so the evidence for its F4 row is kept here.
Harness: `scripts/mixed-version-f4` (a standalone crate, not in the
workspace and not packaged). It runs the released 0.27.57 from crates.io as
the follower B and this tree as the arbiter A, in one process, on loopback,
with production timing (Q = 30 s, P = 3 s, B's own 5 s supersede timer).
Usage: `cargo run --release -- [iterations per variant] [concurrency] [seed]
[close watcher ms]`.

Schedule (the F4 example; two connections, L and W, between one A and one
B): B dials L and A registers the inbound L. B's own finalize of L is held
(its `connect_addr` future is not polled again). B dials W; A registers W at
t = 0, and L is Superseded at A. B sends on W every 250 ms until t = d. At
t = d, B finalizes L: L becomes B's winner, and B starts its 5 s timer on W.
A keeps B's earlier requests on W as E3(a). Variants, 200 iterations each per
run, with random timing:

- `none`: d in [22, 30] s; B sends nothing after d;
- `window`: d in [26, 29.5] s; B sends one message at t_s in [29.95, 30.10] s,
  which is around A's claim, inside the F4 window;
- `coincide`: d in [25.005, 25.035] s, so B's timer fires at about the time A
  completes L (the F4 total-loss interleaving).

After the first close that B sees, B's application sends every 100 ms and
dials again when it has no connection. A watcher records B's close times
(every 1 ms, or every 100 ms in the coarse run); A's claims and completions
come from its tracing events. Checks:

- (a) every lost message (`send` returned Ok, A never received it) is inside
  the F4 window, from the measured boundaries only: on L, from A's claim less
  1 ms to B's observation of L's close plus 1 ms; or on W at or after B's own
  close of W, less one watcher interval. The 1 ms at the claim end covers the
  one-way loopback delay and the lag of A's claim event; the 1 ms at the close
  end covers one `send` call (the watcher never sees the close before B
  processes it). Any other loss is a violation;
- (b) delivery resumes within 15 s;
- (c) every total disconnect is the F4 coincidence: B's timer closed W within
  5 ms of A completing L, plus one watcher interval (the resolution of the
  measured gap);
- (d) at the end both directions deliver, and both ends have the same number
  of open connections.

The run passes only if every requested iteration completed (a setup error,
a failed iteration task, an empty run or a zero concurrency fails it). Before
each run, a self test checks the window predicate with losses just outside
each boundary (2 ms and 50 ms before the claim, 2 ms and 50 ms after B saw L
close, 50 ms before B's close of W) and the completeness rule. A control run
with one injected task failure (`F4_INJECT_TASK_PANIC`) fails, and an empty
run fails.

#### Results of the final harness (library code of `9ae09493`)

| Run | Seed | Watcher | Result |
|---|---|---|---|
| definitive | 3130263 | 1 ms | 600 of 600 iterations; ALL CHECKS PASS |
| coarse | 3130264 | 100 ms | 600 of 600 iterations; ALL CHECKS PASS |

Outcomes, definitive run:

| Variant | Outcome | Iterations |
|---|---|---|
| none | B's timer closed W first; the pair kept L | 54 |
| none | A retired L; B repromoted W; the pair kept W | 145 |
| none | A claimed L, B's timer closed W during A's drain, A aborted and kept L | 1 |
| window | the message came before A's claim, so A did not claim; the pair kept L | 53 |
| window | A retired L; the pair kept W | 147 |
| coincide | A claimed L, B's timer closed W during A's drain, A aborted and kept L | 75 |
| coincide | A retired L before B's timer; the pair kept W | 113 |
| coincide | B's timer closed W before A's claim; the pair kept L | 1 |
| coincide | **total disconnect** | 11 |

- (a) Loss, definitive run: 41 messages in 600 iterations (39 in `window`, 2 in
  `coincide`, 0 in `none`), at most one per iteration in this workload. All
  were inside the F4 window: they were sent 1.13 to 21.84 ms after A's claim
  and 1.45 to 23.66 ms before B saw L close. No loss was outside it. Coarse
  run: 24 messages, all in `window`, all inside the window (1.12 to 21.76 ms
  after A's claim; the close-end margins, 19.7 to 103.8 ms, have the 100 ms
  watcher resolution).
- (b) Recovery after the first close that B sees, definitive run: p50 192 us,
  p90 1.24 ms, p99 13.7 ms, max 103 ms. Coarse run: p50 199 us, p99 1.48 ms,
  max 10.2 ms.
- (c) Total disconnects, definitive run: 0 of 400 iterations in `none` and
  `window`; 11 of 200 in `coincide`. Their d values span 25.0147 to 25.0264 s
  (about 12 ms, because A's completion time also varies from iteration to
  iteration). The measured gap between B's close of W and A's completion of L
  spans −18 us to +2.56 ms. Coarse run: 10 of 200 in `coincide`, and 1 of 200
  in `none`, a random draw at d = 25.0140 s, inside the same band; their
  measured gaps (54 to 66 ms) carry the 100 ms watcher resolution. Every total
  disconnect recovered with one dial by B's application, in 0.9 ms to 103 ms.
- (d) In all 1200 iterations both directions delivered at the end, and both
  ends had one open connection.

#### Earlier runs (the first harness, commit `c85534ae`)

- Seed 3130258 (600 iterations; close times sampled at up to 100 ms in the
  recovery loop; its check (c) was "no total disconnect at all"): it ended
  with 15 violations and exit code 1. All 15 were total disconnects in
  `coincide` (0 in `none` and `window`), that is, this run reproduced the
  total-loss exception that F4 permits, under the old assertion. (a), (b) and
  (d) held.
- Seed 3130259 (600 iterations; 1 ms watcher; check (c) as above, but the
  loss window then had a 100 ms slack at each end): all checks passed. Its 26
  recorded losses also satisfy the strict window above (1.19 to 21.55 ms after
  A's claim, 1.36 to 20.82 ms before B saw L close).
- Seed 3130260 (90 iterations of the committed first harness): all checks
  passed.
- During the harness fix, seeds 3130261 (1 ms) and 3130262 (100 ms) ran with
  the strict window but with a check (c) that did not yet allow for the
  watcher resolution. The 1 ms run passed. The 100 ms run reported its 11
  `coincide` total disconnects as outside the 5 ms coincidence: their
  measured gaps (52 to 60 ms) were the 100 ms watcher resolution, and their d
  values were in the same band. The check now adds one watcher interval;
  seeds 3130263 and 3130264 are the runs of the final harness.

#### What this shows, and its scope

For the sampled two-connection schedule (one old follower process with
connections L and W to one new arbiter, in one process on loopback), the
total loss that F4 describes is real and is the only total loss seen. It
needs B's own 5 s timer to close W within about 2.6 ms of A completing L (A's
claim plus its drain, about 21 ms); a timer that fires between A's claim and
its completion makes A abort and keep L. In the other iterations at least one
connection survived. Every loss was inside the F4 window (messages that B sent
on L after A's claim and before it saw L close), and the pair recovered when
one end dialled again. F4 also needs B to finalize L at least about 22 s after
the handshake completed, a stalled old peer; the harness forces that stall.
These runs do not cover three or more candidate connections with an old peer,
separate processes, real networks, or other send rates, so "at most one lost
message per iteration" is a result of this workload, not a bound.
