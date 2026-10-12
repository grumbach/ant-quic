# ADR-017: Single-Arbiter, Evidence-Gated Connection Retirement

- **Status:** Proposed. Decided by the controller under David's delegation D259 (2026-10-12), decision C-313-3 (D1 = N1). The repository's ADR configuration (`.adr-kit.yaml`: `human_acceptance_required: true`, `ai_may_accept: false`) and `AGENTS.md` reserve the Accepted status for a human, so this file stays Proposed until a human commit marks it Accepted.
- **Date:** 2026-10-12
- **Decision owners:** David Irvine (delegated to the x0x controller, D259)
- **Reviewers:** Codex (cross-model review), x0x controller
- **Supersedes:** none
- **Superseded by:** none
- **Related:** issues #313 (Part 2), #315, #307, #310; PR #318 (#313 Part 1, released in 0.27.57); `docs/design/connection-lifecycle-sync.md`; ADR-004

## Context

Two ant-quic endpoints often hold more than one QUIC connection to each other:
a simultaneous open, a hole-punch winner and an accepted-coordination dial
between the same pair, a reconnect, or a restarted peer. Each end keeps one
**Live** winner per peer in its lifecycle and marks the others **Superseded**.
A superseded connection must eventually close (it holds sockets, keepalives
and receive buffers), but it must not close while it is the only working path.

Before this decision, retirement was a set of local timers:

- An outbound or relay registration that superseded a generation closed it
  after a fixed 5 s drain grace (`schedule_reader_generation_cancel`).
- An inbound supersede never closed the old generation (#315).
- Raw hole-punch and coordinator winners were not tracked at all (#313); R1 of
  #313 Part 2 tracks them without retirement.

Each end decides its winner locally. For connections from different
initiators, both ends compare the shared TLS-exporter connection id, so they
agree. For connections from the same initiator, each end prefers its newer
local generation, and the two ends can register in different orders. So the
two ends can keep **opposite** winners. If both ends then retire their
superseded connection on a timer, each end can close the connection that the
other end kept, and no connection survives (Codex round-2 P2-1). With three or
more candidates the per-pair decisions can even form a cycle, so that every
connection is someone's loser (Codex P2-2, corrected schedule in the plan).

No timer margin fixes this: delivery and scheduling delay are not bounded.
Without a wire change, the only safe structures are:

1. one end decides, or
2. a wire signal shares the decision or the missing order.

(A shared strict total order over connections, such as the exporter id alone,
is also safe, but it gives up the same-initiator "newer wins" semantics that
restart handling depends on, and it changes the rule both ends must share;
Codex R2-P3-1.)

## Decision Drivers

- **Safety:** retirement must never leave a pair with no working connection
  because the two ends chose differently. Network failure can still kill any
  connection; this decision must not add a way to lose all of them.
- **No wire change in 0.27.x:** no new frames, transport parameters or close
  codes. Deployed peers of every version must keep working.
- **Mixed versions by evidence, not by fleet version:** the rule must be safe
  toward peers that run older code, including peers outside our fleet.
- **Symmetric nodes (ADR-004):** no node class may be special.
- **Bounded resources:** superseded connections must eventually close when the
  peer has stopped using them.

## Considered Options

1. **N1: single arbiter per peer pair, evidence-gated retirement** (chosen).
2. **N2: never retire live superseded connections.** Safe and simple, but
   superseded connections stay open while both processes live (keepalive),
   for every pair.
3. **Round-1 design: initiator-authoritative timers with a responder margin
   M.** Rejected: no finite M orders the two ends' closes (Codex P2-1), and the
   three-candidate cycle still retires every connection (Codex P2-2).
4. **W1: a capability transport parameter (`lifecycle_arbitration_v1`).**
   Removes doubt about old peers, but it is a wire change.
5. **W2: an explicit retire handshake ("keep W, retire L", acknowledged after
   the follower drains).** The only loss-free option, but it needs a new
   control stream type: a wire change.
6. **W3: an endpoint-instance nonce (transport parameter).** Tells a restart
   from a concurrent same-initiator connection; a wire change.
7. **A shared total order on exporter ids for every pair.** Safe without
   roles, but it drops same-initiator newer-wins and changes the comparator
   both ends share; needs its own compatibility design.

## Decision

We will retire superseded connections with **N1**: for each peer pair, one end
(the arbiter) is the only end that retires, and it retires only on evidence
that the peer reads the connection the arbiter keeps.

### Roles

- **A1 Role.** For each peer pair, the **arbiter** is the end whose local
  PeerId is the greater one (byte order of the 32-byte id, which is SHA-256 of
  the ML-DSA-65 public key). The other end is the **follower**. Both ends know
  both authenticated identities, so they agree on the roles without any
  message. Two processes with the same identity are one "peer" to the other
  end; an end never arbitrates a pair with its own id.
- **A2 The follower never retires.** It runs no retirement executor and no
  supersede timer. It reads its connections. Its other closes are unchanged:
  registration-time rejection of a newcomer, the hole-punch duplicate close,
  the identity-mismatch close (#313 R1, Q6), the #368 readerless cleanup, the
  ACK-v2 liveness timeout, `disconnect` and shutdown. None of these closes a
  connection that has a running reader and is in use, except on failure or on
  explicit teardown.
- **A3 Registration-time rejection stays.** Both roles still close a rejected
  cross-family newcomer, and a hole-punch duplicate, at registration. This
  happens at handshake completion, before any reader runs on the newcomer, so
  no evidence (E2) can exist on it; the arbiter never retires anything because
  of it.

### The retirement rule

- **A4 One eligibility check.** The arbiter retires a superseded connection L
  only through one claim, `try_claim_retirement(peer, L, epoch)`. Under the
  lifecycle write lock it checks E0, the lifecycle part of E1, E2, E3(c) and
  E4. The executor (a periodic pass, woken early by probe results,
  registrations and accepts) is the only caller; just before the call it
  checks the P2P-layer facts: E1's local reader, E3(a) and E3(b). Reader exit
  cleanup never retires. Neither end pre-cancels a reader that starts late on
  a superseded connection (master did, and its exit closed the connection at
  once): that reader reads L until the claim's drain stops it, and otherwise
  ends only on failure or teardown. The #368 readerless cleanup still closes,
  at either end, an open connection that has had no local reader for 10 s
  (for example a superseded pending accept that `accept` skips). That close
  is not a retirement: the local end does not read the connection, so the
  close loses nothing that end would deliver.

| Check | Content |
|---|---|
| E0 | The local end is the arbiter for the pair (A1). |
| E1 | The current Live winner W is not L, is open, and has a running local reader. |
| E2 | A probe pinned to W, issued in W's current Live period, was answered no more than P = 3 s before the claim. The probe is the existing ACK-v2 probe request; it is answered by the peer's reader of the connection it arrived on, so an answer proves that the peer reads W. |
| E3 | (a) A follower-originated request stream (anything except a reply to our own request) arrived on W in W's current Live period. (b) No stream arrived on L for Q = 30 s, no relay stream that this end serves runs on L, and no client relay session of this end uses L (an established MASQUE relay session is active use without new streams). (c) W has been the Live winner for at least Q. |
| E4 | L is Superseded, with the obligation epoch given by the caller. The obligation is recorded at every Superseded transition (registration, adoption, follow), whether or not the connection is ever delivered by `accept`. A new Superseded period gets a new epoch; repromotion clears it, so a stale claim cannot close a later period. |

The executor collects the P2P-layer evidence during its pass, but it checks
E1's reader, E3(a), E3(b) and the relay streams again while it holds the
reader and activity locks, and it claims before it releases them. A stream
that the reader records after the claim is in flight for the drain (E5).

- **A4.1 Claim, drain, complete (E5).** The claim moves L to a new lifecycle
  state, **Retiring**. Repromotion selects a Retiring entry only when no other
  survivor exists, and a reader exit of a Retiring entry closes nothing. The
  executor then owns the drain:
  1. it stops L's reader at its next accept boundary, but only if L is
     still Retiring with the claimed epoch, checked under the reader lock.
     It marks that reader owner. The exit of a marked owner does
     bookkeeping only (no exited-reader tombstone, no lifecycle or peer
     cleanup), whatever L's state is by then. If the claim already ended,
     nothing is stopped and nothing is drained;
  2. it waits until the reader's accept loop has exited, L's uni read tasks
     and served relay streams are done, local ACK waiters on L are resolved
     and L has no unacknowledged send data, or until the cap (the configured
     `stream_read_deadline`, counted from the claim);
  3. it checks that W is still open, and it stops waiting at once when W
     closes. If W is not open, it aborts: L goes back to Superseded with a new
     epoch, the survivor is repromoted, and L's reader is restarted. (A
     repromotion that finds no other survivor also selects a Retiring L, which
     aborts the claim at once.)
  4. otherwise it completes: only if L is still Retiring with the same epoch,
     L is closed with the reserved `Superseded` close code.

  Drain completion is a completion condition, not a claim condition (Codex
  R2-P2-6), and no wait happens under the lifecycle lock.

- **A4.2 Recovery owns the reader restart.** An abort (step 3), and a
  repromotion that selects a Retiring L, mark L's reader restart as pending.
  Until a new reader of L is admitted, or 30 s pass, repromotion does not
  refuse L as readerless and the #368 cleanup skips it, so a recovery never
  closes the last connection to the peer. The restart waits for the stopped
  owner to exit (also when that owner still runs with its cancel fired), and
  it then releases the pending mark. A reader admission drops the
  exited-reader tombstone of its generation, and the reader-liveness probe
  takes a running owner of the connection over a tombstone, so the restarted
  reader keeps its lifecycle generation and is still seen as live.

### Routing

- **A5 Evidence-gated route moves.** Every route move that this decision adds
  is gated by an answered probe on the new connection (the follow in A6), and
  every retirement is gated by E2. The route choice at registration stays
  master's (the comparator, and first-wins or always-supersede for the raw
  paths), because a route frozen until evidence arrives is not master
  behaviour and would itself strand traffic (Codex R2-P2-4).
- **A6 Implicit follow.** When the follower receives a probe request from the
  arbiter on a connection X, it sends its own probe on X (at most once per
  second per connection). When that probe is answered, and X is still an open
  Superseded connection, X becomes the follower's Live winner and its previous
  winner becomes Superseded (an obligation is recorded; a follower never
  executes it). If X already is its winner, nothing changes. The follower's probe is also the arbiter's E3(a) evidence, so a quiet
  new follower still lets the arbiter retire. The arbiter probes only its
  current winner. A delayed probe on an older winner can move the follower
  back; the follower's own probe on that connection then resets E3(b), so
  nothing is retired until the arbiter's next probe moves the follower forward
  again. Following is a convergence aid, never a safety input.
- **A7 No ACK-v2, no retirement.** If `ack_receive_v2` is not negotiated on W,
  E2 cannot hold, so nothing is retired, and the follower cannot confirm a
  follow either. Routing stays master's.

### Safety argument (new ↔ new; argument, not proof)

1. Only the arbiter retires a superseded connection that has a local reader,
   and never its current winner W (E1).
2. E2 shows that W was open and read at the follower at most P before the
   claim.
3. After its reader on W runs, the follower closes W only on failure or
   teardown (A2): a follower never retires, no reader is pre-cancelled
   (A4), and the readerless cleanup needs a missing reader. A
   registration-time rejection can only hit a newcomer, before any reader
   runs on it (A3).
4. So at the claim, W is open at both ends, unless the network or an
   explicit teardown kills it. If W dies before the stop or during the
   drain, the claim ends (by the abort, or by a repromotion that selects L),
   and L survives: a stale drain does not stop a reader it no longer holds
   (A4.1 step 1), and L is not closed as readerless while its reader
   restarts (A4.2).
5. Convergence: the arbiter retires every quiet non-winner, and A6 makes a new
   follower stop using L. The comparator's non-transitivity only changes which
   W the arbiter picks, never safety (Codex P2-2).

### Mixed versions and remaining bounds

| Case | Behaviour |
|---|---|
| F1 Bounded loss classes | A follower stream opened on L after the claim is never accepted and is lost, although its `send` returned Ok. Streams in flight at the claim, including a relay stream accepted between the claim and the stop, are drained up to the cap. The cap abandons unfinished work (for example a relay session that started in that window and outlives the cap), and application bidi streams handed to `accept_bi` are not tracked. No finite timing or byte bound is claimed; callers that need delivery use ACK-v2. A loss-free handover needs a wire signal (W2). |
| F2 Resources | A superseded connection stays open while the follower keeps using it, while there is no evidence on W (for example an old follower that stays quiet on W, or a pair without ACK-v2), and while a relay session uses it. Two live processes with one identity are one peer to the arbiter: if B is quiet on its connection L, and B' supplies W's evidence, the arbiter retires L, and B then has no connection to the arbiter and must dial again (the #315 S1 case; Codex round 2, P3). This is equal to or better than master for inbound supersedes, and it replaces master's 5 s outbound close, which was the unsafe case. |
| F3 Old arbiter, new follower | The old arbiter applies master's timer closes. The new follower closes fewer connections than master, reads all of them, and follows the old arbiter's own `probe_peer` probes. |
| F4 Old follower, new arbiter | Retirement needs E3(a) from the old follower's own traffic on W, so an old follower that routes to L is never cut off. The old follower's own 5 s timer can still close W. A total loss then needs the old follower to register its newer connection at least about Q − 5 s − P (about 22 s) after that connection's handshake completed, or a connection that completes its handshake at the old follower but never at the arbiter, and in both cases the old timer must fire within about one round trip of the arbiter's claim. Example (Codex round 2): the arbiter A registers inbound L, then W at t = 0; the old B registers W and sends on it, but finalizes L only at t = 25 s, then routes to L and starts its own 5 s timer on W. A keeps B's earlier request on W as E3(a), gets a fresh answer on W near t = 30 s and retires the quiet L; if B's timer closes W before B processes L's close, and A completes L before it processes W's close, no connection survives. On master A would have kept the inbound L. The 30 s age gate makes this rare; it is not excluded. |
| F5 Three or more candidates | Only the arbiter decides; any arbiter-local choice of W is safe. |
| F6 Restart | Arbiter restart: the follower's stale connection gets no keepalive answers and idles out. Follower restart: the arbiter's stale connection is quiet and is retired after Q once the new connection has evidence. |

### Why no wire change is needed

- The roles come from the two authenticated identities.
- E2 reuses the existing ACK-v2 probe request and reply; its support is
  negotiated per connection by the existing `ack_receive_v2` transport
  parameter.
- The close uses the reserved `Superseded` application close code (in use
  since 0.27.0).
- What changes is **which end** closes a superseded connection and **when**.

### ADR-004 (D2)

A per-pair role does not conflict with ADR-004. No node class exists: every
node runs the same code, is the arbiter toward every peer whose id is smaller
than its own and the follower toward every peer whose id is greater, and has
the same capabilities in both roles. The role is derived per pair from authenticated identities, like
the TLS client/server side of one QUIC connection, which ADR-004 already
allows (Codex round-2 answer 5). It is not a capability claim, so ADR-004's
"measure, don't trust" rule is not affected.

## Consequences

### Positive

- No timing-dependent mutual retirement: a pair can no longer lose every
  connection because its two ends chose opposite winners (P2-1, P2-2).
- Inbound supersedes are retired (#315), including the stale pending-accept
  and accept-queue eviction cases, because obligations live in the lifecycle,
  not in the accept queue.
- Raw hole-punch and coordinator winners are retired like every other
  connection (#313).
- Retirement drains in-flight streams and ACK waiters before the close, up to
  a cap.
- No wire change, no public API change.

### Negative / Trade-offs

- Superseded connections stay open longer: at least Q (30 s) after the
  replacement became the winner, and while the follower keeps using them.
  Some (F2) stay open while both processes live.
- The 5 s outbound drain close that master ran on every end is gone; a
  follower never closes a superseded connection to the arbiter.
- More lifecycle transitions at the follower (follows), so more `Replaced`
  events for applications that watch them.
- A small set of old-peer interleavings (F4) can still lose every connection
  of a pair. Their bounds are stated above; a wire signal (W1/W2/W3) would
  remove them.

### Neutral / Operational

- New internal lifecycle state `Retiring`; no public type changes.
- New probe traffic: while a retirement is pending, the arbiter probes its
  winner at most once per 3 s; while the follower shows no use of the winner,
  the interval backs off to 48 s. The follower answers each arbiter probe
  (also an application `probe_peer` probe) with at most one probe per second
  per connection.
- A standalone `NatTraversalEndpoint` has no executor and retires nothing
  automatically.

## Validation

- Library regressions (all deterministic, loopback only), in
  `src/p2p_endpoint.rs` (module `retirement_n1_313`) and
  `src/nat_traversal_api.rs` (module `r2_retirement_313`):
  - opposite choices with both role assignments keep a survivor (P2-1);
  - the three-candidate schedule keeps a survivor and converges (P2-2);
  - delayed accept, delayed reader adoption, janitor tick between E2 and E3,
    and repromote/re-supersede epochs (P2-4);
  - a reader that starts late on a superseded connection at the arbiter reads
    it, and only a claim closes it (no pre-cancel; Codex Q9);
  - round 2 (Codex review of the round-1 code): an abort after the 10 s
    readerless grace keeps the last connection and restarts its reader; a
    stale drain does not stop the reader of a repromoted winner; a recovered
    connection survives a janitor sweep with its old generation; a stream
    that arrives between the pass and the claim blocks the claim; a live
    relay session blocks retirement;
  - slow stream, inline ACK-v2 bidi, reader exit of a Retiring entry, and the
    drain cap (P2-5);
  - a legacy-mode follower (master timers, no follow): an unread winner
    blocks retirement, and the old-follower timer race keeps a survivor
    (P2-6, R2-P2-3). Two demonstration tests weaken the rule in that race:
    without E3(a), E3(c) alone keeps a survivor; without E3(a) and E3(c), the
    pair loses every connection;
  - an abort when the winner dies during the drain, and stale claims,
    completions and aborts after a repromote and re-supersede (epochs);
  - #315: an inbound supersede is retired by the arbiter and kept by the
    follower; the stale pending-accept G1/G2/G3 case is retired; the
    same-peer two-ended hole-punch and coordinator race delivers on the
    replacement and leaves one connection per end after the drain deadline.
- `tests/lifecycle_active_close.rs`: the #307 close-reason test asserts
  registration-time rejection separately from retirement, with role-aware
  assertions.
- Release gates outside ant-quic CI: x0x churn, PubSub provenance and
  generation-pinned send tests (Q10), and real old-binary mixed runs in both
  roles, both registration orders, delayed accepts and three-candidate races.
- Review triggers: any new close path that can reach a connection with a
  running reader; any change to the probe exchange; any proposal for a
  lifecycle wire signal (W1/W2/W3), which would supersede the F4 bounds.

## Notes for AI-assisted work

AI tools may help draft this ADR, but **must not mark it Accepted without human review**. Accepted ADRs are immutable: create a new superseding ADR rather than editing an Accepted ADR.
