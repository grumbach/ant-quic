# ADR-018: Retain Direct Handshakes Across the Punch Cutoff

- **Status:** Proposed
- **Date:** 2026-10-18
- **Decision owners:** Engineer, following the Claude and Codex consensus
- **Reviewers:** Claude
- **Supersedes:** none
- **Superseded by:** none
- **Related:** ant-quic #304, #310, #344; ADR-005, ADR-008, ADR-017

## Context

A PeerId dial with an available coordinator has a short direct-stage budget.
This leaves time for hole punching when the direct route is blocked. Cancelling
the direct handshake at that cutoff also discards progress on a slow but usable
route. The caller can still have time left to finish that handshake.

## Decision Drivers

- Keep the existing stage boundaries, handshake limits and fallback budgets.
- Preserve ownership of each in-flight connection and clean up losing attempts.
- Keep the wire format and public API unchanged.

## Considered Options

1. Treat the earlier no-coordinator budget fix as sufficient. This leaves the
   coordinator-capable slow-handshake failure unresolved.
2. Give the direct stage the remaining caller budget. This delays punching and
   consumes its reserved time.
3. Start punching at the existing cutoff while the owned direct race continues
   within the caller's remaining budget.

## Decision

Implement option C (option 3 above), as assigned by Engineer after the Claude
and Codex votes on 18 October 2026. The direct-stage timer borrows the Happy
Eyeballs future. If it expires on a coordinator-capable PeerId dial, the same
future races the remaining fallback stages. Each stage retains its existing
budget and retry policy. The overlap ends at the earlier of the caller and
ladder deadlines. An exhausted fallback does not cancel a viable direct
handshake before that deadline.

The direct result goes through the existing lifecycle registration. Punch
results keep the existing winner arbitration. Dropping the owned direct race
aborts its pending attempts and releases unregistered results. No new timeout
constant, public API or wire codepoint is introduced.

## Consequences

### Positive

- Slow direct handshakes can finish after punching starts.
- Punching keeps its scheduled opportunity to establish a route.

### Negative / Trade-offs

- Direct and fallback work can overlap within the original budget.
- Cleanup must cover caller cancellation and simultaneous completion, as well
  as successful selection of either path.

### Neutral / Operational

- Existing lifecycle and reader retirement rules remain authoritative.
- No deployment, configuration or protocol negotiation change is required.

## Validation

Use real loopback QUIC connections with an injected gate that owns Connecting,
and paused Tokio time. Assert late direct success, the unchanged punch-stage
budget, caller-deadline expiry, cancellation and punch-winner loser cleanup.
Run the existing Happy Eyeballs, direct-budget, lifecycle and punch-arbitration
suites. Keep all previous assertions.

## Notes for AI-assisted work

This record remains Proposed. Only human engineering review can mark it
Accepted. Accepted ADRs are unchanged.
