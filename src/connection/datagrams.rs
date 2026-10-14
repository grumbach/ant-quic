// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

use std::collections::VecDeque;

use bytes::Bytes;
use thiserror::Error;
use tracing::{debug, trace};

use super::Connection;
use crate::{
    TransportError,
    frame::{Datagram, FrameStruct},
};

/// API to control datagram traffic
pub struct Datagrams<'a> {
    pub(super) conn: &'a mut Connection,
}

impl Datagrams<'_> {
    /// Queue an unreliable, unordered datagram for immediate transmission
    ///
    /// If `drop` is true, previously queued datagrams which are still unsent may be discarded to
    /// make space for this datagram, in order of oldest to newest. If `drop` is false, and there
    /// isn't enough space due to previously queued datagrams, this function will return
    /// `SendDatagramError::Blocked`. `Event::DatagramsUnblocked` will be emitted once datagrams
    /// have been sent.
    ///
    /// Returns `Err` iff a `len`-byte datagram cannot currently be sent.
    pub fn send(&mut self, data: Bytes, drop: bool) -> Result<(), SendDatagramError> {
        if self.conn.config.datagram_receive_buffer_size.is_none() {
            return Err(SendDatagramError::Disabled);
        }
        let max = self
            .max_size()
            .ok_or(SendDatagramError::UnsupportedByPeer)?;
        // Every queued datagram is charged its fixed overhead, so a datagram that cannot fit
        // the send buffer with that overhead is too large.
        let send_buffer_size = self.conn.config.datagram_send_buffer_size;
        let Some(max_buffer_payload) = send_buffer_size.checked_sub(size_of::<Datagram>()) else {
            return Err(SendDatagramError::TooLarge);
        };
        if data.len() > Ord::min(max, max_buffer_payload) {
            return Err(SendDatagramError::TooLarge);
        }
        if drop {
            self.conn
                .datagrams
                .make_space_for(data.len(), send_buffer_size);
        } else if !self
            .conn
            .datagrams
            .has_send_buffer_space(data.len(), send_buffer_size)
        {
            self.conn.datagrams.send_blocked = true;
            return Err(SendDatagramError::Blocked(data));
        }
        self.conn.datagrams.outgoing.push_back(Datagram { data });
        Ok(())
    }

    /// Compute the maximum size of datagrams that may passed to `send_datagram`
    ///
    /// Returns `None` if datagrams are unsupported by the peer or disabled locally.
    ///
    /// This may change over the lifetime of a connection according to variation in the path MTU
    /// estimate. The peer can also enforce an arbitrarily small fixed limit, but if the peer's
    /// limit is large this is guaranteed to be a little over a kilobyte at minimum.
    ///
    /// Not necessarily the maximum size of received datagrams.
    pub fn max_size(&self) -> Option<usize> {
        // We use the conservative overhead bound for any packet number, reducing the budget by at
        // most 3 bytes, so that PN size fluctuations don't cause users sending maximum-size
        // datagrams to suffer avoidable packet loss.
        let max_size = self.conn.path.current_mtu() as usize
            - self.conn.predict_1rtt_overhead(None)
            - Datagram::SIZE_BOUND;
        let limit = self
            .conn
            .peer_params
            .max_datagram_frame_size?
            .into_inner()
            .saturating_sub(Datagram::SIZE_BOUND as u64);
        Some(limit.min(max_size as u64) as usize)
    }

    /// Receive an unreliable, unordered datagram
    pub fn recv(&mut self) -> Option<Bytes> {
        self.conn.datagrams.recv()
    }

    /// Bytes available in the outgoing datagram buffer
    ///
    /// When greater than zero, [`send`](Self::send)ing a datagram of at most this size is
    /// guaranteed not to cause older datagrams to be dropped.
    pub fn send_buffer_space(&self) -> usize {
        self.conn
            .config
            .datagram_send_buffer_size
            .saturating_sub(self.conn.datagrams.outgoing.memory_used())
            .saturating_sub(size_of::<Datagram>())
    }
}

/// Result of receiving a datagram, including any drops that occurred
#[derive(Debug, Clone, Copy, Default)]
pub struct DatagramReceivedResult {
    /// Whether the receive buffer was empty before this datagram
    pub was_empty: bool,
    /// Number of old datagrams that were dropped to make room
    pub dropped_count: usize,
    /// Total bytes of dropped datagrams
    pub dropped_bytes: usize,
}

#[derive(Default)]
pub(super) struct DatagramState {
    /// Datagrams received by the local transport but not delivered to the application
    pub(super) incoming: DatagramBuffer,
    pub(super) outgoing: DatagramBuffer,
    pub(super) send_blocked: bool,
}

impl DatagramState {
    /// Queue an outgoing datagram directly, for tests that exercise the
    /// path-reset drop path without a full send handshake.
    #[cfg(test)]
    pub(super) fn test_push_outgoing(&mut self, data: Bytes) {
        self.outgoing.push_back(Datagram { data });
    }

    pub(super) fn received(
        &mut self,
        datagram: Datagram,
        window: &Option<usize>,
    ) -> Result<DatagramReceivedResult, TransportError> {
        let window = match window {
            None => {
                return Err(TransportError::PROTOCOL_VIOLATION(
                    "unexpected DATAGRAM frame",
                ));
            }
            Some(x) => *x,
        };

        // Charge the fixed per-datagram overhead too, so that every queued datagram uses
        // receive buffer space.
        let size_with_overhead = datagram.data.len().saturating_add(size_of::<Datagram>());

        if size_with_overhead > window {
            return Err(TransportError::PROTOCOL_VIOLATION("oversized datagram"));
        }

        let was_empty = self.incoming.is_empty();
        let mut dropped_count = 0;
        let mut dropped_bytes = 0;

        while self
            .incoming
            .memory_used()
            .saturating_add(size_with_overhead)
            > window
        {
            if let Some(dropped) = self.recv() {
                dropped_count += 1;
                dropped_bytes += dropped.len();
                debug!(
                    dropped_count,
                    dropped_bytes,
                    recv_buffered = self.incoming.payload_bytes,
                    incoming_len = datagram.data.len(),
                    window,
                    "dropping stale datagram (buffer full) - application not reading fast enough"
                );
            } else {
                // Buffer is empty but still can't fit - shouldn't happen with valid window
                break;
            }
        }

        self.incoming.push_back(datagram);
        Ok(DatagramReceivedResult {
            was_empty,
            dropped_count,
            dropped_bytes,
        })
    }

    /// Drop the oldest outgoing datagrams until a `datagram_len`-byte datagram fits
    fn make_space_for(&mut self, datagram_len: usize, send_buffer_size: usize) {
        while !self.has_send_buffer_space(datagram_len, send_buffer_size) {
            // `pop_front` keeps `payload_bytes` in sync; do not subtract again.
            let Some(prev) = self.outgoing.pop_front() else {
                break;
            };
            debug!(
                len = prev.data.len(),
                "dropping outgoing datagram (send buffer full)"
            );
        }
    }

    /// Whether a `datagram_len`-byte datagram fits the send buffer with its overhead
    fn has_send_buffer_space(&self, datagram_len: usize, send_buffer_size: usize) -> bool {
        let Some(total) = self
            .outgoing
            .memory_used()
            .checked_add(datagram_len)
            .and_then(|total| total.checked_add(size_of::<Datagram>()))
        else {
            return false;
        };

        total <= send_buffer_size
    }

    /// Discard outgoing datagrams with a payload larger than `max_payload` bytes
    ///
    /// Used to ensure that reductions in MTU don't get us stuck in a state where we have a datagram
    /// queued but can't send it. A datagram whose payload is exactly `max_payload` still fits and
    /// is kept.
    ///
    /// Returns `true` if datagrams were dropped while a send was blocked, i.e. the caller should
    /// emit [`Event::DatagramsUnblocked`]: dropping frees send-buffer space, but `poll_transmit`
    /// only emits that event after a successful send, so otherwise a sender waiting on the event
    /// after the queue was emptied would never be told it may retry.
    pub(super) fn drop_oversized(&mut self, max_payload: usize) -> bool {
        let before = self.outgoing.queue.len();
        self.outgoing.queue.retain(|datagram| {
            let keep = datagram.data.len() <= max_payload;
            if !keep {
                trace!(
                    "dropping {} byte datagram violating {} byte limit",
                    datagram.data.len(),
                    max_payload
                );
                self.outgoing.payload_bytes -= datagram.data.len();
            }
            keep
        });
        let dropped = before != self.outgoing.queue.len();
        if dropped && self.send_blocked {
            self.send_blocked = false;
            true
        } else {
            false
        }
    }

    /// Attempt to write a datagram frame into `buf`, consuming it from `self.outgoing`
    ///
    /// Returns whether a frame was written. At most `max_size` bytes will be written, including
    /// framing.
    pub(super) fn write(&mut self, buf: &mut Vec<u8>, max_size: usize) -> bool {
        let datagram = match self.outgoing.pop_front() {
            Some(x) => x,
            None => return false,
        };

        if buf.len() + datagram.size(true) > max_size {
            // Future work: we could be more clever about cramming small datagrams into
            // mostly-full packets when a larger one is queued first
            self.outgoing.push_front(datagram);
            return false;
        }

        trace!(len = datagram.data.len(), "DATAGRAM");

        datagram.encode(true, buf);
        true
    }

    pub(super) fn recv(&mut self) -> Option<Bytes> {
        Some(self.incoming.pop_front()?.data)
    }
}

/// Queue of datagrams that tracks the payload bytes it holds
#[derive(Default)]
pub(super) struct DatagramBuffer {
    queue: VecDeque<Datagram>,
    payload_bytes: usize,
}

impl DatagramBuffer {
    fn push_back(&mut self, datagram: Datagram) {
        self.payload_bytes += datagram.data.len();
        self.queue.push_back(datagram);
    }

    fn pop_front(&mut self) -> Option<Datagram> {
        let datagram = self.queue.pop_front()?;
        self.payload_bytes -= datagram.data.len();
        Some(datagram)
    }

    fn push_front(&mut self, datagram: Datagram) {
        self.payload_bytes += datagram.data.len();
        self.queue.push_front(datagram);
    }

    /// Payload bytes plus the fixed in-memory size of every queued datagram
    fn memory_used(&self) -> usize {
        self.payload_bytes
            .saturating_add(self.queue.len().saturating_mul(size_of::<Datagram>()))
    }

    /// Whether the oldest datagram fits a 1-RTT packet with `max_size` bytes of space
    pub(super) fn can_send_1rtt(&self, max_size: usize) -> bool {
        self.queue.front().is_some_and(|x| x.size(true) <= max_size)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

/// Errors that can arise when sending a datagram
#[derive(Debug, Error, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum SendDatagramError {
    /// The peer does not support receiving datagram frames
    #[error("datagrams not supported by peer")]
    UnsupportedByPeer,
    /// Datagram support is disabled locally
    #[error("datagram support disabled")]
    Disabled,
    /// The datagram is larger than the connection can currently accommodate
    ///
    /// Indicates that the path MTU minus overhead or the limit advertised by the peer has been
    /// exceeded.
    #[error("datagram too large")]
    TooLarge,
    /// Send would block
    #[error("datagram send blocked")]
    Blocked(Bytes),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_datagram_received_no_drop() {
        let mut state = DatagramState::default();
        let window = Some(1024);

        // Add a small datagram that fits
        let datagram = Datagram {
            data: Bytes::from(vec![0u8; 100]),
        };
        let result = state.received(datagram, &window).unwrap();

        assert!(result.was_empty);
        assert_eq!(result.dropped_count, 0);
        assert_eq!(result.dropped_bytes, 0);
        assert_eq!(state.incoming.payload_bytes, 100);
    }

    #[test]
    fn test_datagram_received_with_drop() {
        let mut state = DatagramState::default();
        let window = Some(1024);

        // Fill the buffer with a datagram
        let datagram1 = Datagram {
            data: Bytes::from(vec![0u8; 800]),
        };
        let result1 = state.received(datagram1, &window).unwrap();
        assert!(result1.was_empty);
        assert_eq!(result1.dropped_count, 0);

        // Add another datagram that would exceed the window
        let datagram2 = Datagram {
            data: Bytes::from(vec![1u8; 500]),
        };
        let result2 = state.received(datagram2, &window).unwrap();

        // Should have dropped the first datagram to make room
        assert!(!result2.was_empty);
        assert_eq!(result2.dropped_count, 1);
        assert_eq!(result2.dropped_bytes, 800);

        // Buffer should now contain only the second datagram
        assert_eq!(state.incoming.payload_bytes, 500);
        assert_eq!(state.incoming.queue.len(), 1);
    }

    #[test]
    fn test_datagram_received_multiple_drops() {
        let mut state = DatagramState::default();
        // Room for exactly five 200-byte datagrams with their fixed overhead.
        let window = Some(1000 + 5 * size_of::<Datagram>());

        // Fill with multiple small datagrams
        for i in 0..5 {
            let datagram = Datagram {
                data: Bytes::from(vec![i as u8; 200]),
            };
            state.received(datagram, &window).unwrap();
        }

        // Buffer should have 1000 bytes (5 x 200)
        assert_eq!(state.incoming.payload_bytes, 1000);
        assert_eq!(state.incoming.queue.len(), 5);

        // Add a large datagram that requires dropping multiple old ones
        let large_datagram = Datagram {
            data: Bytes::from(vec![99u8; 900]),
        };
        let result = state.received(large_datagram, &window).unwrap();

        // Should have dropped 5 datagrams (1000 bytes) to fit 900 bytes
        assert_eq!(result.dropped_count, 5);
        assert_eq!(result.dropped_bytes, 1000);
        assert_eq!(state.incoming.payload_bytes, 900);
        assert_eq!(state.incoming.queue.len(), 1);
    }

    #[test]
    fn test_datagram_received_disabled() {
        let mut state = DatagramState::default();
        let window = None; // Datagrams disabled

        let datagram = Datagram {
            data: Bytes::from(vec![0u8; 100]),
        };
        let result = state.received(datagram, &window);

        assert!(result.is_err());
    }

    /// RUSTSEC-2026-0342: a peer sends a flood of zero-length DATAGRAM frames (DATAGRAM
    /// frames are not flow controlled). Each queued datagram must consume receive buffer
    /// space, so the incoming queue stays bounded by the window.
    #[test]
    fn peer_zero_length_datagram_flood_is_bounded() {
        const WINDOW: usize = 1024;
        let mut state = DatagramState::default();
        let window = Some(WINDOW);
        for _ in 0..100_000 {
            state
                .received(Datagram { data: Bytes::new() }, &window)
                .unwrap();
        }
        // Every queued datagram costs at least its fixed in-memory size.
        let bound = WINDOW / size_of::<Datagram>();
        assert!(
            state.incoming.queue.len() <= bound,
            "{} empty datagrams queued in a {WINDOW}-byte receive buffer (bound {bound})",
            state.incoming.queue.len()
        );
    }

    /// RUSTSEC-2026-0342 (send side): empty outgoing datagrams also consume send buffer
    /// space.
    #[test]
    fn make_space_for_accounts_for_empty_datagram_metadata() {
        let mut state = DatagramState::default();
        for _ in 0..2 {
            state.outgoing.push_back(Datagram { data: Bytes::new() });
        }
        let window = 2 * size_of::<Datagram>();

        assert!(!state.has_send_buffer_space(0, window));
        state.make_space_for(0, window);
        assert_eq!(state.outgoing.queue.len(), 1);
        assert!(state.has_send_buffer_space(0, window));
        state.outgoing.push_back(Datagram { data: Bytes::new() });
        assert_eq!(state.outgoing.memory_used(), window);
    }

    #[test]
    fn make_space_for_accounts_for_new_datagram() {
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 7]),
        });
        state.outgoing.push_back(Datagram {
            data: Bytes::from_static(&[0; 2]),
        });
        state.make_space_for(4, 10 + 2 * size_of::<Datagram>());

        assert_eq!(state.outgoing.queue.len(), 1);
        assert_eq!(state.outgoing.queue[0].data.len(), 2);
        assert_eq!(state.outgoing.payload_bytes, 2);
    }

    #[test]
    fn make_space_for_handles_overflowing_capacity_check() {
        let mut state = DatagramState::default();
        state.outgoing.queue.push_back(Datagram {
            data: Bytes::from_static(&[0]),
        });
        state.outgoing.payload_bytes = usize::MAX - 1;

        state.make_space_for(2, usize::MAX);

        assert!(state.outgoing.is_empty());
        assert_eq!(state.outgoing.payload_bytes, usize::MAX - 2);
    }

    #[test]
    fn send_buffer_space_handles_metadata_overflow() {
        assert!(!DatagramState::default().has_send_buffer_space(usize::MAX, usize::MAX));
    }

    /// RUSTSEC-2026-0343 guard: sustained eviction must keep `payload_bytes` equal to the
    /// queued payload (no double subtraction when the oldest datagram is dropped).
    #[test]
    fn sustained_eviction_keeps_send_accounting_in_sync() {
        const SEND_BUFFER: usize = 4096;
        let mut state = DatagramState::default();
        for i in 0..10_000usize {
            let len = i % 300;
            state.make_space_for(len, SEND_BUFFER);
            state.outgoing.push_back(Datagram {
                data: Bytes::from(vec![0u8; len]),
            });
            let queued: usize = state.outgoing.queue.iter().map(|d| d.data.len()).sum();
            assert_eq!(state.outgoing.payload_bytes, queued);
            assert!(state.outgoing.memory_used() <= SEND_BUFFER);
        }
    }

    #[test]
    fn test_datagram_received_oversized() {
        let mut state = DatagramState::default();
        let window = Some(100);

        // Datagram larger than window
        let datagram = Datagram {
            data: Bytes::from(vec![0u8; 200]),
        };
        let result = state.received(datagram, &window);

        assert!(result.is_err());
    }

    /// A datagram whose payload is exactly the usable limit still fits and must
    /// survive `drop_oversized` (`<=`, not `<`); dropping a larger one must
    /// clear the send block and report that the caller should emit
    /// `DatagramsUnblocked`, and must keep the payload accounting in sync.
    #[test]
    fn drop_oversized_keeps_limit_sized_datagram_and_unblocks() {
        let mut state = DatagramState::default();
        let max_payload = 1200usize;

        // Exactly at the limit — must be kept.
        state.outgoing.push_back(Datagram {
            data: Bytes::from(vec![0u8; max_payload]),
        });
        // One byte over the limit — must be dropped.
        state.outgoing.push_back(Datagram {
            data: Bytes::from(vec![0u8; max_payload + 1]),
        });
        // A prior send was blocked for lack of space.
        state.send_blocked = true;

        let newly_unblocked = state.drop_oversized(max_payload);

        // The exactly-limit-sized datagram survives (`<=`, not `<`).
        assert_eq!(
            state.outgoing.queue.len(),
            1,
            "drop_oversized must keep the datagram whose payload equals the limit"
        );
        assert_eq!(
            state.outgoing.queue.front().unwrap().data.len(),
            max_payload
        );
        // payload accounting stays in sync with the queue.
        assert_eq!(state.outgoing.payload_bytes, max_payload);
        // Dropping the oversized datagram freed space, so the block is cleared
        // and the caller is told to emit DatagramsUnblocked.
        assert!(
            !state.send_blocked,
            "drop_oversized must clear send_blocked after it frees space"
        );
        assert!(
            newly_unblocked,
            "drop_oversized must report that a blocked send is now unblocked"
        );
    }

    /// drop_oversized must NOT signal an unblock when it drops nothing, nor when
    /// nothing was blocked — otherwise the caller would emit a spurious
    /// DatagramsUnblocked.
    #[test]
    fn drop_oversized_does_not_signal_unblock_without_a_drop() {
        // Nothing oversized: no drop, no signal, flag untouched.
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from(vec![0u8; 1000]),
        });
        state.send_blocked = true;
        assert!(
            !state.drop_oversized(1200),
            "no drop means no unblock signal"
        );
        assert_eq!(state.outgoing.queue.len(), 1);
        assert!(
            state.send_blocked,
            "the flag must be left set when nothing is dropped"
        );

        // Oversized dropped but no prior block: no signal.
        let mut state = DatagramState::default();
        state.outgoing.push_back(Datagram {
            data: Bytes::from(vec![0u8; 1500]),
        });
        assert!(
            !state.drop_oversized(1200),
            "dropping without a prior block must not signal an unblock"
        );
        assert!(state.outgoing.is_empty());
    }
}
