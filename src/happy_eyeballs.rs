// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! RFC 8305 Happy Eyeballs v2 implementation for parallel IPv4/IPv6 connection racing.
//!
//! This module implements the Happy Eyeballs algorithm (RFC 8305) which races connection
//! attempts across multiple addresses with staggered timing. This is used to provide fast
//! and reliable connectivity in dual-stack environments where either IPv4 or IPv6 might be
//! faster or more reliable.
//!
//! # Algorithm Overview
//!
//! Per RFC 8305 Section 5:
//! 1. Addresses are sorted to interleave address families (starting with the preferred family)
//! 2. The first connection attempt starts immediately
//! 3. After a configurable delay (default 250ms), if no connection has succeeded, the next
//!    attempt starts in parallel
//! 4. On any failure, the next attempt starts immediately without waiting for the delay
//! 5. The first successful connection wins; all other pending attempts are aborted
//!    before the winner is returned (see `race_connect` for the exact guarantee)
//!
//! # Example
//!
//! ```rust,ignore
//! use ant_quic::happy_eyeballs::{race_connect, HappyEyeballsConfig};
//! use std::net::SocketAddr;
//!
//! let addresses: Vec<SocketAddr> = vec![
//!     "192.168.1.1:9000".parse().unwrap(),
//!     "[::1]:9000".parse().unwrap(),
//! ];
//!
//! let config = HappyEyeballsConfig::default();
//! let (connection, addr) = race_connect(&addresses, &config, |addr| async move {
//!     // Your connection logic here
//!     Ok::<_, String>("connected")
//! }).await?;
//! ```

use std::future::Future;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

use futures_util::FutureExt;
use thiserror::Error;
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

/// Which address family to prefer when interleaving connection attempts.
///
/// RFC 8305 recommends preferring IPv6 by default to encourage IPv6 adoption,
/// but applications may override this based on local network conditions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressFamily {
    /// Prefer IPv6 addresses first (RFC 8305 default)
    IPv6Preferred,
    /// Prefer IPv4 addresses first
    IPv4Preferred,
}

/// Configuration for the RFC 8305 Happy Eyeballs algorithm.
///
/// Controls timing and address family preferences for parallel connection racing.
///
/// # Defaults
///
/// - `connection_attempt_delay`: 250ms (RFC 8305 Section 5 recommendation)
/// - `first_address_family_count`: 1 (start with one address from the preferred family)
/// - `preferred_family`: [`AddressFamily::IPv6Preferred`]
#[derive(Debug, Clone)]
pub struct HappyEyeballsConfig {
    /// Delay before starting the next connection attempt (RFC 8305 recommends 250ms).
    ///
    /// If a connection attempt fails before this delay elapses, the next attempt
    /// starts immediately without waiting.
    pub connection_attempt_delay: Duration,

    /// Maximum number of addresses from the preferred family to try first.
    ///
    /// After this many addresses from the preferred family, addresses are interleaved
    /// between families.
    pub first_address_family_count: usize,

    /// Which address family to prefer when ordering connection attempts.
    pub preferred_family: AddressFamily,
}

impl Default for HappyEyeballsConfig {
    fn default() -> Self {
        Self {
            connection_attempt_delay: Duration::from_millis(250),
            first_address_family_count: 1,
            preferred_family: AddressFamily::IPv6Preferred,
        }
    }
}

/// Errors that can occur during the Happy Eyeballs connection racing algorithm.
#[derive(Debug, Error)]
pub enum HappyEyeballsError {
    /// No addresses were provided to attempt connections to.
    #[error("no addresses provided for connection attempts")]
    NoAddresses,

    /// All connection attempts failed.
    ///
    /// Contains the list of addresses attempted and their corresponding error messages.
    #[error(
        "all {count} connection attempts failed: {summary}",
        count = errors.len(),
        summary = format_error_summary(errors)
    )]
    AllAttemptsFailed {
        /// Each failed attempt's address and error description.
        errors: Vec<(SocketAddr, String)>,
    },

    /// The connection racing timed out before any attempt succeeded.
    #[error("connection racing timed out")]
    Timeout,
}

/// Formats a summary of connection errors for display.
fn format_error_summary(errors: &[(SocketAddr, String)]) -> String {
    errors
        .iter()
        .map(|(addr, err)| format!("{addr}: {err}"))
        .collect::<Vec<_>>()
        .join("; ")
}

/// Sort addresses according to RFC 8305 Section 4 address interleaving.
///
/// The sorted order:
/// 1. Start with `config.first_address_family_count` addresses from the preferred family
/// 2. Then alternate between the non-preferred family and the preferred family
/// 3. Original order within each family is preserved
///
/// # Arguments
///
/// * `addresses` - The list of socket addresses to sort
/// * `config` - Configuration controlling preferred family and first-family count
///
/// # Returns
///
/// A new `Vec<SocketAddr>` with addresses interleaved per the algorithm.
///
/// # Example
///
/// ```rust,ignore
/// use ant_quic::happy_eyeballs::{sort_addresses, HappyEyeballsConfig, AddressFamily};
///
/// let addrs: Vec<SocketAddr> = vec![
///     "192.168.1.1:80".parse().unwrap(),  // v4_a
///     "[::1]:80".parse().unwrap(),         // v6_a
///     "192.168.1.2:80".parse().unwrap(),   // v4_b
///     "[::2]:80".parse().unwrap(),         // v6_b
///     "192.168.1.3:80".parse().unwrap(),   // v4_c
/// ];
///
/// let config = HappyEyeballsConfig {
///     preferred_family: AddressFamily::IPv6Preferred,
///     first_address_family_count: 1,
///     ..Default::default()
/// };
///
/// let sorted = sort_addresses(&addrs, &config);
/// // Result: [v6_a, v4_a, v6_b, v4_b, v4_c]
/// ```
pub fn sort_addresses(addresses: &[SocketAddr], config: &HappyEyeballsConfig) -> Vec<SocketAddr> {
    if addresses.is_empty() {
        return Vec::new();
    }

    let is_preferred = |addr: &SocketAddr| -> bool {
        match config.preferred_family {
            AddressFamily::IPv6Preferred => addr.is_ipv6(),
            AddressFamily::IPv4Preferred => addr.is_ipv4(),
        }
    };

    // Separate addresses into preferred and non-preferred families, preserving order
    let preferred: Vec<SocketAddr> = addresses.iter().copied().filter(is_preferred).collect();
    let non_preferred: Vec<SocketAddr> = addresses
        .iter()
        .copied()
        .filter(|a| !is_preferred(a))
        .collect();

    let mut result = Vec::with_capacity(addresses.len());

    // Phase 1: Add first_address_family_count addresses from preferred family
    let first_count = config.first_address_family_count.min(preferred.len());
    result.extend_from_slice(&preferred[..first_count]);

    // Phase 2: Interleave remaining addresses, starting with non-preferred
    let mut pref_iter = preferred[first_count..].iter();
    let mut non_pref_iter = non_preferred.iter();

    loop {
        let non_pref_next = non_pref_iter.next();
        let pref_next = pref_iter.next();

        match (non_pref_next, pref_next) {
            (Some(np), Some(p)) => {
                result.push(*np);
                result.push(*p);
            }
            (Some(np), None) => {
                result.push(*np);
            }
            (None, Some(p)) => {
                result.push(*p);
            }
            (None, None) => break,
        }
    }

    result
}

/// What one spawned attempt returns: the address it dialled and its result.
type AttemptOutcome<C> = (SocketAddr, Result<C, String>);

/// Longest time the winner waits for the aborted losers to end.
///
/// A loser that yields ends at once when it is aborted, so the wait is
/// normally microseconds. A loser in a non-yielding section (blocking code)
/// cannot be stopped from outside; this bound keeps it from holding a ready
/// winner (#294).
const LOSER_SHUTDOWN_GRACE: Duration = Duration::from_millis(50);

/// Spawn a single connection attempt into the race's [`JoinSet`].
///
/// The set owns the task: dropping or shutting down the set stops the
/// attempt. A panic in the attempt future becomes a failed attempt, so the
/// coordinator always gets one outcome per attempt.
fn spawn_attempt<F, Fut, C, E>(
    attempts: &mut JoinSet<AttemptOutcome<C>>,
    addr: SocketAddr,
    attempt_num: usize,
    connect_fn: &F,
) where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<C, E>> + Send + 'static,
    C: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    debug!(addr = %addr, attempt = attempt_num, "Starting connection attempt");
    let fut = connect_fn(addr);
    attempts.spawn(async move {
        let outcome = match AssertUnwindSafe(fut).catch_unwind().await {
            Ok(Ok(conn)) => Ok(conn),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("connection attempt panicked".to_string()),
        };
        (addr, outcome)
    });
}

/// Race multiple connection attempts using the RFC 8305 Happy Eyeballs algorithm.
///
/// Attempts connections to the given addresses with staggered timing, returning the
/// first successful connection. Failed attempts trigger the next attempt immediately;
/// otherwise, the next attempt starts after `config.connection_attempt_delay`.
///
/// The function is generic over the connection function, making it testable without
/// requiring a real QUIC endpoint.
///
/// # Arguments
///
/// * `addresses` - List of socket addresses to try connecting to
/// * `config` - Happy Eyeballs configuration (timing, address family preferences)
/// * `connect_fn` - A function that takes a `SocketAddr` and returns a future resolving
///   to either a successful connection or an error
///
/// # Returns
///
/// A tuple of the successful connection and the address it connected to, or
/// a [`HappyEyeballsError`] if all attempts failed.
///
/// # Errors
///
/// Returns [`HappyEyeballsError::NoAddresses`] if the address list is empty.
/// Returns [`HappyEyeballsError::AllAttemptsFailed`] if every attempt fails.
///
/// # Algorithm
///
/// Per RFC 8305 Section 5:
/// 1. Sort addresses using [`sort_addresses`]
/// 2. Start the first connection attempt immediately
/// 3. Wait for `connection_attempt_delay` or for the attempt to complete
/// 4. If the attempt succeeded, return it (cancel remaining attempts)
/// 5. If the attempt failed, start the next attempt immediately
/// 6. If the delay elapsed, start the next attempt in parallel
/// 7. Repeat until one succeeds or all fail
///
/// # Cancellation
///
/// One [`JoinSet`] owns every spawned attempt (#294). Tokio cancellation is
/// cooperative: an aborted attempt ends at its next poll (its next `.await`).
/// - When an attempt wins, every other attempt is aborted before the winner
///   is returned. The race then waits for the aborted attempts to end, for at
///   most 50 ms. An attempt that yields (every normal async dial) has ended,
///   and a loser that also connected has been dropped, when the caller gets
///   the winner. An attempt in a non-yielding section (blocking code) cannot
///   be stopped from outside; it stays aborted and ends at its next poll,
///   after the winner is returned. It cannot delay the winner by more than
///   the bound.
/// - When the caller drops the returned future (for example an outer
///   timeout), the set is dropped and every attempt is aborted. Each attempt
///   ends at its next poll.
/// - An attempt that panics counts as a failed attempt; it does not stall the
///   race.
pub async fn race_connect<F, Fut, C, E>(
    addresses: &[SocketAddr],
    config: &HappyEyeballsConfig,
    connect_fn: F,
) -> Result<(C, SocketAddr), HappyEyeballsError>
where
    F: Fn(SocketAddr) -> Fut,
    Fut: Future<Output = Result<C, E>> + Send + 'static,
    C: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    if addresses.is_empty() {
        return Err(HappyEyeballsError::NoAddresses);
    }

    let sorted = sort_addresses(addresses, config);
    debug!(
        addresses = ?sorted,
        delay_ms = config.connection_attempt_delay.as_millis(),
        "Starting Happy Eyeballs connection racing"
    );

    let mut attempts: JoinSet<AttemptOutcome<C>> = JoinSet::new();
    let mut errors: Vec<(SocketAddr, String)> = Vec::new();
    let mut pending = sorted.iter().copied().enumerate().peekable();

    // Spawn the first attempt immediately
    if let Some((index, addr)) = pending.next() {
        spawn_attempt(&mut attempts, addr, index + 1, &connect_fn);
    }

    // Main event loop
    loop {
        let joined = if pending.peek().is_some() {
            // More addresses to try: race the next result against the delay timer.
            tokio::select! {
                biased;

                // Prefer checking results over starting new attempts
                joined = attempts.join_next() => joined,

                // Timer fires: start next attempt in parallel
                () = tokio::time::sleep(config.connection_attempt_delay) => {
                    if let Some((index, addr)) = pending.next() {
                        debug!(
                            addr = %addr,
                            attempt = index + 1,
                            "Starting parallel attempt after delay"
                        );
                        spawn_attempt(&mut attempts, addr, index + 1, &connect_fn);
                    }
                    continue;
                }
            }
        } else {
            // No more addresses to try - wait for the attempts in flight
            attempts.join_next().await
        };

        match joined {
            Some(Ok((addr, Ok(conn)))) => {
                info!(addr = %addr, "Happy Eyeballs: connection succeeded");
                // Abort every losing attempt, then give the aborted attempts a
                // bounded time to end. Results that arrive here (a loser that
                // also connected) are dropped.
                attempts.abort_all();
                let drained = tokio::time::timeout(LOSER_SHUTDOWN_GRACE, async {
                    while attempts.join_next().await.is_some() {}
                })
                .await;
                if drained.is_err() {
                    // These attempts are aborted and end at their next poll.
                    // Dropping the set at return detaches them.
                    debug!(
                        remaining = attempts.len(),
                        "Happy Eyeballs: aborted attempts did not end within the grace period"
                    );
                }
                return Ok((conn, addr));
            }
            Some(Ok((addr, Err(err)))) => {
                warn!(addr = %addr, error = %err, "Connection attempt failed");
                errors.push((addr, err));
            }
            Some(Err(join_error)) => {
                // Panics are caught inside the attempt, so only an external
                // cancellation (runtime shutdown) reaches this arm.
                warn!(error = %join_error, "Connection attempt ended without a result");
            }
            None => {
                // No attempt in flight.
                if pending.peek().is_none() {
                    break;
                }
            }
        }

        // An attempt ended without a winner: start the next attempt
        // immediately (RFC 8305 Section 5).
        if let Some((index, addr)) = pending.next() {
            spawn_attempt(&mut attempts, addr, index + 1, &connect_fn);
        }
    }

    Err(HappyEyeballsError::AllAttemptsFailed { errors })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DropWitness {
        count: Arc<AtomicUsize>,
        dropped: Arc<tokio::sync::Notify>,
    }

    impl Drop for DropWitness {
        fn drop(&mut self) {
            self.count.fetch_add(1, Ordering::SeqCst);
            self.dropped.notify_one();
        }
    }

    /// Parse a v4 socket address from a string.
    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Parse a v6 socket address from a string.
    fn v6(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    // ========================================================================
    // sort_addresses tests
    // ========================================================================

    #[test]
    fn test_sort_ipv6_preferred() {
        let addrs = vec![
            v4("192.168.1.1:80"), // v4_a
            v6("[::1]:80"),       // v6_a
            v4("192.168.1.2:80"), // v4_b
            v6("[::2]:80"),       // v6_b
            v4("192.168.1.3:80"), // v4_c
        ];

        let config = HappyEyeballsConfig {
            preferred_family: AddressFamily::IPv6Preferred,
            first_address_family_count: 1,
            ..Default::default()
        };

        let sorted = sort_addresses(&addrs, &config);

        // Expected: [v6_a, v4_a, v6_b, v4_b, v4_c]
        assert_eq!(sorted.len(), 5);
        assert_eq!(sorted[0], v6("[::1]:80")); // first preferred
        assert_eq!(sorted[1], v4("192.168.1.1:80")); // first non-preferred
        assert_eq!(sorted[2], v6("[::2]:80")); // second preferred
        assert_eq!(sorted[3], v4("192.168.1.2:80")); // second non-preferred
        assert_eq!(sorted[4], v4("192.168.1.3:80")); // remaining non-preferred
    }

    #[test]
    fn test_sort_ipv4_preferred() {
        let addrs = vec![
            v6("[::1]:80"),
            v4("10.0.0.1:80"),
            v6("[::2]:80"),
            v4("10.0.0.2:80"),
        ];

        let config = HappyEyeballsConfig {
            preferred_family: AddressFamily::IPv4Preferred,
            first_address_family_count: 1,
            ..Default::default()
        };

        let sorted = sort_addresses(&addrs, &config);

        // Expected: [v4_a, v6_a, v4_b, v6_b]
        assert_eq!(sorted.len(), 4);
        assert_eq!(sorted[0], v4("10.0.0.1:80")); // first preferred (v4)
        assert_eq!(sorted[1], v6("[::1]:80")); // first non-preferred (v6)
        assert_eq!(sorted[2], v4("10.0.0.2:80")); // second preferred (v4)
        assert_eq!(sorted[3], v6("[::2]:80")); // second non-preferred (v6)
    }

    #[test]
    fn test_sort_single_family() {
        // All IPv4 - should preserve original order
        let addrs = vec![v4("10.0.0.1:80"), v4("10.0.0.2:80"), v4("10.0.0.3:80")];

        let config = HappyEyeballsConfig::default(); // IPv6 preferred

        let sorted = sort_addresses(&addrs, &config);

        // No preferred addresses exist, so all go into non-preferred
        // Phase 1 adds 0 preferred (none exist), Phase 2 interleaves the rest
        assert_eq!(sorted.len(), 3);
        assert_eq!(sorted[0], v4("10.0.0.1:80"));
        assert_eq!(sorted[1], v4("10.0.0.2:80"));
        assert_eq!(sorted[2], v4("10.0.0.3:80"));
    }

    #[test]
    fn test_sort_empty() {
        let addrs: Vec<SocketAddr> = vec![];
        let config = HappyEyeballsConfig::default();
        let sorted = sort_addresses(&addrs, &config);
        assert!(sorted.is_empty());
    }

    #[test]
    fn test_sort_first_count_two() {
        let addrs = vec![
            v4("10.0.0.1:80"),
            v6("[::1]:80"),
            v4("10.0.0.2:80"),
            v6("[::2]:80"),
            v6("[::3]:80"),
        ];

        let config = HappyEyeballsConfig {
            preferred_family: AddressFamily::IPv6Preferred,
            first_address_family_count: 2,
            ..Default::default()
        };

        let sorted = sort_addresses(&addrs, &config);

        // Phase 1: [v6_a, v6_b] (first 2 preferred)
        // Phase 2: interleave remaining - non-preferred [v4_a, v4_b] with preferred [v6_c]
        // => [v4_a, v6_c, v4_b]
        assert_eq!(sorted.len(), 5);
        assert_eq!(sorted[0], v6("[::1]:80"));
        assert_eq!(sorted[1], v6("[::2]:80"));
        assert_eq!(sorted[2], v4("10.0.0.1:80"));
        assert_eq!(sorted[3], v6("[::3]:80"));
        assert_eq!(sorted[4], v4("10.0.0.2:80"));
    }

    // ========================================================================
    // race_connect tests
    // ========================================================================

    #[tokio::test]
    async fn test_race_single_address_success() {
        let addrs = vec![v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig::default();

        let result = race_connect(&addrs, &config, |addr| async move {
            Ok::<_, String>(format!("connected to {addr}"))
        })
        .await;

        let (conn, addr) = result.unwrap();
        assert_eq!(conn, "connected to 10.0.0.1:80");
        assert_eq!(addr, v4("10.0.0.1:80"));
    }

    #[tokio::test]
    async fn test_race_first_succeeds_fast() {
        // First attempt succeeds before delay, second should never start
        let attempt_count = Arc::new(AtomicUsize::new(0));
        let attempt_count_clone = Arc::clone(&attempt_count);

        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(500),
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, move |addr| {
            let count = Arc::clone(&attempt_count_clone);
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                // Succeed immediately
                Ok::<_, String>(format!("connected to {addr}"))
            }
        })
        .await;

        let (conn, addr) = result.unwrap();
        assert_eq!(conn, "connected to [::1]:80");
        assert_eq!(addr, v6("[::1]:80"));

        // Only one attempt should have been made (the first one succeeded immediately)
        assert_eq!(attempt_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_race_first_fails_second_succeeds() {
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_secs(10), // Long delay, won't fire
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, |addr| async move {
            if addr == v6("[::1]:80") {
                Err("connection refused".to_string())
            } else {
                Ok(format!("connected to {addr}"))
            }
        })
        .await;

        let (conn, addr) = result.unwrap();
        assert_eq!(conn, "connected to 10.0.0.1:80");
        assert_eq!(addr, v4("10.0.0.1:80"));
    }

    #[tokio::test]
    async fn test_race_slow_first_fast_second() {
        // First attempt is slow (> delay), second attempt succeeds quickly
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(50),
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, |addr| async move {
            if addr == v6("[::1]:80") {
                // Slow: takes 2 seconds
                tokio::time::sleep(Duration::from_secs(2)).await;
                Ok::<_, String>(format!("connected to {addr}"))
            } else {
                // Fast: succeeds quickly
                tokio::time::sleep(Duration::from_millis(10)).await;
                Ok(format!("connected to {addr}"))
            }
        })
        .await;

        let (conn, addr) = result.unwrap();
        // The fast second attempt should win
        assert_eq!(conn, "connected to 10.0.0.1:80");
        assert_eq!(addr, v4("10.0.0.1:80"));
    }

    #[tokio::test]
    async fn test_race_all_fail() {
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80"), v4("10.0.0.2:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(10),
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, |addr| async move {
            Err::<String, _>(format!("failed to connect to {addr}"))
        })
        .await;

        match result {
            Err(HappyEyeballsError::AllAttemptsFailed { errors }) => {
                assert_eq!(errors.len(), 3, "Expected 3 errors, got {}", errors.len());
                // All three addresses should appear in the errors
                let addrs_in_errors: Vec<SocketAddr> =
                    errors.iter().map(|(addr, _)| *addr).collect();
                assert!(addrs_in_errors.contains(&v6("[::1]:80")));
                assert!(addrs_in_errors.contains(&v4("10.0.0.1:80")));
                assert!(addrs_in_errors.contains(&v4("10.0.0.2:80")));
            }
            other => panic!("Expected AllAttemptsFailed, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_race_empty_addresses() {
        let addrs: Vec<SocketAddr> = vec![];
        let config = HappyEyeballsConfig::default();

        let result = race_connect(&addrs, &config, |addr| async move {
            Ok::<_, String>(format!("connected to {addr}"))
        })
        .await;

        match result {
            Err(HappyEyeballsError::NoAddresses) => {} // Expected
            other => panic!("Expected NoAddresses, got: {other:?}"),
        }
    }

    #[test]
    fn test_default_config() {
        let config = HappyEyeballsConfig::default();
        assert_eq!(config.connection_attempt_delay, Duration::from_millis(250));
        assert_eq!(config.preferred_family, AddressFamily::IPv6Preferred);
        assert_eq!(config.first_address_family_count, 1);
    }

    #[tokio::test]
    async fn test_race_immediate_failure_triggers_next() {
        // Verify that an immediate failure starts the next attempt without waiting
        // for the delay timer
        let attempt_times = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let attempt_times_clone = Arc::clone(&attempt_times);

        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            // Very long delay - if the second attempt starts quickly despite this,
            // it means the failure triggered it immediately
            connection_attempt_delay: Duration::from_secs(60),
            ..Default::default()
        };

        let start = tokio::time::Instant::now();
        let result = race_connect(&addrs, &config, move |addr| {
            let times = Arc::clone(&attempt_times_clone);
            let start_time = start;
            async move {
                {
                    let mut t = times.lock().await;
                    t.push((addr, start_time.elapsed()));
                }
                if addr == v6("[::1]:80") {
                    // Fail immediately
                    Err("connection refused".to_string())
                } else {
                    // Second attempt succeeds
                    Ok(format!("connected to {addr}"))
                }
            }
        })
        .await;

        let (conn, _addr) = result.unwrap();
        assert_eq!(conn, "connected to 10.0.0.1:80");

        // Check that the second attempt started much sooner than the 60s delay
        let times = attempt_times.lock().await;
        assert_eq!(times.len(), 2);
        // The second attempt should start within a few ms, certainly not 60 seconds
        let second_start = times[1].1;
        assert!(
            second_start < Duration::from_millis(500),
            "Second attempt took too long to start: {second_start:?} (expected < 500ms, \
             indicating failure-triggered immediate start)"
        );
    }

    #[tokio::test]
    async fn test_race_cancels_remaining_on_success() {
        // Verify that remaining tasks are aborted when one succeeds
        let completed = Arc::new(AtomicUsize::new(0));
        let completed_clone = Arc::clone(&completed);

        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80"), v4("10.0.0.2:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(10),
            ..Default::default()
        };

        let result = race_connect(&addrs, &config, move |addr| {
            let done = Arc::clone(&completed_clone);
            async move {
                if addr == v4("10.0.0.1:80") {
                    // This one succeeds after a short delay
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    done.fetch_add(1, Ordering::SeqCst);
                    Ok::<_, String>(format!("connected to {addr}"))
                } else {
                    // Others take very long
                    tokio::time::sleep(Duration::from_secs(10)).await;
                    done.fetch_add(1, Ordering::SeqCst);
                    Ok(format!("connected to {addr}"))
                }
            }
        })
        .await;

        let (_conn, addr) = result.unwrap();
        assert_eq!(addr, v4("10.0.0.1:80"));

        // Give a moment for abort to propagate
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Only one task should have completed (the fast successful one).
        // The others should have been aborted.
        assert_eq!(completed.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn dropping_race_cancels_entered_attempt() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let drop_event = Arc::new(tokio::sync::Notify::new());
        let entered_for_attempt = Arc::clone(&entered);
        let dropped_for_attempt = Arc::clone(&dropped);
        let drop_event_for_attempt = Arc::clone(&drop_event);
        let addrs = vec![v6("[::1]:80")];

        let race = tokio::spawn(async move {
            race_connect(&addrs, &HappyEyeballsConfig::default(), move |_| {
                let entered = Arc::clone(&entered_for_attempt);
                let dropped = Arc::clone(&dropped_for_attempt);
                let drop_event = Arc::clone(&drop_event_for_attempt);
                async move {
                    let _witness = DropWitness {
                        count: dropped,
                        dropped: drop_event,
                    };
                    entered.notify_one();
                    std::future::pending::<Result<String, String>>().await
                }
            })
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), entered.notified())
            .await
            .unwrap();
        race.abort();
        let _ = race.await;

        tokio::time::timeout(Duration::from_secs(1), drop_event.notified())
            .await
            .unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn timing_out_race_cancels_entered_attempt() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let dropped = Arc::new(AtomicUsize::new(0));
        let drop_event = Arc::new(tokio::sync::Notify::new());
        let entered_for_attempt = Arc::clone(&entered);
        let dropped_for_attempt = Arc::clone(&dropped);
        let drop_event_for_attempt = Arc::clone(&drop_event);
        let addrs = vec![v6("[::1]:80")];

        let mut race = Box::pin(async {
            race_connect(&addrs, &HappyEyeballsConfig::default(), move |_| {
                let entered = Arc::clone(&entered_for_attempt);
                let dropped = Arc::clone(&dropped_for_attempt);
                let drop_event = Arc::clone(&drop_event_for_attempt);
                async move {
                    let _witness = DropWitness {
                        count: dropped,
                        dropped: drop_event,
                    };
                    entered.notify_one();
                    std::future::pending::<Result<String, String>>().await
                }
            })
            .await
        });

        tokio::time::timeout(Duration::from_secs(1), async {
            tokio::select! {
                () = entered.notified() => {}
                result = &mut race => panic!("race ended before attempt entered: {result:?}"),
            }
        })
        .await
        .unwrap();
        let result = tokio::time::timeout(Duration::from_millis(50), &mut race).await;

        assert!(result.is_err());
        drop(race);
        tokio::time::timeout(Duration::from_secs(1), drop_event.notified())
            .await
            .unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    /// #294: when a winner is found, a losing attempt that yields must
    /// already be stopped when `race_connect` returns. An abort that is only
    /// scheduled leaves the losing dial running (and holding its resources)
    /// after the caller has the winner. The winner itself must not be dropped.
    /// (A loser that does not yield is covered by
    /// `blocking_loser_does_not_hold_ready_winner`.)
    ///
    /// Deterministic: explicit gates on the current-thread runtime. The
    /// winning attempt waits until the losing dial has entered, and the check
    /// runs with no yield after the race returns, so a loser that is only
    /// scheduled for cancellation is still alive at the check.
    #[tokio::test]
    async fn winner_return_stops_losing_attempts_before_handoff() {
        let loser_entered = Arc::new(tokio::sync::Notify::new());
        let loser_dropped = Arc::new(AtomicUsize::new(0));
        let winner_dropped = Arc::new(AtomicUsize::new(0));
        let loser_entered_for_attempt = Arc::clone(&loser_entered);
        let loser_dropped_for_attempt = Arc::clone(&loser_dropped);
        let winner_dropped_for_attempt = Arc::clone(&winner_dropped);
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(10),
            ..Default::default()
        };

        let race = race_connect(&addrs, &config, move |addr| {
            let loser_entered = Arc::clone(&loser_entered_for_attempt);
            let loser_dropped = Arc::clone(&loser_dropped_for_attempt);
            let winner_dropped = Arc::clone(&winner_dropped_for_attempt);
            async move {
                if addr == v6("[::1]:80") {
                    let _witness = DropWitness {
                        count: loser_dropped,
                        dropped: Arc::new(tokio::sync::Notify::new()),
                    };
                    loser_entered.notify_one();
                    std::future::pending::<Result<DropWitness, String>>().await
                } else {
                    // Gate: win only after the losing dial is in flight.
                    loser_entered.notified().await;
                    Ok(DropWitness {
                        count: winner_dropped,
                        dropped: Arc::new(tokio::sync::Notify::new()),
                    })
                }
            }
        });
        let (winner, addr) = tokio::time::timeout(Duration::from_secs(5), race)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(addr, v4("10.0.0.1:80"));
        assert_eq!(
            loser_dropped.load(Ordering::SeqCst),
            1,
            "the losing attempt must be stopped before the winner is returned"
        );
        assert_eq!(
            winner_dropped.load(Ordering::SeqCst),
            0,
            "stopping the losers must not drop the winning connection"
        );
        drop(winner);
        assert_eq!(winner_dropped.load(Ordering::SeqCst), 1);
    }

    /// #294: an attempt task that panics must count as a failed attempt.
    /// Before the fix the coordinator kept its own channel sender, so it
    /// waited for a result that never came and the race hung until an outer
    /// timeout cancelled it.
    ///
    /// Deterministic in outcome: the race uses no timer (one address), so a
    /// correct race ends on the attempt's first poll and a broken race never
    /// ends. The guard only bounds how long the failure takes to report.
    #[tokio::test]
    async fn panicking_attempt_is_a_failed_attempt_not_a_hang() {
        let addrs = vec![v6("[::1]:80")];

        let outcome = tokio::time::timeout(
            Duration::from_secs(5),
            race_connect(&addrs, &HappyEyeballsConfig::default(), |addr| async move {
                if addr.is_ipv6() {
                    // `resume_unwind` skips the panic hook, so the test log stays clean.
                    std::panic::resume_unwind(Box::new("injected attempt panic"));
                }
                Ok::<String, String>(format!("connected to {addr}"))
            }),
        )
        .await;

        match outcome {
            Ok(Err(HappyEyeballsError::AllAttemptsFailed { errors })) => {
                assert_eq!(errors.len(), 1, "one failed attempt expected: {errors:?}");
                assert_eq!(errors[0].0, v6("[::1]:80"));
                assert!(
                    errors[0].1.contains("panicked"),
                    "failure must name the panic: {}",
                    errors[0].1
                );
            }
            Ok(other) => panic!("expected AllAttemptsFailed, got: {other:?}"),
            Err(_) => panic!("race hung after its only attempt panicked"),
        }
    }

    /// #294 round 2: a losing attempt that blocks in a non-yielding section
    /// (here `block_in_place`) cannot be stopped from outside, because tokio
    /// cancellation is cooperative. The race must still hand over a ready
    /// winner after a bounded wait. It must not wait until the blocked loser
    /// ends.
    ///
    /// Deterministic in outcome: the gate keeps the loser blocked until the
    /// test releases it, so a race that waits for the loser cannot return
    /// before the release. A race with a bounded wait returns long before the
    /// 5 s guard.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn blocking_loser_does_not_hold_ready_winner() {
        let entered = Arc::new(tokio::sync::Notify::new());
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let release_rx = Arc::new(std::sync::Mutex::new(release_rx));
        let addrs = vec![v6("[::1]:80"), v4("10.0.0.1:80")];
        let config = HappyEyeballsConfig {
            connection_attempt_delay: Duration::from_millis(1),
            ..Default::default()
        };

        let mut race = tokio::spawn(async move {
            race_connect(&addrs, &config, move |addr| {
                let entered = Arc::clone(&entered);
                let release_rx = Arc::clone(&release_rx);
                async move {
                    if addr.is_ipv6() {
                        entered.notify_one();
                        // Blocking section: an abort cannot interrupt it.
                        tokio::task::block_in_place(|| {
                            let _ = release_rx.lock().unwrap().recv();
                        });
                        std::future::pending::<Result<u8, String>>().await
                    } else {
                        // Gate: win only after the loser is blocked.
                        entered.notified().await;
                        Ok(42)
                    }
                }
            })
            .await
        });

        let before_release = tokio::time::timeout(Duration::from_secs(5), &mut race).await;
        // Release the blocked worker before any assertion, so that a failure
        // cannot leave a blocked thread behind.
        let _ = release_tx.send(());
        let joined = match before_release {
            Ok(joined) => joined,
            Err(_) => {
                let _ = tokio::time::timeout(Duration::from_secs(5), race).await;
                panic!("the ready winner was held until the blocked loser was released");
            }
        };
        let (winner, addr) = joined.unwrap().unwrap();
        assert_eq!(winner, 42);
        assert_eq!(addr, v4("10.0.0.1:80"));
    }

    #[test]
    fn test_error_display() {
        let err = HappyEyeballsError::NoAddresses;
        assert_eq!(
            err.to_string(),
            "no addresses provided for connection attempts"
        );

        let err = HappyEyeballsError::Timeout;
        assert_eq!(err.to_string(), "connection racing timed out");

        let err = HappyEyeballsError::AllAttemptsFailed {
            errors: vec![
                (v4("10.0.0.1:80"), "refused".to_string()),
                (v6("[::1]:80"), "timeout".to_string()),
            ],
        };
        let display = err.to_string();
        assert!(display.contains("10.0.0.1:80: refused"));
        assert!(display.contains("[::1]:80: timeout"));
    }
}
