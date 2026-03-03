//! Circuit breaker for HTTP vulnerability enrichment sources.
#![allow(dead_code)]
//!
//! Each CircuitBreaker tracks consecutive failures for a single API source.
//! Once the failure count reaches the threshold the circuit opens and
//! callers skip the source for the remainder of the scan. The breaker is
//! intentionally scan-scoped (created fresh per invocation, never static).

use std::sync::atomic::{AtomicU32, Ordering};

use crate::utils::progress;

/// A scan-scoped circuit breaker for a single enrichment source.
///
/// # Example
/// ```rust
/// let cb = CircuitBreaker::new("osv", 5);
/// cb.record_failure();
/// assert!(!cb.is_open()); // 1 failure, threshold not reached
/// ```
pub struct CircuitBreaker {
    failures: AtomicU32,
    threshold: u32,
    source_name: &'static str,
}

impl CircuitBreaker {
    /// Create a new breaker for `source_name` that opens after `threshold`
    /// consecutive failures. Does NOT use Arc internally — callers wrap if needed.
    pub fn new(source_name: &'static str, threshold: u32) -> Self {
        Self {
            failures: AtomicU32::new(0),
            threshold,
            source_name,
        }
    }

    /// Record one failure. If this failure hits the threshold, emit a progress
    /// event so the user knows the source has been disabled for this scan.
    pub fn record_failure(&self) {
        let prev = self.failures.fetch_add(1, Ordering::SeqCst);
        let new_count = prev + 1;
        if new_count == self.threshold {
            progress(
                &format!("{}.circuit_breaker.tripped", self.source_name),
                &format!(
                    "source={} failures={} threshold={}; disabling for this scan",
                    self.source_name, new_count, self.threshold
                ),
            );
        }
    }

    /// Reset the failure counter to zero (call on a successful request).
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::SeqCst);
    }

    /// Returns true when the circuit is open (failures >= threshold).
    /// Callers should skip the enrichment source when this returns true.
    pub fn is_open(&self) -> bool {
        self.failures.load(Ordering::SeqCst) >= self.threshold
    }

    /// The name of the enrichment source this breaker guards.
    pub fn source_name(&self) -> &str {
        self.source_name
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::new("test_source", 5);
        assert!(!cb.is_open(), "new breaker should start closed");
    }

    #[test]
    fn test_circuit_breaker_trips_at_threshold() {
        let cb = CircuitBreaker::new("test_source", 5);
        for _ in 0..4 {
            cb.record_failure();
            assert!(!cb.is_open(), "should not open before threshold");
        }
        cb.record_failure(); // 5th failure
        assert!(cb.is_open(), "should open at threshold");
    }

    #[test]
    fn test_circuit_breaker_resets_on_success() {
        let cb = CircuitBreaker::new("test_source", 5);
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // resets to 0
        // Need 5 more failures to trip again
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        cb.record_failure();
        assert!(
            !cb.is_open(),
            "after reset, 4 failures should not open the circuit"
        );
    }

    #[test]
    fn test_circuit_breaker_stays_open_past_threshold() {
        let cb = CircuitBreaker::new("test_source", 5);
        for _ in 0..7 {
            cb.record_failure();
        }
        assert!(cb.is_open(), "should stay open past threshold");
    }
}
