//! Circuit breaker for HTTP vulnerability enrichment sources.
//!
//! Each CircuitBreaker tracks consecutive failures for a single API source.
//! Once the failure count reaches the threshold the circuit opens and
//! callers skip the source. Breakers optionally auto-reset after a TTL.
//!
//! Use `global_breaker("osv")` to get shared breakers that persist across
//! scans within the same process, or `CircuitBreaker::new()` for scan-scoped
//! breakers without TTL.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use crate::utils::progress;

/// A circuit breaker for a single enrichment source.
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
    ttl: Option<Duration>,
    tripped_at: Mutex<Option<Instant>>,
}

impl CircuitBreaker {
    /// Create a new breaker without TTL (stays open until manual reset via `record_success`).
    pub fn new(source_name: &'static str, threshold: u32) -> Self {
        Self {
            failures: AtomicU32::new(0),
            threshold,
            source_name,
            ttl: None,
            tripped_at: Mutex::new(None),
        }
    }

    /// Create a new breaker that auto-resets after `ttl` elapses since tripping.
    pub fn with_ttl(source_name: &'static str, threshold: u32, ttl: Duration) -> Self {
        Self {
            failures: AtomicU32::new(0),
            threshold,
            source_name,
            ttl: Some(ttl),
            tripped_at: Mutex::new(None),
        }
    }

    /// Record one failure. If this failure hits the threshold, record the trip
    /// timestamp and emit a progress event.
    pub fn record_failure(&self) {
        let prev = self.failures.fetch_add(1, Ordering::SeqCst);
        let new_count = prev + 1;
        if new_count == self.threshold {
            *self.tripped_at.lock().unwrap() = Some(Instant::now());
            progress(
                &format!("{}.circuit_breaker.tripped", self.source_name),
                &format!(
                    "source={} failures={} threshold={}; disabling{}",
                    self.source_name,
                    new_count,
                    self.threshold,
                    self.ttl
                        .map(|d| format!(" (auto-reset in {}s)", d.as_secs()))
                        .unwrap_or_default()
                ),
            );
        }
    }

    /// Reset the failure counter to zero (call on a successful request).
    pub fn record_success(&self) {
        self.failures.store(0, Ordering::SeqCst);
        *self.tripped_at.lock().unwrap() = None;
    }

    /// Returns true when the circuit is open (failures >= threshold).
    /// If a TTL is set and has elapsed, the breaker auto-resets and returns false.
    pub fn is_open(&self) -> bool {
        if self.failures.load(Ordering::SeqCst) >= self.threshold {
            if let Some(ttl) = self.ttl {
                let tripped = self.tripped_at.lock().unwrap();
                if let Some(at) = *tripped {
                    if at.elapsed() > ttl {
                        drop(tripped);
                        self.failures.store(0, Ordering::SeqCst);
                        *self.tripped_at.lock().unwrap() = None;
                        progress(
                            &format!("{}.circuit_breaker.reset", self.source_name),
                            &format!("TTL ({:?}) expired, re-enabling source", ttl),
                        );
                        return false;
                    }
                }
            }
            true
        } else {
            false
        }
    }

    /// The name of the enrichment source this breaker guards.
    pub fn source_name(&self) -> &str {
        self.source_name
    }
}

// ---------------------------------------------------------------------------
// Global breaker registry — shared across scans within a single process
// ---------------------------------------------------------------------------

struct GlobalBreakerRegistry {
    breakers: Mutex<HashMap<&'static str, &'static CircuitBreaker>>,
}

impl GlobalBreakerRegistry {
    fn new() -> Self {
        Self {
            breakers: Mutex::new(HashMap::new()),
        }
    }

    fn get(
        &self,
        source_name: &'static str,
        threshold: u32,
        ttl: Duration,
    ) -> &'static CircuitBreaker {
        let mut map = self.breakers.lock().unwrap();
        if let Some(&breaker) = map.get(source_name) {
            return breaker;
        }
        let breaker: &'static CircuitBreaker =
            Box::leak(Box::new(CircuitBreaker::with_ttl(source_name, threshold, ttl)));
        map.insert(source_name, breaker);
        breaker
    }
}

static GLOBAL_REGISTRY: OnceLock<GlobalBreakerRegistry> = OnceLock::new();

/// Default TTL for global circuit breakers (5 minutes).
const DEFAULT_TTL_SECS: u64 = 300;

/// Get a shared circuit breaker from the global registry.
///
/// Breakers persist across scans within the same process and auto-reset
/// after 5 minutes. All global breakers use threshold=5.
pub fn global_breaker(source_name: &'static str) -> &'static CircuitBreaker {
    GLOBAL_REGISTRY
        .get_or_init(GlobalBreakerRegistry::new)
        .get(source_name, 5, Duration::from_secs(DEFAULT_TTL_SECS))
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

    #[test]
    fn test_ttl_breaker_stays_open_before_expiry() {
        let cb = CircuitBreaker::with_ttl("test_ttl", 3, Duration::from_secs(300));
        for _ in 0..3 {
            cb.record_failure();
        }
        assert!(cb.is_open(), "should be open before TTL expires");
    }

    #[test]
    fn test_ttl_breaker_resets_after_expiry() {
        let cb = CircuitBreaker::with_ttl("test_ttl_reset", 3, Duration::from_millis(50));
        for _ in 0..3 {
            cb.record_failure();
        }
        assert!(cb.is_open(), "should be open immediately after tripping");
        std::thread::sleep(Duration::from_millis(60));
        assert!(!cb.is_open(), "should auto-reset after TTL expires");
    }

    #[test]
    fn test_no_ttl_stays_open_indefinitely() {
        let cb = CircuitBreaker::new("test_no_ttl", 3);
        for _ in 0..3 {
            cb.record_failure();
        }
        assert!(cb.is_open());
        std::thread::sleep(Duration::from_millis(10));
        assert!(cb.is_open(), "without TTL, breaker stays open");
    }

    #[test]
    fn test_global_breaker_returns_same_instance() {
        let b1 = global_breaker("test_global_same");
        let b2 = global_breaker("test_global_same");
        // Same pointer — same static breaker
        assert!(std::ptr::eq(b1, b2), "global_breaker should return same instance");
    }

    #[test]
    fn test_global_breaker_survives_across_calls() {
        let b1 = global_breaker("test_global_survive");
        for _ in 0..5 {
            b1.record_failure();
        }
        assert!(b1.is_open());
        // Simulate "next scan" — get same breaker
        let b2 = global_breaker("test_global_survive");
        assert!(b2.is_open(), "breaker should still be open from previous use");
    }
}
