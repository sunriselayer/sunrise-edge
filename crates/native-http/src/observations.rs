//! Fixed local observations. No input bytes, dynamic labels or protocol state.
use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};

#[derive(Debug, Default)]
pub(crate) struct Counter(AtomicU64);
impl Counter {
    pub(crate) fn increment(&self) {
        let _previous = self.0.fetch_update(Ordering::Relaxed, Ordering::Relaxed,
            |value: u64| Some(value.saturating_add(1)));
    }
    fn get(&self) -> u64 { self.0.load(Ordering::Relaxed) }
}

#[derive(Debug, Default)]
pub(crate) struct Counters {
    pub(crate) connections_admitted: Counter,
    pub(crate) connections_refused: Counter,
    pub(crate) accept_failures: Counter,
    pub(crate) upgrade_failures: Counter,
    pub(crate) upgrade_timeouts: Counter,
    pub(crate) requests_dispatched: Counter,
    pub(crate) requests_refused: Counter,
    pub(crate) input_timeouts: Counter,
    pub(crate) output_timeouts: Counter,
    pub(crate) connection_failures: Counter,
    pub(crate) connection_task_failures: Counter,
    pub(crate) blocking_admitted: Counter,
    pub(crate) blocking_overloaded: Counter,
    pub(crate) blocking_closed: Counter,
    pub(crate) blocking_panics: Counter,
}

/// Cloneable in-memory observation owner. Values reset with a new host.
#[derive(Clone, Debug, Default)]
pub struct NativeHttpObservations(pub(crate) Arc<Counters>);

/// Fixed snapshot. Dispatch/admission counts do not imply application commit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NativeHttpSnapshot {
    /// Accepted connections holding capacity.
    pub connections_admitted: u64,
    /// Sockets refused before upgrade/parsing.
    pub connections_refused: u64,
    /// Listener accept errors.
    pub accept_failures: u64,
    /// Non-timeout stream-upgrade errors.
    pub upgrade_failures: u64,
    /// Typed stream-upgrade timeouts.
    pub upgrade_timeouts: u64,
    /// Complete bounded requests dispatched to the router.
    pub requests_dispatched: u64,
    /// Bounded collector refusals.
    pub requests_refused: u64,
    /// Connections encountering a typed input timeout, counted once.
    pub input_timeouts: u64,
    /// Connections encountering an output budget timeout, counted once.
    pub output_timeouts: u64,
    /// Hyper connection errors, including transport timeouts.
    pub connection_failures: u64,
    /// Panicked or cancelled connection tasks.
    pub connection_task_failures: u64,
    /// Synchronous jobs admitted, including pre-spawn releases.
    pub blocking_admitted: u64,
    /// Synchronous capacity refusals.
    pub blocking_overloaded: u64,
    /// Synchronous closed-admission refusals.
    pub blocking_closed: u64,
    /// Admitted synchronous jobs unwinding while holding their permit.
    pub blocking_panics: u64,
}

/// Closed host-termination category; no arbitrary caller-supplied labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeStopReason {
    /// Unix SIGINT.
    Sigint,
    /// Unix SIGTERM.
    Sigterm,
    /// Signal installation/stream failure.
    SignalFailure,
    /// Serving failed before the signal completed.
    ServeFailure,
}

impl NativeHttpObservations {
    /// Reads local counters independently; not an atomic protocol snapshot.
    #[must_use]
    pub fn snapshot(&self) -> NativeHttpSnapshot {
        let counters: &Counters = &self.0;
        NativeHttpSnapshot {
            connections_admitted: counters.connections_admitted.get(),
            connections_refused: counters.connections_refused.get(),
            accept_failures: counters.accept_failures.get(),
            upgrade_failures: counters.upgrade_failures.get(),
            upgrade_timeouts: counters.upgrade_timeouts.get(),
            requests_dispatched: counters.requests_dispatched.get(),
            requests_refused: counters.requests_refused.get(),
            input_timeouts: counters.input_timeouts.get(),
            output_timeouts: counters.output_timeouts.get(),
            connection_failures: counters.connection_failures.get(),
            connection_task_failures: counters.connection_task_failures.get(),
            blocking_admitted: counters.blocking_admitted.get(),
            blocking_overloaded: counters.blocking_overloaded.get(),
            blocking_closed: counters.blocking_closed.get(),
            blocking_panics: counters.blocking_panics.get(),
        }
    }
}

impl NativeHttpSnapshot {
    /// One fixed-schema secret-free record, bounded below 2 KiB for all u64s.
    #[must_use]
    pub fn termination_summary(self, reason: NativeStopReason) -> String {
        let reason: &str = match reason {
            NativeStopReason::Sigint => "sigint",
            NativeStopReason::Sigterm => "sigterm",
            NativeStopReason::SignalFailure => "signal_failure",
            NativeStopReason::ServeFailure => "serve_failure",
        };
        format!("native_operations schema=1 stop={reason} connections_admitted={} connections_refused={} accept_failures={} upgrade_failures={} upgrade_timeouts={} requests_dispatched={} requests_refused={} input_timeouts={} output_timeouts={} connection_failures={} connection_task_failures={} blocking_admitted={} blocking_overloaded={} blocking_closed={} blocking_panics={}\n",
            self.connections_admitted, self.connections_refused, self.accept_failures,
            self.upgrade_failures, self.upgrade_timeouts, self.requests_dispatched,
            self.requests_refused, self.input_timeouts, self.output_timeouts,
            self.connection_failures, self.connection_task_failures, self.blocking_admitted,
            self.blocking_overloaded, self.blocking_closed, self.blocking_panics)
    }
}

/// One private latch per connection, shared by socket and collector attribution.
#[derive(Debug, Default)]
pub(crate) struct ConnectionObservations {
    pub(crate) owner: NativeHttpObservations,
    input_timeout: AtomicBool,
    output_timeout: AtomicBool,
}
impl ConnectionObservations {
    pub(crate) fn new(owner: NativeHttpObservations) -> Arc<Self> {
        Arc::new(Self { owner, ..Self::default() })
    }
    pub(crate) fn input_timeout(&self) {
        if !self.input_timeout.swap(true, Ordering::Relaxed) {
            self.owner.0.input_timeouts.increment();
        }
    }
    pub(crate) fn output_timeout(&self) {
        if !self.output_timeout.swap(true, Ordering::Relaxed) {
            self.owner.0.output_timeouts.increment();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn counters_saturate_and_connection_timeout_latches_are_once() {
        let executor: crate::NativeBlockingExecutor = crate::NativeBlockingExecutor::new(
            crate::NativeBlockingPolicy::new(std::num::NonZeroUsize::new(1).unwrap()));
        let owner: NativeHttpObservations = executor.observations();
        owner.0.connections_admitted.0.store(u64::MAX - 1, Ordering::Relaxed);
        for _poll in 0..10 { owner.0.connections_admitted.increment(); }
        assert_eq!(owner.snapshot().connections_admitted, u64::MAX);
        let connection: Arc<ConnectionObservations> = ConnectionObservations::new(owner.clone());
        for _poll in 0..10 {
            connection.input_timeout();
            connection.output_timeout();
        }
        assert_eq!(owner.snapshot().input_timeouts, 1);
        assert_eq!(owner.snapshot().output_timeouts, 1);
        ConnectionObservations::new(owner.clone()).input_timeout();
        assert_eq!(owner.snapshot().input_timeouts, 2);
        owner.0.blocking_admitted.0.store(u64::MAX, Ordering::Relaxed);
        let permit = executor.try_acquire().unwrap();
        executor.close();
        assert_eq!(owner.snapshot().blocking_admitted, u64::MAX);
        assert!(tokio::time::timeout(std::time::Duration::from_millis(10), executor.wait_drained()).await.is_err(),
            "saturated observations cannot make an outstanding lifecycle drain complete");
        drop(permit);
        tokio::time::timeout(std::time::Duration::from_secs(2), executor.wait_drained()).await.unwrap();
    }

    #[test]
    fn termination_schema_is_fixed_bounded_and_secret_free() {
        let snapshot: NativeHttpSnapshot = NativeHttpSnapshot {
            connections_admitted: u64::MAX, connections_refused: u64::MAX,
            accept_failures: u64::MAX, upgrade_failures: u64::MAX, upgrade_timeouts: u64::MAX,
            requests_dispatched: u64::MAX, requests_refused: u64::MAX,
            input_timeouts: u64::MAX, output_timeouts: u64::MAX,
            connection_failures: u64::MAX, connection_task_failures: u64::MAX,
            blocking_admitted: u64::MAX, blocking_overloaded: u64::MAX,
            blocking_closed: u64::MAX, blocking_panics: u64::MAX,
        };
        let names: [&str; 17] = ["schema", "stop", "connections_admitted", "connections_refused",
            "accept_failures", "upgrade_failures", "upgrade_timeouts", "requests_dispatched",
            "requests_refused", "input_timeouts", "output_timeouts", "connection_failures",
            "connection_task_failures", "blocking_admitted", "blocking_overloaded", "blocking_closed", "blocking_panics"];
        for (reason, label) in [(NativeStopReason::Sigint, "sigint"), (NativeStopReason::Sigterm, "sigterm"),
            (NativeStopReason::SignalFailure, "signal_failure"), (NativeStopReason::ServeFailure, "serve_failure")] {
            let summary: String = snapshot.termination_summary(reason);
            assert!(summary.len() <= 2 * 1024);
            assert_eq!(summary.lines().count(), 1);
            assert!(summary.ends_with('\n'));
            let mut fields = summary.split_whitespace();
            assert_eq!(fields.next(), Some("native_operations"));
            let pairs: Vec<(&str, &str)> = fields.map(|field: &str| field.split_once('=').unwrap()).collect();
            assert_eq!(pairs.iter().map(|(name, _)| *name).collect::<Vec<&str>>(), names);
            assert_eq!(pairs[0].1, "1");
            assert_eq!(pairs[1].1, label);
            for (_, count) in &pairs[2..] { assert_eq!(count.parse::<u64>().unwrap(), u64::MAX); }
            for excluded in ["http", "127.0.0.1", "secret", "certificate", "request_id", "object_id", "body=", "error="] {
                assert!(!summary.contains(excluded));
            }
        }
    }
}
