//! Fixed local observations. No input bytes, dynamic labels or protocol state.
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

const LIVE_FIELDS: [&[u8]; 15] = [
    b"connections_admitted=",
    b"connections_refused=",
    b"accept_failures=",
    b"upgrade_failures=",
    b"upgrade_timeouts=",
    b"requests_dispatched=",
    b"requests_refused=",
    b"input_timeouts=",
    b"output_timeouts=",
    b"connection_failures=",
    b"connection_task_failures=",
    b"blocking_admitted=",
    b"blocking_overloaded=",
    b"blocking_closed=",
    b"blocking_panics=",
];
const MAX_LIVE_RECORD_BYTES: usize = 2_048;

/// Fixed, input-independent rejection categories for the live record grammar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeHttpLiveRecordError {
    /// The record framing or fixed prefix was not exact.
    Framing,
    /// The live field names or order did not match schema 1.
    Fields,
    /// A counter was not a canonical unsigned decimal `u64`.
    Counter,
}

impl core::fmt::Display for NativeHttpLiveRecordError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message: &str = match self {
            Self::Framing => "invalid live observation framing",
            Self::Fields => "invalid live observation fields",
            Self::Counter => "invalid live observation counter",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for NativeHttpLiveRecordError {}

/// Decodes one canonical DR-0223 live record without retaining input text.
pub fn decode_live_summary(
    input: &[u8],
) -> Result<NativeHttpSnapshot, NativeHttpLiveRecordError> {
    const PREFIX: &[u8] = b"native_operations schema=1 kind=live ";
    if input.len() <= PREFIX.len() + 1
        || input.len() >= MAX_LIVE_RECORD_BYTES
        || input.last() != Some(&b'\n')
        || input[..input.len() - 1].contains(&b'\n')
        || input.contains(&b'\r')
        || input.contains(&0)
        || input.get(..PREFIX.len()) != Some(PREFIX)
    {
        return Err(NativeHttpLiveRecordError::Framing);
    }
    let mut body: &[u8] = &input[PREFIX.len()..input.len() - 1];
    let mut values: [u64; 15] = [0; 15];
    for (index, expected_field) in LIVE_FIELDS.iter().enumerate() {
        let separator: Option<usize> = body.iter().position(|byte: &u8| *byte == b' ');
        let (field, remainder): (&[u8], &[u8]) = if index + 1 == LIVE_FIELDS.len() {
            if separator.is_some() {
                return Err(NativeHttpLiveRecordError::Fields);
            }
            (body, &[])
        } else {
            match separator {
                Some(position) => (&body[..position], &body[position + 1..]),
                None => return Err(NativeHttpLiveRecordError::Fields),
            }
        };
        if field.len() <= expected_field.len()
            || field.get(..expected_field.len()) != Some(*expected_field)
        {
            return Err(NativeHttpLiveRecordError::Fields);
        }
        let decimal: &[u8] = &field[expected_field.len()..];
        if decimal.is_empty()
            || (decimal.len() > 1 && decimal.first() == Some(&b'0'))
            || !decimal.iter().all(u8::is_ascii_digit)
        {
            return Err(NativeHttpLiveRecordError::Counter);
        }
        let mut value: u64 = 0;
        for digit in decimal {
            value = value
                .checked_mul(10)
                .and_then(|accumulator: u64| accumulator.checked_add(u64::from(*digit - b'0')))
                .ok_or(NativeHttpLiveRecordError::Counter)?;
        }
        values[index] = value;
        body = remainder;
    }
    if !body.is_empty() {
        return Err(NativeHttpLiveRecordError::Fields);
    }
    Ok(NativeHttpSnapshot {
        connections_admitted: values[0],
        connections_refused: values[1],
        accept_failures: values[2],
        upgrade_failures: values[3],
        upgrade_timeouts: values[4],
        requests_dispatched: values[5],
        requests_refused: values[6],
        input_timeouts: values[7],
        output_timeouts: values[8],
        connection_failures: values[9],
        connection_task_failures: values[10],
        blocking_admitted: values[11],
        blocking_overloaded: values[12],
        blocking_closed: values[13],
        blocking_panics: values[14],
    })
}

#[derive(Debug, Default)]
pub(crate) struct Counter(AtomicU64);
impl Counter {
    pub(crate) fn increment(&self) {
        let _previous = self
            .0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value: u64| {
                Some(value.saturating_add(1))
            });
    }
    fn get(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
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
    /// One fixed-schema live counter record, bounded below 2 KiB for all u64s.
    #[must_use]
    pub fn live_summary(self) -> String {
        format!("native_operations schema=1 kind=live {}\n", self.counter_fields())
    }

    /// One fixed-schema secret-free record, bounded below 2 KiB for all u64s.
    #[must_use]
    pub fn termination_summary(self, reason: NativeStopReason) -> String {
        let reason: &str = match reason {
            NativeStopReason::Sigint => "sigint",
            NativeStopReason::Sigterm => "sigterm",
            NativeStopReason::SignalFailure => "signal_failure",
            NativeStopReason::ServeFailure => "serve_failure",
        };
        format!(
            "native_operations schema=1 stop={reason} {}\n",
            self.counter_fields()
        )
    }

    fn counter_fields(self) -> String {
        format!(
            "connections_admitted={} connections_refused={} accept_failures={} upgrade_failures={} upgrade_timeouts={} requests_dispatched={} requests_refused={} input_timeouts={} output_timeouts={} connection_failures={} connection_task_failures={} blocking_admitted={} blocking_overloaded={} blocking_closed={} blocking_panics={}",
            self.connections_admitted,
            self.connections_refused,
            self.accept_failures,
            self.upgrade_failures,
            self.upgrade_timeouts,
            self.requests_dispatched,
            self.requests_refused,
            self.input_timeouts,
            self.output_timeouts,
            self.connection_failures,
            self.connection_task_failures,
            self.blocking_admitted,
            self.blocking_overloaded,
            self.blocking_closed,
            self.blocking_panics
        )
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
        Arc::new(Self {
            owner,
            ..Self::default()
        })
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
            crate::NativeBlockingPolicy::new(std::num::NonZeroUsize::new(1).unwrap()),
        );
        let owner: NativeHttpObservations = executor.observations();
        owner
            .0
            .connections_admitted
            .0
            .store(u64::MAX - 1, Ordering::Relaxed);
        for _poll in 0..10 {
            owner.0.connections_admitted.increment();
        }
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
        owner
            .0
            .blocking_admitted
            .0
            .store(u64::MAX, Ordering::Relaxed);
        let permit = executor.try_acquire().unwrap();
        executor.close();
        assert_eq!(owner.snapshot().blocking_admitted, u64::MAX);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(10),
                executor.wait_drained()
            )
            .await
            .is_err(),
            "saturated observations cannot make an outstanding lifecycle drain complete"
        );
        drop(permit);
        tokio::time::timeout(std::time::Duration::from_secs(2), executor.wait_drained())
            .await
            .unwrap();
    }

    #[test]
    fn termination_schema_is_fixed_bounded_and_secret_free() {
        let snapshot: NativeHttpSnapshot = NativeHttpSnapshot {
            connections_admitted: u64::MAX,
            connections_refused: u64::MAX,
            accept_failures: u64::MAX,
            upgrade_failures: u64::MAX,
            upgrade_timeouts: u64::MAX,
            requests_dispatched: u64::MAX,
            requests_refused: u64::MAX,
            input_timeouts: u64::MAX,
            output_timeouts: u64::MAX,
            connection_failures: u64::MAX,
            connection_task_failures: u64::MAX,
            blocking_admitted: u64::MAX,
            blocking_overloaded: u64::MAX,
            blocking_closed: u64::MAX,
            blocking_panics: u64::MAX,
        };
        let names: [&str; 17] = [
            "schema",
            "stop",
            "connections_admitted",
            "connections_refused",
            "accept_failures",
            "upgrade_failures",
            "upgrade_timeouts",
            "requests_dispatched",
            "requests_refused",
            "input_timeouts",
            "output_timeouts",
            "connection_failures",
            "connection_task_failures",
            "blocking_admitted",
            "blocking_overloaded",
            "blocking_closed",
            "blocking_panics",
        ];
        for (reason, label) in [
            (NativeStopReason::Sigint, "sigint"),
            (NativeStopReason::Sigterm, "sigterm"),
            (NativeStopReason::SignalFailure, "signal_failure"),
            (NativeStopReason::ServeFailure, "serve_failure"),
        ] {
            let summary: String = snapshot.termination_summary(reason);
            assert!(summary.len() <= 2 * 1024);
            assert_eq!(summary.lines().count(), 1);
            assert!(summary.ends_with('\n'));
            let mut fields = summary.split_whitespace();
            assert_eq!(fields.next(), Some("native_operations"));
            let pairs: Vec<(&str, &str)> = fields
                .map(|field: &str| field.split_once('=').unwrap())
                .collect();
            assert_eq!(
                pairs.iter().map(|(name, _)| *name).collect::<Vec<&str>>(),
                names
            );
            assert_eq!(pairs[0].1, "1");
            assert_eq!(pairs[1].1, label);
            for (_, count) in &pairs[2..] {
                assert_eq!(count.parse::<u64>().unwrap(), u64::MAX);
            }
            for excluded in [
                "http",
                "127.0.0.1",
                "secret",
                "certificate",
                "request_id",
                "object_id",
                "body=",
                "error=",
            ] {
                assert!(!summary.contains(excluded));
            }
        }

        let live_summary: String = snapshot.live_summary();
        assert!(live_summary.len() <= 2 * 1024);
        assert_eq!(live_summary.lines().count(), 1);
        assert!(live_summary.ends_with('\n'));
        let mut live_fields = live_summary.split_whitespace();
        assert_eq!(live_fields.next(), Some("native_operations"));
        assert_eq!(live_fields.next(), Some("schema=1"));
        assert_eq!(live_fields.next(), Some("kind=live"));
        let live_pairs: Vec<(&str, &str)> = live_fields
            .map(|field: &str| field.split_once('=').unwrap())
            .collect();
        let live_names: Vec<&str> = vec![
            "connections_admitted",
            "connections_refused",
            "accept_failures",
            "upgrade_failures",
            "upgrade_timeouts",
            "requests_dispatched",
            "requests_refused",
            "input_timeouts",
            "output_timeouts",
            "connection_failures",
            "connection_task_failures",
            "blocking_admitted",
            "blocking_overloaded",
            "blocking_closed",
            "blocking_panics",
        ];
        let actual_live_names: Vec<&str> =
            live_pairs.iter().map(|(name, _)| *name).collect();
        assert_eq!(actual_live_names, live_names);
        for (_, count) in &live_pairs {
            assert_eq!(count.parse::<u64>().unwrap(), u64::MAX);
        }
        for excluded in [
            "http",
            "127.0.0.1",
            "secret",
            "certificate",
            "request_id",
            "object_id",
            "body=",
            "error=",
        ] {
            assert!(!live_summary.contains(excluded));
        }
    }

    #[test]
    fn live_and_termination_records_have_independent_fixed_field_order() {
        let snapshot: NativeHttpSnapshot = NativeHttpSnapshot {
            connections_admitted: 1,
            connections_refused: 2,
            accept_failures: 3,
            upgrade_failures: 4,
            upgrade_timeouts: 5,
            requests_dispatched: 6,
            requests_refused: 7,
            input_timeouts: 8,
            output_timeouts: 9,
            connection_failures: 10,
            connection_task_failures: 11,
            blocking_admitted: 12,
            blocking_overloaded: 13,
            blocking_closed: 14,
            blocking_panics: 15,
        };
        let expected_fields: &str = "connections_admitted=1 connections_refused=2 accept_failures=3 upgrade_failures=4 upgrade_timeouts=5 requests_dispatched=6 requests_refused=7 input_timeouts=8 output_timeouts=9 connection_failures=10 connection_task_failures=11 blocking_admitted=12 blocking_overloaded=13 blocking_closed=14 blocking_panics=15";
        assert_eq!(
            snapshot.live_summary(),
            format!("native_operations schema=1 kind=live {expected_fields}\n")
        );
        assert_eq!(
            snapshot.termination_summary(NativeStopReason::Sigterm),
            format!("native_operations schema=1 stop=sigterm {expected_fields}\n")
        );
    }

    #[test]
    fn live_decoder_round_trips_independent_zero_maximum_and_distinct_records() {
        let zero: NativeHttpSnapshot = NativeHttpSnapshot::default();
        let maximum: NativeHttpSnapshot = NativeHttpSnapshot {
            connections_admitted: u64::MAX,
            connections_refused: u64::MAX,
            accept_failures: u64::MAX,
            upgrade_failures: u64::MAX,
            upgrade_timeouts: u64::MAX,
            requests_dispatched: u64::MAX,
            requests_refused: u64::MAX,
            input_timeouts: u64::MAX,
            output_timeouts: u64::MAX,
            connection_failures: u64::MAX,
            connection_task_failures: u64::MAX,
            blocking_admitted: u64::MAX,
            blocking_overloaded: u64::MAX,
            blocking_closed: u64::MAX,
            blocking_panics: u64::MAX,
        };
        let distinct: NativeHttpSnapshot = NativeHttpSnapshot {
            connections_admitted: 1,
            connections_refused: 2,
            accept_failures: 3,
            upgrade_failures: 4,
            upgrade_timeouts: 5,
            requests_dispatched: 6,
            requests_refused: 7,
            input_timeouts: 8,
            output_timeouts: 9,
            connection_failures: 10,
            connection_task_failures: 11,
            blocking_admitted: 12,
            blocking_overloaded: 13,
            blocking_closed: 14,
            blocking_panics: 15,
        };
        let zero_record: &[u8] = concat!(
            "native_operations schema=1 kind=live ",
            "connections_admitted=0 connections_refused=0 accept_failures=0 ",
            "upgrade_failures=0 upgrade_timeouts=0 requests_dispatched=0 ",
            "requests_refused=0 input_timeouts=0 output_timeouts=0 ",
            "connection_failures=0 connection_task_failures=0 blocking_admitted=0 ",
            "blocking_overloaded=0 blocking_closed=0 blocking_panics=0\n"
        )
        .as_bytes();
        let maximum_record: &[u8] = concat!(
            "native_operations schema=1 kind=live ",
            "connections_admitted=18446744073709551615 connections_refused=18446744073709551615 ",
            "accept_failures=18446744073709551615 upgrade_failures=18446744073709551615 ",
            "upgrade_timeouts=18446744073709551615 requests_dispatched=18446744073709551615 ",
            "requests_refused=18446744073709551615 input_timeouts=18446744073709551615 ",
            "output_timeouts=18446744073709551615 connection_failures=18446744073709551615 ",
            "connection_task_failures=18446744073709551615 blocking_admitted=18446744073709551615 ",
            "blocking_overloaded=18446744073709551615 blocking_closed=18446744073709551615 ",
            "blocking_panics=18446744073709551615\n"
        )
        .as_bytes();
        let distinct_record: &[u8] = concat!(
            "native_operations schema=1 kind=live ",
            "connections_admitted=1 connections_refused=2 accept_failures=3 ",
            "upgrade_failures=4 upgrade_timeouts=5 requests_dispatched=6 ",
            "requests_refused=7 input_timeouts=8 output_timeouts=9 ",
            "connection_failures=10 connection_task_failures=11 blocking_admitted=12 ",
            "blocking_overloaded=13 blocking_closed=14 blocking_panics=15\n"
        )
        .as_bytes();
        for (record, expected) in [
            (zero_record, zero),
            (maximum_record, maximum),
            (distinct_record, distinct),
        ] {
            assert_eq!(decode_live_summary(record), Ok(expected));
            assert_eq!(expected.live_summary().as_bytes(), record);
        }
    }

    #[test]
    fn live_decoder_rejects_noncanonical_and_nonlive_records() {
        let valid: &[u8] = concat!(
            "native_operations schema=1 kind=live ",
            "connections_admitted=0 connections_refused=0 accept_failures=0 ",
            "upgrade_failures=0 upgrade_timeouts=0 requests_dispatched=0 ",
            "requests_refused=0 input_timeouts=0 output_timeouts=0 ",
            "connection_failures=0 connection_task_failures=0 blocking_admitted=0 ",
            "blocking_overloaded=0 blocking_closed=0 blocking_panics=0\n"
        )
        .as_bytes();
        let reordered: &[u8] = concat!(
            "native_operations schema=1 kind=live ",
            "connections_refused=0 connections_admitted=0 accept_failures=0 ",
            "upgrade_failures=0 upgrade_timeouts=0 requests_dispatched=0 ",
            "requests_refused=0 input_timeouts=0 output_timeouts=0 ",
            "connection_failures=0 connection_task_failures=0 blocking_admitted=0 ",
            "blocking_overloaded=0 blocking_closed=0 blocking_panics=0\n"
        )
        .as_bytes();
        let duplicate: &[u8] = concat!(
            "native_operations schema=1 kind=live ",
            "connections_admitted=0 connections_admitted=0 accept_failures=0 ",
            "upgrade_failures=0 upgrade_timeouts=0 requests_dispatched=0 ",
            "requests_refused=0 input_timeouts=0 output_timeouts=0 ",
            "connection_failures=0 connection_task_failures=0 blocking_admitted=0 ",
            "blocking_overloaded=0 blocking_closed=0 blocking_panics=0\n"
        )
        .as_bytes();
        let extra: &[u8] = concat!(
            "native_operations schema=1 kind=live ",
            "connections_admitted=0 connections_refused=0 accept_failures=0 ",
            "upgrade_failures=0 upgrade_timeouts=0 requests_dispatched=0 ",
            "requests_refused=0 input_timeouts=0 output_timeouts=0 ",
            "connection_failures=0 connection_task_failures=0 blocking_admitted=0 ",
            "blocking_overloaded=0 blocking_closed=0 blocking_panics=0 extra=0\n"
        )
        .as_bytes();
        let mut embedded_lf: Vec<u8> = valid.to_vec();
        embedded_lf.insert(valid.len() - 1, b'\n');
        let mut embedded_nul: Vec<u8> = valid.to_vec();
        embedded_nul.insert(valid.len() - 1, 0);
        const COUNTER_PREFIX: &[u8] =
            b"native_operations schema=1 kind=live connections_admitted=";
        const COUNTER_SUFFIX: &[u8] = concat!(
            " connections_refused=0 accept_failures=0 upgrade_failures=0 ",
            "upgrade_timeouts=0 requests_dispatched=0 requests_refused=0 ",
            "input_timeouts=0 output_timeouts=0 connection_failures=0 ",
            "connection_task_failures=0 blocking_admitted=0 blocking_overloaded=0 ",
            "blocking_closed=0 blocking_panics=0\n"
        )
        .as_bytes();
        let with_first_counter = |value: &[u8]| -> Vec<u8> {
            let mut record: Vec<u8> = Vec::with_capacity(
                COUNTER_PREFIX.len() + value.len() + COUNTER_SUFFIX.len(),
            );
            record.extend_from_slice(COUNTER_PREFIX);
            record.extend_from_slice(value);
            record.extend_from_slice(COUNTER_SUFFIX);
            record
        };
        let leading_zero: Vec<u8> = with_first_counter(b"00");
        let signed: Vec<u8> = with_first_counter(b"+1");
        let overflow: Vec<u8> = with_first_counter(b"18446744073709551616");
        let non_ascii: Vec<u8> = with_first_counter(b"\xff");
        let malformed: [(&[u8], NativeHttpLiveRecordError); 14] = [
            (b"native_operations schema=2 kind=live\n", NativeHttpLiveRecordError::Framing),
            (b"native_operations schema=1 kind=termination\n", NativeHttpLiveRecordError::Framing),
            (reordered, NativeHttpLiveRecordError::Fields),
            (duplicate, NativeHttpLiveRecordError::Fields),
            (extra, NativeHttpLiveRecordError::Fields),
            (&leading_zero, NativeHttpLiveRecordError::Counter),
            (&signed, NativeHttpLiveRecordError::Counter),
            (&overflow, NativeHttpLiveRecordError::Counter),
            (&non_ascii, NativeHttpLiveRecordError::Counter),
            (
                b"native_operations schema=1 kind=live connections_admitted=0",
                NativeHttpLiveRecordError::Framing,
            ),
            (
                b" native_operations schema=1 kind=live connections_admitted=0\n",
                NativeHttpLiveRecordError::Framing,
            ),
            (&embedded_lf, NativeHttpLiveRecordError::Framing),
            (&embedded_nul, NativeHttpLiveRecordError::Framing),
            (
                b"native_operations schema=1 kind=live connections_admitted=0\r\n",
                NativeHttpLiveRecordError::Framing,
            ),
        ];
        for (record, expected_error) in malformed {
            assert_eq!(decode_live_summary(record), Err(expected_error));
        }
    }
}
