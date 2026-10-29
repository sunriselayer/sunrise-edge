use native_http::NativeHttpSnapshot;
use std::{
    io,
    path::PathBuf,
    time::{Duration, Instant},
};

pub(crate) const LOCAL_OBSERVATIONS_SOCKET_FLAG: &str = "--local-observations-socket";
#[cfg(unix)]
const MAX_SOCKET_PATH_BYTES: usize = 100;
const LIVE_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LocalObservationsPath(PathBuf);

impl LocalObservationsPath {
    pub(crate) fn parse(value: Option<String>) -> Result<Option<Self>, String> {
        let Some(value) = value else {
            return Ok(None);
        };
        #[cfg(not(unix))]
        {
            let _value = value;
            return Err(format!("{LOCAL_OBSERVATIONS_SOCKET_FLAG} requires Unix"));
        }
        #[cfg(unix)]
        {
            if value.is_empty() || value.as_bytes().contains(&0) {
                return Err(format!(
                    "{LOCAL_OBSERVATIONS_SOCKET_FLAG} requires a nonempty path without NUL"
                ));
            }
            if value.len() > MAX_SOCKET_PATH_BYTES {
                return Err(format!(
                    "{LOCAL_OBSERVATIONS_SOCKET_FLAG} path exceeds {MAX_SOCKET_PATH_BYTES} bytes"
                ));
            }
            let path: PathBuf = PathBuf::from(value);
            if !path.is_absolute() {
                return Err(format!(
                    "{LOCAL_OBSERVATIONS_SOCKET_FLAG} requires an absolute path"
                ));
            }
            Ok(Some(Self(path)))
        }
    }
}

#[derive(Default)]
pub(crate) struct PreparedLocalObservations {
    #[cfg(unix)]
    socket: Option<std::os::unix::net::UnixDatagram>,
    cooldown: LiveSnapshotCooldown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LiveSendOutcome {
    Disabled,
    Throttled,
    Sent,
    Dropped,
}

impl PreparedLocalObservations {
    pub(crate) fn disabled() -> Self {
        Self::default()
    }

    pub(crate) fn connect(path: Option<LocalObservationsPath>) -> io::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::disabled());
        };
        #[cfg(unix)]
        {
            let socket: std::os::unix::net::UnixDatagram =
                std::os::unix::net::UnixDatagram::unbound()?;
            socket.set_nonblocking(true)?;
            socket.connect(&path.0)?;
            Ok(Self {
                socket: Some(socket),
                cooldown: LiveSnapshotCooldown::default(),
            })
        }
        #[cfg(not(unix))]
        {
            let _path = path;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "local Native observations require Unix",
            ))
        }
    }

    pub(crate) fn is_enabled(&self) -> bool {
        #[cfg(unix)]
        {
            self.socket.is_some()
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    pub(crate) fn is_eligible(&self, now: Instant) -> bool {
        self.cooldown.is_eligible(now)
    }

    pub(crate) fn next_eligible(&self) -> Option<Instant> {
        self.cooldown.next_eligible()
    }

    pub(super) fn try_send(
        &mut self,
        attempted_at: Instant,
        snapshot: NativeHttpSnapshot,
    ) -> LiveSendOutcome {
        self.try_send_with_interval(attempted_at, snapshot, LIVE_SNAPSHOT_INTERVAL)
    }

    fn try_send_with_interval(
        &mut self,
        attempted_at: Instant,
        snapshot: NativeHttpSnapshot,
        interval: Duration,
    ) -> LiveSendOutcome {
        #[cfg(unix)]
        {
            if self.socket.is_none() {
                return LiveSendOutcome::Disabled;
            }
            if !self.cooldown.is_eligible(attempted_at) {
                return LiveSendOutcome::Throttled;
            }
            if !self.cooldown.charge(attempted_at, interval) {
                self.socket = None;
                return LiveSendOutcome::Disabled;
            }
            let summary: String = snapshot.live_summary();
            let socket: &std::os::unix::net::UnixDatagram = match self.socket.as_ref() {
                Some(socket) => socket,
                None => return LiveSendOutcome::Disabled,
            };
            match socket.send(summary.as_bytes()) {
                Ok(length) if length == summary.len() => LiveSendOutcome::Sent,
                Ok(_) | Err(_) => LiveSendOutcome::Dropped,
            }
        }
        #[cfg(not(unix))]
        {
            let _unused_inputs = (attempted_at, snapshot, interval);
            LiveSendOutcome::Disabled
        }
    }
}

#[derive(Default)]
pub(crate) struct LiveSnapshotCooldown {
    next_eligible: Option<Instant>,
    exhausted: bool,
}

impl LiveSnapshotCooldown {
    fn is_eligible(&self, now: Instant) -> bool {
        !self.exhausted
            && self
                .next_eligible
                .is_none_or(|deadline: Instant| now >= deadline)
    }

    fn next_eligible(&self) -> Option<Instant> {
        self.next_eligible
    }

    fn charge(&mut self, attempted_at: Instant, interval: Duration) -> bool {
        let Some(deadline) = attempted_at.checked_add(interval) else {
            self.exhausted = true;
            return false;
        };
        self.next_eligible = Some(deadline);
        true
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    #[test]
    fn local_socket_path_is_opt_in_absolute_bounded_and_nul_free() {
        assert_eq!(LocalObservationsPath::parse(None).unwrap(), None);
        assert!(LocalObservationsPath::parse(Some(String::new())).is_err());
        assert!(LocalObservationsPath::parse(Some("relative.sock".into())).is_err());
        assert!(LocalObservationsPath::parse(Some("/tmp/a\0b".into())).is_err());
        assert!(LocalObservationsPath::parse(Some(format!("/{}", "a".repeat(100)))).is_err());
        assert!(LocalObservationsPath::parse(Some(format!("/{}", "a".repeat(99)))).is_ok());
        assert!(LocalObservationsPath::parse(Some("/tmp/native-observations.sock".into())).is_ok());

        let tokens: Vec<std::ffi::OsString> = vec![
            LOCAL_OBSERVATIONS_SOCKET_FLAG.into(),
            "/tmp/one.sock".into(),
            LOCAL_OBSERVATIONS_SOCKET_FLAG.into(),
            "/tmp/two.sock".into(),
        ];
        let mut parsed =
            crate::common::FlagSet::parse(tokens, &[LOCAL_OBSERVATIONS_SOCKET_FLAG], &[]).unwrap();
        assert!(parsed.optional_one(LOCAL_OBSERVATIONS_SOCKET_FLAG).is_err());
    }

    #[test]
    fn snapshot_cooldown_charges_each_attempt_including_failures() {
        let start: Instant = Instant::now();
        let mut cooldown: LiveSnapshotCooldown = LiveSnapshotCooldown::default();
        assert!(cooldown.is_eligible(start));
        assert!(cooldown.charge(start, LIVE_SNAPSHOT_INTERVAL));
        assert!(!cooldown.is_eligible(start + Duration::from_millis(999)));
        assert!(cooldown.is_eligible(start + LIVE_SNAPSHOT_INTERVAL));
        let failed_attempt: Instant = start + LIVE_SNAPSHOT_INTERVAL;
        assert!(cooldown.charge(failed_attempt, LIVE_SNAPSHOT_INTERVAL));
        assert!(!cooldown.is_eligible(failed_attempt + Duration::from_millis(999)));
        assert!(cooldown.is_eligible(failed_attempt + LIVE_SNAPSHOT_INTERVAL));
    }

    #[test]
    fn disconnected_and_full_local_receivers_are_best_effort_drops() {
        let (sender, receiver): (UnixDatagram, UnixDatagram) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        drop(receiver);
        let mut disconnected: PreparedLocalObservations = PreparedLocalObservations {
            socket: Some(sender),
            cooldown: LiveSnapshotCooldown::default(),
        };
        let start: Instant = Instant::now();
        assert_eq!(
            disconnected.try_send(start, NativeHttpSnapshot::default()),
            LiveSendOutcome::Dropped
        );

        let (sender, receiver): (UnixDatagram, UnixDatagram) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        let payload: [u8; 2 * 1024] = [b'x'; 2 * 1024];
        let mut filled: bool = false;
        // This bounded owning fixture requires its host queue to fill within
        // the stated sends; it is not a guarantee for arbitrary Unix hosts.
        for _attempt in 0..128 {
            match sender.send(&payload) {
                Ok(length) => assert_eq!(length, payload.len()),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    filled = true;
                    break;
                }
                Err(error) => panic!("unexpected local datagram error: {error}"),
            }
        }
        assert!(
            filled,
            "test environment prerequisite failed: Unix datagram peer queue did not fill within 128 x 2 KiB sends"
        );
        let mut full: PreparedLocalObservations = PreparedLocalObservations {
            socket: Some(sender),
            cooldown: LiveSnapshotCooldown::default(),
        };
        assert_eq!(
            full.try_send(start, NativeHttpSnapshot::default()),
            LiveSendOutcome::Dropped
        );
        drop(receiver);
    }

    #[test]
    fn successful_and_failed_sends_each_charge_one_attempt_window() {
        let (sender, receiver): (UnixDatagram, UnixDatagram) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut output: PreparedLocalObservations = PreparedLocalObservations {
            socket: Some(sender),
            cooldown: LiveSnapshotCooldown::default(),
        };
        let start: Instant = Instant::now();
        let snapshot: NativeHttpSnapshot = NativeHttpSnapshot::default();
        assert_eq!(output.try_send(start, snapshot), LiveSendOutcome::Sent);
        assert_eq!(
            output.try_send(start + Duration::from_millis(500), snapshot),
            LiveSendOutcome::Throttled
        );
        let mut payload: [u8; 2 * 1024] = [0; 2 * 1024];
        let received: usize = receiver.recv(&mut payload).unwrap();
        assert!(received > 0);
        assert_eq!(
            receiver.recv(&mut payload).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(
            output.try_send(start + LIVE_SNAPSHOT_INTERVAL, snapshot),
            LiveSendOutcome::Sent
        );
        assert!(receiver.recv(&mut payload).unwrap() > 0);

        let (sender, receiver): (UnixDatagram, UnixDatagram) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        drop(receiver);
        let mut disconnected: PreparedLocalObservations = PreparedLocalObservations {
            socket: Some(sender),
            cooldown: LiveSnapshotCooldown::default(),
        };
        assert_eq!(
            disconnected.try_send(start, snapshot),
            LiveSendOutcome::Dropped
        );
        assert_eq!(
            disconnected.try_send(start + Duration::from_millis(500), snapshot),
            LiveSendOutcome::Throttled
        );
        assert_eq!(
            disconnected.try_send(start + LIVE_SNAPSHOT_INTERVAL, snapshot),
            LiveSendOutcome::Dropped
        );
    }

    #[test]
    fn cooldown_overflow_permanently_disables_the_private_sender() {
        let (sender, receiver): (UnixDatagram, UnixDatagram) = UnixDatagram::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut output: PreparedLocalObservations = PreparedLocalObservations {
            socket: Some(sender),
            cooldown: LiveSnapshotCooldown::default(),
        };
        let start: Instant = Instant::now();
        assert!(start.checked_add(Duration::MAX).is_none());
        assert_eq!(
            output.try_send_with_interval(start, NativeHttpSnapshot::default(), Duration::MAX,),
            LiveSendOutcome::Disabled
        );
        assert!(!output.is_enabled());
        assert_eq!(
            output.try_send(
                start + LIVE_SNAPSHOT_INTERVAL,
                NativeHttpSnapshot::default()
            ),
            LiveSendOutcome::Disabled
        );
        let mut payload: [u8; 2 * 1024] = [0; 2 * 1024];
        assert_eq!(
            receiver.recv(&mut payload).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
}

#[cfg(all(test, not(unix)))]
mod nonunix_tests {
    use super::*;

    #[test]
    fn explicit_local_socket_option_refuses_on_non_unix_targets() {
        assert!(
            LocalObservationsPath::parse(Some("/tmp/native-observations.sock".into())).is_err()
        );
    }
}
