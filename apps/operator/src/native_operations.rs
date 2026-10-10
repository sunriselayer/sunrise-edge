//! One process-local stop/drain/summary owner for Native operator serving.
use native_http::{NativeBlockingExecutor, NativeHttpObservations, NativeStopReason};
use std::{
    future::Future,
    io::{self, Write},
    pin::Pin,
};

mod live_observations;
pub(crate) use live_observations::{
    LOCAL_OBSERVATIONS_SOCKET_FLAG, LocalObservationsPath, PreparedLocalObservations,
};

type StopFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub(crate) struct StopOwner {
    buffered: Option<io::Result<NativeStopReason>>,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(unix)]
    live_signal: Option<tokio::signal::unix::Signal>,
    live_ready: bool,
    live_observations: PreparedLocalObservations,
}

impl StopOwner {
    /// Call inside the owned Tokio runtime, before binding or announcing readiness.
    pub(crate) fn install(live_observations: PreparedLocalObservations) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{Signal, SignalKind, signal};
            let interrupt: Signal = signal(SignalKind::interrupt())?;
            let terminate: Signal = signal(SignalKind::terminate())?;
            // Opt-in only: Tokio's SIGUSR1 registration is process-wide and is
            // not restored when this stream or the stop owner is dropped.
            let live_signal: Option<Signal> = if live_observations.is_enabled() {
                Some(signal(SignalKind::user_defined1())?)
            } else {
                None
            };
            Ok(Self {
                buffered: None,
                interrupt,
                terminate,
                live_signal,
                live_ready: false,
                live_observations,
            })
        }
        #[cfg(not(unix))]
        {
            let _live_observations = live_observations;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Native orderly signal ownership requires Unix",
            ))
        }
    }

    /// Poll preserved listeners immediately before the status line. A ready
    /// notification/error is retained for the real close/join/drain owner.
    /// A signal arriving after this poll can still race printing; this does
    /// not promise an atomic relationship between OS delivery and stdout.
    pub(crate) fn stop_before_readiness(&mut self) -> bool {
        if self.buffered.is_some() {
            return true;
        }
        #[cfg(unix)]
        {
            let mut context: std::task::Context<'_> =
                std::task::Context::from_waker(std::task::Waker::noop());
            self.buffered = polled_signal_result(
                self.interrupt.poll_recv(&mut context),
                NativeStopReason::Sigint,
            )
            .or_else(|| {
                polled_signal_result(
                    self.terminate.poll_recv(&mut context),
                    NativeStopReason::Sigterm,
                )
            });
        }
        #[cfg(not(unix))]
        {
            self.buffered = Some(Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Native orderly signal ownership requires Unix",
            )));
        }
        self.buffered.is_some()
    }

    /// Enable opt-in snapshots only after the existing readiness line is flushed.
    pub(crate) fn readiness_announced(&mut self) {
        #[cfg(unix)]
        if let Some(live_signal) = self.live_signal.as_mut() {
            let mut context: std::task::Context<'_> =
                std::task::Context::from_waker(std::task::Waker::noop());
            match live_signal.poll_recv(&mut context) {
                std::task::Poll::Pending | std::task::Poll::Ready(Some(())) => {}
                std::task::Poll::Ready(None) => self.live_signal = None,
            }
        }
        self.live_ready = true;
    }

    async fn wait(mut self, observations: NativeHttpObservations) -> io::Result<NativeStopReason> {
        if let Some(result) = self.buffered.take() {
            return result;
        }
        #[cfg(unix)]
        {
            loop {
                if !self.live_observations.is_enabled() {
                    self.live_signal = None;
                }
                let now: std::time::Instant = std::time::Instant::now();
                let live_eligible: bool = self.live_observations.is_eligible(now);
                let live_enabled: bool = live_snapshot_enabled(
                    self.live_ready,
                    self.live_signal.is_some(),
                    self.live_observations.is_enabled(),
                );
                let event: WaitEvent = match self.live_signal.as_mut() {
                    Some(live_signal) if live_enabled && live_eligible => {
                        select_stop_or_live(
                            self.interrupt.recv(),
                            self.terminate.recv(),
                            live_signal.recv(),
                        )
                        .await
                    }
                    Some(_) if live_enabled => {
                        let deadline: std::time::Instant = match self
                            .live_observations
                            .next_eligible()
                        {
                            Some(deadline) => deadline,
                            None => {
                                self.live_signal = None;
                                continue;
                            }
                        };
                        tokio::select! {
                            biased;
                            received = self.interrupt.recv() => WaitEvent::Interrupt(received),
                            received = self.terminate.recv() => WaitEvent::Terminate(received),
                            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)) => WaitEvent::Cooldown,
                        }
                    }
                    Some(_) | None => tokio::select! {
                        biased;
                        received = self.interrupt.recv() => WaitEvent::Interrupt(received),
                        received = self.terminate.recv() => WaitEvent::Terminate(received),
                    },
                };
                match event {
                    WaitEvent::Interrupt(received) => {
                        return signal_result(received, NativeStopReason::Sigint);
                    }
                    WaitEvent::Terminate(received) => {
                        return signal_result(received, NativeStopReason::Sigterm);
                    }
                    WaitEvent::Live(received) => match live_notification_action(received) {
                        LiveNotificationAction::Snapshot => {
                            let attempted_at: std::time::Instant = std::time::Instant::now();
                            let _outcome = self
                                .live_observations
                                .try_send(attempted_at, observations.snapshot());
                        }
                        LiveNotificationAction::Disable => {
                            self.live_signal = None;
                        }
                    },
                    WaitEvent::Cooldown => {}
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _owner = &mut self;
            let _observations = &observations;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Native orderly signal ownership requires Unix",
            ))
        }
    }
}

#[cfg(unix)]
fn live_snapshot_enabled(ready: bool, signal_open: bool, socket_enabled: bool) -> bool {
    ready && signal_open && socket_enabled
}

#[cfg(unix)]
enum WaitEvent {
    Interrupt(Option<()>),
    Terminate(Option<()>),
    Live(Option<()>),
    Cooldown,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveNotificationAction {
    Snapshot,
    Disable,
}

#[cfg(unix)]
fn live_notification_action(received: Option<()>) -> LiveNotificationAction {
    match received {
        Some(()) => LiveNotificationAction::Snapshot,
        None => LiveNotificationAction::Disable,
    }
}

#[cfg(unix)]
async fn select_stop_or_live<I, T, L>(interrupt: I, terminate: T, live: L) -> WaitEvent
where
    I: Future<Output = Option<()>>,
    T: Future<Output = Option<()>>,
    L: Future<Output = Option<()>>,
{
    tokio::select! {
        biased;
        received = interrupt => WaitEvent::Interrupt(received),
        received = terminate => WaitEvent::Terminate(received),
        received = live => WaitEvent::Live(received),
    }
}

#[cfg(unix)]
fn polled_signal_result(
    received: std::task::Poll<Option<()>>,
    reason: NativeStopReason,
) -> Option<io::Result<NativeStopReason>> {
    match received {
        std::task::Poll::Pending => None,
        std::task::Poll::Ready(received) => Some(signal_result(received, reason)),
    }
}

#[cfg(unix)]
fn signal_result(received: Option<()>, reason: NativeStopReason) -> io::Result<NativeStopReason> {
    received.map(|()| reason).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::BrokenPipe,
            "Native stop signal stream closed",
        )
    })
}

/// Owns an entered serving lifecycle, including a buffered pre-readiness stop.
/// Installation/binding/startup-output refusals happen before this boundary and
/// retain their existing startup errors without a termination record. Every
/// entered lifecycle emits its one record only after connection and work drain.
pub(crate) async fn serve<R, F>(
    executor: NativeBlockingExecutor,
    stop: StopOwner,
    run: R,
) -> io::Result<()>
where
    R: FnOnce(StopFuture, NativeHttpObservations) -> F,
    F: Future<Output = io::Result<()>>,
{
    let observations: NativeHttpObservations = executor.observations();
    let stop_executor: NativeBlockingExecutor = executor.clone();
    let (sender, receiver) = tokio::sync::oneshot::channel::<io::Result<NativeStopReason>>();
    let shutdown_observations: NativeHttpObservations = observations.clone();
    let shutdown: StopFuture = Box::pin(async move {
        let result: io::Result<NativeStopReason> = stop.wait(shutdown_observations).await;
        stop_executor.close();
        let _sent = sender.send(result);
    });
    let served: io::Result<()> = run(shutdown, observations.clone()).await;
    executor.close();
    executor.wait_drained().await;
    let stopped: io::Result<NativeStopReason> = receiver.await.unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "Native stop owner did not complete",
        ))
    });
    let reason: NativeStopReason = match (&served, &stopped) {
        (Err(_), _) => NativeStopReason::ServeFailure,
        (Ok(()), Ok(reason)) => *reason,
        (Ok(()), Err(_)) => NativeStopReason::SignalFailure,
    };
    let summary: String = observations.snapshot().termination_summary(reason);
    // Fixed one-record output only after actual work completion. An I/O failure
    // propagates and cannot turn a signal/serve error into a clean success.
    let summary_result: io::Result<()> = io::stderr().lock().write_all(summary.as_bytes());
    served?;
    stopped?;
    summary_result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use native_http::{NODE_EVENT_MEDIA_TYPE, NODE_EVENT_PATH, NativeBlockingPolicy};
    use std::{num::NonZeroUsize, time::Duration};
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::oneshot,
        time::timeout,
    };

    const TEST_DEADLINE: Duration = Duration::from_secs(2);

    /// A real HTTP request against the public router with the retained executor.
    /// Creating the router precedes polling the supplied stop future. The
    /// bounded owning test future drives both client and server, so neither
    /// introduces a detached test server or outstanding synchronous job.
    async fn assert_closed_router_post(
        executor: NativeBlockingExecutor,
        shutdown: Option<StopFuture>,
    ) {
        let app = native_http::closed_event_router_with_executor(executor);
        if let Some(shutdown) = shutdown {
            shutdown.await;
        }
        let listener: TcpListener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address: std::net::SocketAddr = listener.local_addr().unwrap();
        let (sender, receiver): (oneshot::Sender<()>, oneshot::Receiver<()>) = oneshot::channel();
        let server = native_http::serve(listener, app, async move {
            receiver.await.unwrap();
        });
        let exchange = async move {
            let mut stream: TcpStream = TcpStream::connect(address).await.unwrap();
            let request: String = format!(
                "POST {NODE_EVENT_PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Type: {NODE_EVENT_MEDIA_TYPE}\r\nContent-Length: 3\r\nConnection: close\r\n\r\nabc"
            );
            stream.write_all(request.as_bytes()).await.unwrap();
            let mut response: Vec<u8> = Vec::new();
            (&mut stream)
                .take(1_025)
                .read_to_end(&mut response)
                .await
                .unwrap();
            sender.send(()).unwrap();
            response
        };
        let (served, response): (io::Result<()>, Vec<u8>) = tokio::join!(server, exchange);
        served.unwrap();
        assert!(
            response.len() <= 1_024,
            "bounded established refusal response"
        );
        assert!(response.starts_with(b"HTTP/1.1 503"));
        assert!(response.ends_with(b"\r\n\r\nblocking-admission-closed"));
    }

    #[tokio::test]
    async fn buffered_stop_closes_router_admission_before_serving_returns() {
        for signal_failure in [false, true] {
            let executor: NativeBlockingExecutor = NativeBlockingExecutor::new(
                NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()),
            );
            let probe_executor: NativeBlockingExecutor = executor.clone();
            let mut stop: StopOwner =
                StopOwner::install(PreparedLocalObservations::disabled()).unwrap();
            // Private buffered-result injection only; no OS signal is sent.
            stop.buffered = Some(if signal_failure {
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "buffered signal stream closed",
                ))
            } else {
                Ok(NativeStopReason::Sigterm)
            });
            assert!(
                stop.stop_before_readiness(),
                "buffered stop suppresses readiness"
            );
            assert!(
                stop.stop_before_readiness(),
                "readiness polling retains the stop result"
            );
            match stop.buffered.as_ref().unwrap() {
                Ok(reason) => {
                    assert!(!signal_failure);
                    assert_eq!(*reason, NativeStopReason::Sigterm);
                }
                Err(error) => {
                    assert!(signal_failure);
                    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                }
            }
            let result: io::Result<()> = timeout(
                TEST_DEADLINE,
                serve(
                    executor.clone(),
                    stop,
                    move |shutdown, _observations| async move {
                        // This POST completes inside the run future, before the
                        // host wrapper's fallback close after run returns. It must
                        // therefore observe closure by the actual shutdown future.
                        assert_closed_router_post(probe_executor, Some(shutdown)).await;
                        Ok::<(), io::Error>(())
                    },
                ),
            )
            .await
            .unwrap();
            if signal_failure {
                let error: io::Error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
                assert_eq!(error.to_string(), "buffered signal stream closed");
            } else {
                result.unwrap();
            }
            assert_eq!(executor.observations().snapshot().blocking_closed, 1);
            assert_eq!(executor.observations().snapshot().blocking_admitted, 0);
        }
    }

    #[tokio::test]
    async fn serving_failure_closes_admission_and_is_not_clean_stop() {
        let executor: NativeBlockingExecutor =
            NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()));
        let stop: StopOwner =
            StopOwner::install(PreparedLocalObservations::disabled()).unwrap();
        let error: io::Error = timeout(
            TEST_DEADLINE,
            serve(
                executor.clone(),
                stop,
                |shutdown, _observations| async move {
                    // The serving failure never polls the stop future. Dropping it
                    // closes the result channel; the wrapper must not wait forever
                    // or replace this error with a clean signal-stop result.
                    drop(shutdown);
                    Err::<(), io::Error>(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "test serving failure",
                    ))
                },
            ),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(error.to_string(), "test serving failure");
        timeout(
            TEST_DEADLINE,
            assert_closed_router_post(executor.clone(), None),
        )
        .await
        .unwrap();
        assert_eq!(executor.observations().snapshot().blocking_closed, 1);
        assert_eq!(executor.observations().snapshot().blocking_admitted, 0);
    }

    #[test]
    fn closed_signal_stream_is_an_error_not_clean_stop() {
        assert_eq!(
            signal_result(None, NativeStopReason::Sigterm)
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            signal_result(Some(()), NativeStopReason::Sigint).unwrap(),
            NativeStopReason::Sigint
        );
        assert_eq!(
            signal_result(Some(()), NativeStopReason::Sigterm).unwrap(),
            NativeStopReason::Sigterm
        );
        assert!(polled_signal_result(std::task::Poll::Pending, NativeStopReason::Sigint).is_none());
        assert_eq!(
            polled_signal_result(std::task::Poll::Ready(Some(())), NativeStopReason::Sigterm)
                .unwrap()
                .unwrap(),
            NativeStopReason::Sigterm
        );
        assert_eq!(
            polled_signal_result(std::task::Poll::Ready(None), NativeStopReason::Sigint)
                .unwrap()
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn live_signal_requires_readiness_and_open_opt_in_resources() {
        assert!(!live_snapshot_enabled(false, true, true));
        assert!(!live_snapshot_enabled(true, false, true));
        assert!(!live_snapshot_enabled(true, true, false));
        assert!(live_snapshot_enabled(true, true, true));
    }

    #[tokio::test]
    async fn stop_notifications_precede_live_under_load_and_closed_live_only_disables_sampling() {
        let (live_sender, mut live_receiver): (
            tokio::sync::mpsc::Sender<()>,
            tokio::sync::mpsc::Receiver<()>,
        ) = tokio::sync::mpsc::channel(8);
        for _notification in 0..8 {
            live_sender.try_send(()).unwrap();
        }
        let interrupt: std::future::Ready<Option<()>> = std::future::ready(Some(()));
        let terminate: std::future::Ready<Option<()>> = std::future::ready(Some(()));
        let live = live_receiver.recv();
        assert!(matches!(
            select_stop_or_live(interrupt, terminate, live).await,
            WaitEvent::Interrupt(Some(()))
        ));

        drop(live_receiver);
        drop(live_sender);
        let (live_sender, mut live_receiver): (
            tokio::sync::mpsc::Sender<()>,
            tokio::sync::mpsc::Receiver<()>,
        ) = tokio::sync::mpsc::channel(8);
        for _notification in 0..8 {
            live_sender.try_send(()).unwrap();
        }
        let interrupt: std::future::Pending<Option<()>> = std::future::pending();
        let terminate: std::future::Ready<Option<()>> = std::future::ready(Some(()));
        let live = live_receiver.recv();
        assert!(matches!(
            select_stop_or_live(interrupt, terminate, live).await,
            WaitEvent::Terminate(Some(()))
        ));
        drop(live_receiver);
        drop(live_sender);

        let interrupt: std::future::Pending<Option<()>> = std::future::pending();
        let terminate: std::future::Pending<Option<()>> = std::future::pending();
        let live: std::future::Ready<Option<()>> = std::future::ready(None);
        assert!(matches!(
            select_stop_or_live(interrupt, terminate, live).await,
            WaitEvent::Live(None)
        ));
        assert_eq!(
            live_notification_action(None),
            LiveNotificationAction::Disable
        );
        assert_eq!(
            live_notification_action(Some(())),
            LiveNotificationAction::Snapshot
        );
    }
}
