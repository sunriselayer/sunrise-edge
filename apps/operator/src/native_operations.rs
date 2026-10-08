//! One process-local stop/drain/summary owner for Native operator serving.
use native_http::{NativeBlockingExecutor, NativeHttpObservations, NativeStopReason};
use std::{future::Future, io::{self, Write}, pin::Pin};

type StopFuture = Pin<Box<dyn Future<Output = ()> + Send>>;

pub(crate) struct StopOwner {
    buffered: Option<io::Result<NativeStopReason>>,
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
}

impl StopOwner {
    /// Call inside the owned Tokio runtime, before binding or announcing readiness.
    pub(crate) fn install() -> io::Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{Signal, SignalKind, signal};
            let interrupt: Signal = signal(SignalKind::interrupt())?;
            let terminate: Signal = signal(SignalKind::terminate())?;
            Ok(Self { buffered: None, interrupt, terminate })
        }
        #[cfg(not(unix))]
        {
            Err(io::Error::new(io::ErrorKind::Unsupported,
                "Native orderly signal ownership requires Unix"))
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
            self.buffered = polled_signal_result(self.interrupt.poll_recv(&mut context), NativeStopReason::Sigint)
                .or_else(|| polled_signal_result(self.terminate.poll_recv(&mut context), NativeStopReason::Sigterm));
        }
        #[cfg(not(unix))]
        {
            self.buffered = Some(Err(io::Error::new(io::ErrorKind::Unsupported,
                "Native orderly signal ownership requires Unix")));
        }
        self.buffered.is_some()
    }

    async fn wait(mut self) -> io::Result<NativeStopReason> {
        if let Some(result) = self.buffered.take() {
            return result;
        }
        #[cfg(unix)]
        {
            tokio::select! {
                biased;
                received = self.interrupt.recv() => signal_result(received, NativeStopReason::Sigint),
                received = self.terminate.recv() => signal_result(received, NativeStopReason::Sigterm),
            }
        }
        #[cfg(not(unix))]
        {
            let _owner = &mut self;
            Err(io::Error::new(io::ErrorKind::Unsupported,
                "Native orderly signal ownership requires Unix"))
        }
    }
}

#[cfg(unix)]
fn polled_signal_result(received: std::task::Poll<Option<()>>, reason: NativeStopReason)
    -> Option<io::Result<NativeStopReason>> {
    match received {
        std::task::Poll::Pending => None,
        std::task::Poll::Ready(received) => Some(signal_result(received, reason)),
    }
}

#[cfg(unix)]
fn signal_result(received: Option<()>, reason: NativeStopReason) -> io::Result<NativeStopReason> {
    received.map(|()| reason).ok_or_else(||
        io::Error::new(io::ErrorKind::BrokenPipe, "Native stop signal stream closed"))
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
    let shutdown: StopFuture = Box::pin(async move {
        let result: io::Result<NativeStopReason> = stop.wait().await;
        stop_executor.close();
        let _sent = sender.send(result);
    });
    let served: io::Result<()> = run(shutdown, observations.clone()).await;
    executor.close();
    executor.wait_drained().await;
    let stopped: io::Result<NativeStopReason> = receiver.await.unwrap_or_else(|_| {
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "Native stop owner did not complete"))
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
    use native_http::{NativeBlockingPolicy, NODE_EVENT_MEDIA_TYPE, NODE_EVENT_PATH};
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
            (&mut stream).take(1_025).read_to_end(&mut response).await.unwrap();
            sender.send(()).unwrap();
            response
        };
        let (served, response): (io::Result<()>, Vec<u8>) = tokio::join!(server, exchange);
        served.unwrap();
        assert!(response.len() <= 1_024, "bounded established refusal response");
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
            let mut stop: StopOwner = StopOwner::install().unwrap();
            // Private buffered-result injection only; no OS signal is sent.
            stop.buffered = Some(if signal_failure {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "buffered signal stream closed"))
            } else {
                Ok(NativeStopReason::Sigterm)
            });
            assert!(stop.stop_before_readiness(), "buffered stop suppresses readiness");
            assert!(stop.stop_before_readiness(), "readiness polling retains the stop result");
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
                serve(executor.clone(), stop, move |shutdown, _observations| async move {
                    // This POST completes inside the run future, before the
                    // host wrapper's fallback close after run returns. It must
                    // therefore observe closure by the actual shutdown future.
                    assert_closed_router_post(probe_executor, Some(shutdown)).await;
                    Ok::<(), io::Error>(())
                }),
            ).await.unwrap();
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
        let executor: NativeBlockingExecutor = NativeBlockingExecutor::new(
            NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()),
        );
        let stop: StopOwner = StopOwner::install().unwrap();
        let error: io::Error = timeout(
            TEST_DEADLINE,
            serve(executor.clone(), stop, |shutdown, _observations| async move {
                // The serving failure never polls the stop future. Dropping it
                // closes the result channel; the wrapper must not wait forever
                // or replace this error with a clean signal-stop result.
                drop(shutdown);
                Err::<(), io::Error>(io::Error::new(io::ErrorKind::ConnectionAborted, "test serving failure"))
            }),
        ).await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        assert_eq!(error.to_string(), "test serving failure");
        timeout(TEST_DEADLINE, assert_closed_router_post(executor.clone(), None)).await.unwrap();
        assert_eq!(executor.observations().snapshot().blocking_closed, 1);
        assert_eq!(executor.observations().snapshot().blocking_admitted, 0);
    }

    #[test]
    fn closed_signal_stream_is_an_error_not_clean_stop() {
        assert_eq!(signal_result(None, NativeStopReason::Sigterm).unwrap_err().kind(),
            io::ErrorKind::BrokenPipe);
        assert_eq!(signal_result(Some(()), NativeStopReason::Sigint).unwrap(), NativeStopReason::Sigint);
        assert_eq!(signal_result(Some(()), NativeStopReason::Sigterm).unwrap(), NativeStopReason::Sigterm);
        assert!(polled_signal_result(std::task::Poll::Pending, NativeStopReason::Sigint).is_none());
        assert_eq!(polled_signal_result(std::task::Poll::Ready(Some(())), NativeStopReason::Sigterm)
            .unwrap().unwrap(), NativeStopReason::Sigterm);
        assert_eq!(polled_signal_result(std::task::Poll::Ready(None), NativeStopReason::Sigint)
            .unwrap().unwrap_err().kind(), io::ErrorKind::BrokenPipe);
    }
}
