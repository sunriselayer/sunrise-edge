//! Private controlled writer proofs. These are not real TLS peer evidence.
use crate::IoIdleTimeoutStream;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncWrite, AsyncWriteExt};

enum Writer {
    Ready,
    PendingFlush,
    PendingShutdown,
}
impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(*self, Self::PendingFlush) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(*self, Self::PendingShutdown) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
}
fn stream(writer: Writer) -> IoIdleTimeoutStream<Writer> {
    IoIdleTimeoutStream::new(
        writer,
        Duration::from_millis(40),
        Duration::from_millis(150),
    )
}
#[tokio::test]
async fn first_pending_flush_and_first_shutdown_are_bounded() {
    let mut flush: IoIdleTimeoutStream<Writer> = stream(Writer::PendingFlush);
    let error: io::Error = tokio::time::timeout(Duration::from_secs(2), flush.flush())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    let mut shutdown: IoIdleTimeoutStream<Writer> = stream(Writer::PendingShutdown);
    let error: io::Error = tokio::time::timeout(Duration::from_secs(2), shutdown.shutdown())
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}
#[tokio::test]
async fn ready_empty_pre_output_flush_does_not_time_application_work() {
    let mut ready: IoIdleTimeoutStream<Writer> = stream(Writer::Ready);
    ready.flush().await.unwrap();
    assert!(ready.write_total_deadline.is_none());
    assert!(ready.write_idle_deadline.is_none());
    tokio::time::sleep(Duration::from_millis(250)).await;
    ready.flush().await.unwrap();
    assert!(ready.write_total_deadline.is_none());
    ready
        .write_all(b"application completed later")
        .await
        .unwrap();
    ready.shutdown().await.unwrap();
}
#[tokio::test]
async fn output_progress_never_resets_the_total_deadline() {
    let mut ready: IoIdleTimeoutStream<Writer> = IoIdleTimeoutStream::new(
        Writer::Ready,
        Duration::from_millis(500),
        Duration::from_millis(150),
    );
    ready.write_all(b"begin").await.unwrap();
    let error: io::Error = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            if let Err(error) = ready.write_all(b"progress").await {
                break error;
            }
            if let Err(error) = ready.flush().await {
                break error;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(error.to_string().contains("total timeout"));
}
