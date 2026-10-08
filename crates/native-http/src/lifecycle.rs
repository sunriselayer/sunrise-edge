//! Actual blocking-job ownership, independent of saturating observations.
use crate::NativeHttpObservations;
use std::sync::{Arc, Mutex};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore, TryAcquireError};

#[derive(Debug, Default)]
struct State {
    closed: bool,
    outstanding: usize,
}

#[derive(Debug, Default)]
pub(crate) struct BlockingLifecycle {
    state: Mutex<State>,
    drained: Notify,
}

impl BlockingLifecycle {
    pub(crate) fn close(&self, permits: &Semaphore) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        permits.close();
    }

    pub(crate) fn acquire(
        self: &Arc<Self>,
        permits: &Arc<Semaphore>,
        observations: &NativeHttpObservations,
    ) -> Result<BlockingPermit, TryAcquireError> {
        // Acquisition, registration and close have one synchronization boundary.
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed {
            return Err(TryAcquireError::Closed);
        }
        let permit: OwnedSemaphorePermit = Arc::clone(permits).try_acquire_owned()?;
        // Each outstanding entry owns one permit; semaphore capacity bounds this
        // exact lifecycle value. It must never use a saturating telemetry count.
        state.outstanding = match state.outstanding.checked_add(1) {
            Some(outstanding) => outstanding,
            None => return Err(TryAcquireError::NoPermits),
        };
        Ok(BlockingPermit {
            permit: Some(permit),
            lifecycle: Arc::clone(self),
            observations: observations.clone(),
        })
    }

    pub(crate) async fn wait_drained(&self) {
        loop {
            let notified = self.drained.notified();
            tokio::pin!(notified);
            // Register before checking zero, including for multiple waiters.
            notified.as_mut().enable();
            if self
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .outstanding
                == 0
            {
                return;
            }
            notified.await;
        }
    }
}

#[derive(Debug)]
pub(crate) struct BlockingPermit {
    permit: Option<OwnedSemaphorePermit>,
    lifecycle: Arc<BlockingLifecycle>,
    observations: NativeHttpObservations,
}

impl Drop for BlockingPermit {
    fn drop(&mut self) {
        if std::thread::panicking() {
            self.observations.0.blocking_panics.increment();
        }
        let mut state = self
            .lifecycle
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Release capacity before publishing completion under the same lock.
        drop(self.permit.take());
        state.outstanding -= 1;
        if state.outstanding == 0 {
            self.lifecycle.drained.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeBlockingExecutor, NativeBlockingPolicy};
    use std::{
        num::NonZeroUsize,
        sync::{Barrier, Condvar},
        time::Duration,
    };

    fn executor() -> NativeBlockingExecutor {
        NativeBlockingExecutor::new(NativeBlockingPolicy::new(NonZeroUsize::new(2).unwrap()))
    }

    #[tokio::test]
    async fn close_races_acquire_without_untracked_work() {
        for _round in 0..64 {
            let executor: NativeBlockingExecutor = executor();
            let barrier: Arc<Barrier> = Arc::new(Barrier::new(2));
            let acquire_executor: NativeBlockingExecutor = executor.clone();
            let acquire_barrier: Arc<Barrier> = Arc::clone(&barrier);
            let acquire = std::thread::spawn(move || {
                acquire_barrier.wait();
                acquire_executor.try_acquire()
            });
            barrier.wait();
            executor.close();
            let result: Result<BlockingPermit, TryAcquireError> = acquire.join().unwrap();
            assert!(matches!(
                executor.try_acquire(),
                Err(TryAcquireError::Closed)
            ));
            if let Ok(permit) = result {
                assert!(
                    tokio::time::timeout(Duration::from_millis(5), executor.wait_drained())
                        .await
                        .is_err()
                );
                drop(permit);
            }
            tokio::time::timeout(Duration::from_secs(2), executor.wait_drained())
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn pre_spawn_release_and_multiple_waiters_do_not_leak() {
        let executor: NativeBlockingExecutor = executor();
        let permit: BlockingPermit = executor.try_acquire().unwrap();
        executor.close();
        let first = executor.wait_drained();
        let second = executor.wait_drained();
        tokio::pin!(first, second);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut first)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut second)
                .await
                .is_err()
        );
        drop(permit); // A pre-spawn refusal releases tracking just like closure completion.
        tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(first, second);
        })
        .await
        .unwrap();
    }

    struct Release(Arc<(Mutex<bool>, Condvar)>);
    impl Drop for Release {
        fn drop(&mut self) {
            let (ready, wake): &(Mutex<bool>, Condvar) = &self.0;
            *ready.lock().unwrap() = true;
            wake.notify_all();
        }
    }

    #[test]
    fn queued_detached_and_unwinding_jobs_keep_drain_owned() {
        let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let released: Arc<(Mutex<bool>, Condvar)> = Arc::new((Mutex::new(false), Condvar::new()));
        let cleanup: Release = Release(Arc::clone(&released));
        runtime.block_on(async {
            let executor: NativeBlockingExecutor = executor();
            let (started, entered) = tokio::sync::oneshot::channel::<()>();
            let first_permit: BlockingPermit = executor.try_acquire().unwrap();
            let first = tokio::task::spawn_blocking(move || {
                let _permit: BlockingPermit = first_permit;
                started.send(()).unwrap();
                let (ready, wake): &(Mutex<bool>, Condvar) = &released;
                let mut ready = ready.lock().unwrap();
                while !*ready {
                    ready = wake.wait(ready).unwrap();
                }
            });
            entered.await.unwrap();
            let second_permit: BlockingPermit = executor.try_acquire().unwrap();
            let (queued_started, queued_entered) = tokio::sync::oneshot::channel::<()>();
            let second = tokio::task::spawn_blocking(move || {
                let _permit: BlockingPermit = second_permit;
                queued_started.send(()).unwrap();
                panic!("private unwind control");
            });
            drop(first); // A dropped HTTP waiter cannot detach lifecycle tracking.
            executor.close();
            let mut queued_entered = queued_entered;
            assert_eq!(
                queued_entered.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            );
            assert!(
                tokio::time::timeout(Duration::from_millis(20), executor.wait_drained())
                    .await
                    .is_err()
            );
            drop(cleanup);
            queued_entered.await.unwrap();
            assert!(second.await.unwrap_err().is_panic());
            tokio::time::timeout(Duration::from_secs(2), executor.wait_drained())
                .await
                .unwrap();
            assert_eq!(executor.observations().snapshot().blocking_panics, 1);
        });
    }
}
