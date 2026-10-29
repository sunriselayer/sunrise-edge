use super::*;

/// Counts every runtime capability access, including discovery and clock access,
/// so refusal cannot accidentally acquire a lease or send before the oracle.
struct CountedRuntime<R> {
    inner: R,
    accesses: Arc<AtomicUsize>,
}

impl<R: Runtime> Runtime for CountedRuntime<R> {
    type State = R::State;
    type Blobs = R::Blobs;
    type NodeSigner = R::NodeSigner;
    type Network = R::Network;
    type Time = R::Time;
    type TaskScheduler = R::TaskScheduler;

    fn state_store(&self) -> &Self::State {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.state_store()
    }

    fn blob_store(&self) -> &Self::Blobs {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.blob_store()
    }

    fn signer(&self) -> &Self::NodeSigner {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.signer()
    }

    fn transport(&self) -> &Self::Network {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.transport()
    }

    fn clock(&self) -> &Self::Time {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.clock()
    }

    fn scheduler(&self) -> &Self::TaskScheduler {
        self.accesses.fetch_add(1, Ordering::SeqCst);
        self.inner.scheduler()
    }
}

#[derive(Clone, Copy, Debug)]
enum RecoveryLane {
    Indexed,
    Scanned,
}

async fn attempt_recovery(
    lane: RecoveryLane,
    executor: NativeBlockingExecutor,
    accesses: Arc<AtomicUsize>,
) -> bool {
    match lane {
        RecoveryLane::Indexed => {
            let runtime = Arc::new(CountedRuntime {
                inner: indexed_runtime(ScriptedIndexedStore::new(Vec::new(), Vec::new())),
                accesses,
            });
            let result: Result<NativeOutboxRecoveryReport, IndexedOutboxRecoveryError> =
                recover_indexed_outbox_once(
                    runtime,
                    indexed_authority(),
                    Arc::new(FixedIndexedIdentity),
                    executor,
                )
                .await;
            matches!(result, Err(IndexedOutboxRecoveryError::AdmissionClosed))
        }
        RecoveryLane::Scanned => {
            let runtime: Arc<CountedRuntime<MemoryRuntime>> = Arc::new(CountedRuntime {
                inner: MemoryRuntime::new(ValidatorId::new([0x44; 32])),
                accesses,
            });
            let result: Result<NativeOutboxRecoveryReport, NativeOutboxRecoveryError> =
                recover_outboxes_once(
                    runtime,
                    config(),
                    Arc::new(SequenceLeaseIds::default()),
                    executor,
                    None,
                    NonZeroUsize::new(1).unwrap(),
                )
                .await;
            matches!(result, Err(NativeOutboxRecoveryError::AdmissionClosed))
        }
    }
}

struct ReleaseBlockingThread(Arc<(Mutex<bool>, Condvar)>);

impl Drop for ReleaseBlockingThread {
    fn drop(&mut self) {
        let (ready, wake): &(Mutex<bool>, Condvar) = self.0.as_ref();
        *ready.lock().unwrap() = true;
        wake.notify_all();
    }
}

/// Exercises the actual public scheduler entry points, not a substitute work
/// closure. The independent blocker only saturates Tokio's one blocking thread.
#[test]
fn queued_recovery_refuses_after_stop_before_any_runtime_access() {
    for lane in [RecoveryLane::Indexed, RecoveryLane::Scanned] {
        let runtime: tokio::runtime::Runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .max_blocking_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let entered: Arc<Notify> = Arc::new(Notify::new());
            let signal: Arc<Notify> = Arc::clone(&entered);
            let release: Arc<(Mutex<bool>, Condvar)> =
                Arc::new((Mutex::new(false), Condvar::new()));
            let release_on_exit: ReleaseBlockingThread =
                ReleaseBlockingThread(Arc::clone(&release));
            let blocker = tokio::task::spawn_blocking(move || {
                signal.notify_one();
                let (ready, wake): &(Mutex<bool>, Condvar) = release.as_ref();
                let ready = ready.lock().unwrap();
                let (ready, result) = wake
                    .wait_timeout_while(ready, Duration::from_secs(10), |ready| !*ready)
                    .unwrap();
                assert!(
                    *ready && !result.timed_out(),
                    "bounded recovery fixture release"
                );
            });
            timeout(Duration::from_secs(2), entered.notified())
                .await
                .unwrap();

            let executor: NativeBlockingExecutor = NativeBlockingExecutor::new(
                NativeBlockingPolicy::new(NonZeroUsize::new(1).unwrap()),
            );
            let observations: NativeHttpObservations = executor.observations();
            let accesses: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
            let queued = tokio::spawn(attempt_recovery(
                lane,
                executor.clone(),
                Arc::clone(&accesses),
            ));
            timeout(Duration::from_secs(2), async {
                while observations.snapshot().blocking_admitted != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            assert_eq!(accesses.load(Ordering::SeqCst), 0);
            executor.close();

            // A new scheduler invocation still gets the original admission
            // error immediately; it neither queues nor accesses runtime.
            assert!(attempt_recovery(lane, executor.clone(), Arc::clone(&accesses)).await);
            assert_eq!(observations.snapshot().blocking_closed, 1);
            drop(release_on_exit);
            timeout(Duration::from_secs(2), blocker)
                .await
                .unwrap()
                .unwrap();
            assert!(
                timeout(Duration::from_secs(2), queued)
                    .await
                    .unwrap()
                    .unwrap(),
                "queued {lane:?} recovery must return AdmissionClosed"
            );
            assert_eq!(accesses.load(Ordering::SeqCst), 0);
            timeout(Duration::from_secs(2), executor.wait_drained())
                .await
                .unwrap();
            assert_eq!(observations.snapshot().blocking_admitted, 1);
            assert_eq!(observations.snapshot().blocking_closed, 1);
        });
    }
}
