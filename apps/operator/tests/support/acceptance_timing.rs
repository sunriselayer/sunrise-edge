//! Test-private, best-effort observations of genuine acceptance work.
//! A completed span is not a successful test, proof or protocol clock.

use protocol_types::Epoch;
use std::io::{self, Write};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
pub(crate) enum Stage {
    InitialReadiness,
    CompiledSeal,
    InitialSeal,
    FirstSuccessor,
    RecurringEpoch,
    FreezeDrain,
    HistoryCut,
    CutImportReadiness,
    OrderedSeal,
    HistorySeal,
    SuccessorActivation,
    FourthHostRestart,
    TerminalUnlock,
}

impl Stage {
    const fn label(self) -> &'static str {
        match self {
            Self::InitialReadiness => "initial-readiness",
            Self::CompiledSeal => "compiled-seal",
            Self::InitialSeal => "initial-seal",
            Self::FirstSuccessor => "first-successor",
            Self::RecurringEpoch => "recurring-epoch",
            Self::FreezeDrain => "freeze-drain",
            Self::HistoryCut => "history-cut",
            Self::CutImportReadiness => "cut-import-readiness",
            Self::OrderedSeal => "ordered-seal",
            Self::HistorySeal => "history-seal",
            Self::SuccessorActivation => "successor-activation",
            Self::FourthHostRestart => "fourth-host-restart",
            Self::TerminalUnlock => "terminal-unlock",
        }
    }
}

pub(crate) struct AcceptanceSpan<W: Write = io::Stderr> {
    stage: Stage,
    epoch: Option<Epoch>,
    started: Instant,
    writer: W,
}

impl AcceptanceSpan<io::Stderr> {
    pub(crate) fn start(stage: Stage, epoch: Option<Epoch>) -> Self {
        Self::with_writer(stage, epoch, io::stderr())
    }
}

impl<W: Write> AcceptanceSpan<W> {
    fn with_writer(stage: Stage, epoch: Option<Epoch>, writer: W) -> Self {
        let mut span: Self = Self {
            stage,
            epoch,
            started: Instant::now(),
            writer,
        };
        span.observe("start", Duration::ZERO);
        span
    }

    fn observe(&mut self, observation: &'static str, elapsed: Duration) {
        // Only closed stage labels, actual public epochs and elapsed time enter
        // the record. Never include a path, command, key, request or artifact.
        if let Some(epoch) = self.epoch {
            let _ignored: io::Result<()> = writeln!(
                self.writer,
                "[acceptance-timing] stage={} epoch={} observation={} elapsed_ms={}",
                self.stage.label(),
                epoch.get(),
                observation,
                elapsed.as_millis()
            );
        } else {
            let _ignored: io::Result<()> = writeln!(
                self.writer,
                "[acceptance-timing] stage={} epoch=- observation={} elapsed_ms={}",
                self.stage.label(),
                observation,
                elapsed.as_millis()
            );
        }
    }
}

impl<W: Write> Drop for AcceptanceSpan<W> {
    fn drop(&mut self) {
        let observation: &'static str = if std::thread::panicking() {
            "unwind"
        } else {
            "end"
        };
        self.observe(observation, self.started.elapsed());
    }
}

#[cfg(test)]
mod tests {
    use super::{AcceptanceSpan, Stage};
    use protocol_types::Epoch;
    use std::cell::RefCell;
    use std::io::{self, Write};
    use std::rc::Rc;
    use std::time::Duration;

    #[derive(Clone)]
    struct Capture(Rc<RefCell<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.borrow_mut().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn records_only_closed_stage_epoch_and_monotonic_duration() {
        let captured: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let mut span: AcceptanceSpan<Capture> = AcceptanceSpan::with_writer(
            Stage::HistoryCut,
            Some(Epoch::new(7)),
            Capture(Rc::clone(&captured)),
        );
        span.observe("end", Duration::from_millis(1234));
        assert_eq!(
            captured.borrow().as_slice(),
            b"[acceptance-timing] stage=history-cut epoch=7 observation=start elapsed_ms=0\n\
[acceptance-timing] stage=history-cut epoch=7 observation=end elapsed_ms=1234\n"
        );
        drop(span);
        let lines: String = String::from_utf8(captured.borrow().clone()).unwrap();
        assert_eq!(lines.lines().count(), 3);
        assert!(lines.lines().last().unwrap().starts_with(
            "[acceptance-timing] stage=history-cut epoch=7 observation=end elapsed_ms="
        ));
        assert!(!lines.contains("passed"));
    }

    #[test]
    fn unavailable_epoch_is_not_an_invented_epoch_zero() {
        let captured: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let span: AcceptanceSpan<Capture> = AcceptanceSpan::with_writer(
            Stage::InitialReadiness,
            None,
            Capture(Rc::clone(&captured)),
        );
        assert_eq!(
            captured.borrow().as_slice(),
            b"[acceptance-timing] stage=initial-readiness epoch=- observation=start elapsed_ms=0\n"
        );
        drop(span);
    }

    #[test]
    fn write_failure_never_becomes_acceptance_failure() {
        struct Unavailable;

        impl Write for Unavailable {
            fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }

            fn flush(&mut self) -> io::Result<()> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
        }

        let mut span: AcceptanceSpan<Unavailable> =
            AcceptanceSpan::with_writer(Stage::HistorySeal, None, Unavailable);
        span.observe("end", Duration::from_millis(5));
        drop(span);
    }

    #[test]
    fn panic_unwind_is_never_reported_as_a_completed_span() {
        let captured: Rc<RefCell<Vec<u8>>> = Rc::new(RefCell::new(Vec::new()));
        let result: std::thread::Result<()> =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _span: AcceptanceSpan<Capture> = AcceptanceSpan::with_writer(
                    Stage::RecurringEpoch,
                    Some(Epoch::new(3)),
                    Capture(Rc::clone(&captured)),
                );
                panic!("genuine assertion failure");
            }));
        assert!(result.is_err());
        let lines: String = String::from_utf8(captured.borrow().clone()).unwrap();
        assert_eq!(lines.lines().count(), 2);
        assert!(lines.lines().last().unwrap().starts_with(
            "[acceptance-timing] stage=recurring-epoch epoch=3 observation=unwind elapsed_ms="
        ));
        assert!(!lines.contains("observation=end"));
        assert!(!lines.contains("passed"));
    }
}
