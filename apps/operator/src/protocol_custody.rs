//! DR-0264 Linux deployment ownership. No protocol or generic signing service.
#[cfg(target_os = "linux")]
mod linux;

pub(crate) fn run(
    worker: bool,
    tokens: Vec<std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        linux::run(worker, tokens)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (worker, tokens);
        Err("original ordered custody requires Linux".into())
    }
}

/// Separate complete certified FastVote deployment profile; no ordered IPC change.
pub(crate) fn run_certified(
    worker: bool,
    tokens: Vec<std::ffi::OsString>,
) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        linux::run_certified(worker, tokens)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (worker, tokens);
        Err("certified FastVote custody requires Linux".into())
    }
}

#[cfg(target_os = "linux")]
pub(crate) use linux::Worker;
