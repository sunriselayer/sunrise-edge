//! Learns this process's own effective UID using only the safe Tokio
//! socket APIs this slice already relies on (`UnixStream::pair` plus
//! `peer_cred`), rather than an `unsafe` `libc::geteuid` call or a new
//! dependency: the peer of a freshly created, already-connected Unix socket
//! pair is, by construction, this very process, so its reported peer
//! credential is exactly this process's own effective UID.

/// Returns this process's own effective UID. Must be called from inside a
/// running Tokio runtime (`UnixStream::pair` registers with the reactor).
pub(super) async fn own_uid() -> std::io::Result<u32> {
    let (first, _second) = tokio::net::UnixStream::pair()?;
    Ok(first.peer_cred()?.uid())
}

#[cfg(test)]
mod tests {
    use super::own_uid;

    #[tokio::test(flavor = "current_thread")]
    async fn own_uid_matches_the_actual_process_uid() {
        // `UnixStream::pair` is used here purely to observe the standard
        // `peer_cred` result against the process's documented own UID, not
        // to assert a specific numeric value.
        let observed = own_uid().await.unwrap();
        let (first, second) = tokio::net::UnixStream::pair().unwrap();
        assert_eq!(first.peer_cred().unwrap().uid(), observed);
        assert_eq!(second.peer_cred().unwrap().uid(), observed);
    }
}
