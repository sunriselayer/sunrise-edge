//! Bounded input reads with caller-owned oversize and CLI error classification.

use std::{
    fs::File,
    io::{self, Read},
};

/// Read at most one byte beyond the accepted size so callers can reject an
/// oversized input while retaining their own error variant and message.
pub(super) fn read_for_size_check(path: &str, maximum: usize) -> io::Result<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    File::open(path)?
        .take((maximum + 1) as u64)
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}
