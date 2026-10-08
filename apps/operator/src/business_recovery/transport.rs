//! Maintained age transport, opaque failures and the same-cursor C4 quotas.
#![forbid(unsafe_code)]

use super::{RecoveryError, RecoveryLimits};
use age::{Decryptor, Encryptor, x25519};
use sha2::{Digest, Sha256};
use std::{
    cell::Cell,
    io::{self, Read, Write},
    path::Path,
};
use sunrise_edge_client::immutable_archive::{
    ArchiveReadBudget, AttachedFilePolicy, AttachedRegularFile,
};
use zeroize::Zeroizing;

fn refused() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "recovery transport refused")
}

/// Owned by the caller, not the reader borrowed by age. No cursor/counter is
/// reset when the authenticated header constructor releases phase admission.
pub(super) struct CipherPhase(Cell<bool>);
impl CipherPhase {
    pub(super) fn header() -> Self {
        Self(Cell::new(false))
    }
    fn parsed_header(&self) {
        self.0.set(true);
    }
}

pub(super) struct CipherReader<'a, R> {
    pub(super) inner: R,
    phase: &'a CipherPhase,
    budget: &'a ArchiveReadBudget,
    header: u64,
    maximum: u64,
    observed: u64,
    physical_zeros: u64,
    failed: bool,
}
impl<'a, R: Read> CipherReader<'a, R> {
    pub(super) fn new(
        inner: R,
        phase: &'a CipherPhase,
        budget: &'a ArchiveReadBudget,
        limits: &RecoveryLimits,
    ) -> Self {
        Self {
            inner,
            phase,
            budget,
            header: limits.header_bytes,
            maximum: limits.ciphertext_bytes,
            observed: 0,
            physical_zeros: 0,
            failed: false,
        }
    }
    pub(super) fn observed(&self) -> u64 {
        self.observed
    }
    #[cfg(test)]
    pub(super) fn physical_zeros(&self) -> u64 {
        self.physical_zeros
    }
    pub(super) fn physical_eof(&mut self) -> Result<(), RecoveryError> {
        if !self.phase.0.get() {
            return Err(RecoveryError::Transport);
        }
        let mut probe: [u8; 1] = [0];
        if self
            .read(&mut probe)
            .map_err(|_| RecoveryError::Transport)?
            != 0
        {
            self.failed = true;
            return Err(RecoveryError::Transport);
        }
        Ok(())
    }
    fn fail<T>(&mut self) -> io::Result<T> {
        self.failed = true;
        Err(refused())
    }
}
impl<R: Read> Read for CipherReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.failed || self.budget.check().is_err() {
            return self.fail();
        }
        if bytes.is_empty() {
            return Ok(0);
        } // Never used as EOF evidence.
        let total: bool = self.phase.0.get();
        let limit: u64 = if total {
            self.maximum
        } else {
            self.header.min(self.maximum)
        };
        if self.observed >= limit {
            if !total || self.observed != limit {
                return self.fail();
            }
            // C4: the SAME unbuffered cursor is probed before age may report
            // final authentication. A cap is never a synthetic EOF.
            let mut probe: [u8; 1] = [0];
            return match self.inner.read(&mut probe) {
                Ok(0) => {
                    self.physical_zeros = match self.physical_zeros.checked_add(1) {
                        Some(value) => value,
                        None => return self.fail(),
                    };
                    if self.budget.check().is_err() {
                        return self.fail();
                    }
                    Ok(0)
                }
                Ok(1) => {
                    self.observed = match self.observed.checked_add(1) {
                        Some(value) => value,
                        None => return self.fail(),
                    };
                    self.fail()
                }
                Ok(_) | Err(_) => self.fail(),
            };
        }
        let remaining: u64 = limit - self.observed;
        let count: usize = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        match self.inner.read(&mut bytes[..count]) {
            Ok(read) if read <= count => {
                self.observed = match self
                    .observed
                    .checked_add(u64::try_from(read).map_err(|_| refused())?)
                {
                    Some(value) => value,
                    None => return self.fail(),
                };
                if read == 0 {
                    self.physical_zeros = match self.physical_zeros.checked_add(1) {
                        Some(value) => value,
                        None => return self.fail(),
                    };
                }
                if self.budget.check().is_err() {
                    return self.fail();
                }
                Ok(read)
            }
            Ok(_) | Err(_) => self.fail(),
        }
    }
}

/// Counts EVERY plaintext framing/body byte. At the cap a nonempty real
/// decoder probe still runs, permitting authenticated zero, never Take EOF.
pub(super) struct PlainReader<'a, R> {
    inner: R,
    budget: &'a ArchiveReadBudget,
    maximum: u64,
    observed: u64,
    failed: bool,
}
impl<'a, R: Read> PlainReader<'a, R> {
    pub(super) fn new(inner: R, maximum: u64, budget: &'a ArchiveReadBudget) -> Self {
        Self {
            inner,
            budget,
            maximum,
            observed: 0,
            failed: false,
        }
    }
    pub(super) fn observed(&self) -> u64 {
        self.observed
    }
    pub(super) fn authenticated_eof(&mut self) -> Result<(), RecoveryError> {
        let mut probe: [u8; 1] = [0];
        if self
            .read(&mut probe)
            .map_err(|_| RecoveryError::Transport)?
            != 0
        {
            return Err(RecoveryError::Transport);
        }
        Ok(())
    }
}
impl<R: Read> Read for PlainReader<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.failed || self.budget.check().is_err() {
            self.failed = true;
            return Err(refused());
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        let remaining: u64 = self.maximum.saturating_sub(self.observed);
        if remaining == 0 {
            let mut probe: [u8; 1] = [0];
            match self.inner.read(&mut probe) {
                Ok(0) => {
                    if self.budget.check().is_ok() {
                        return Ok(0);
                    }
                }
                Ok(1) => {
                    self.observed = self.observed.checked_add(1).ok_or_else(refused)?;
                }
                Ok(_) | Err(_) => {}
            }
            self.failed = true;
            return Err(refused());
        }
        let count: usize = bytes
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        match self.inner.read(&mut bytes[..count]) {
            Ok(read) if read <= count => {
                self.observed = self
                    .observed
                    .checked_add(u64::try_from(read).map_err(|_| refused())?)
                    .ok_or_else(refused)?;
                if self.budget.check().is_ok() {
                    return Ok(read);
                }
            }
            Ok(_) | Err(_) => {}
        }
        self.failed = true;
        Err(refused())
    }
}

pub(super) struct CipherWriter<'a, W> {
    inner: W,
    budget: &'a ArchiveReadBudget,
    maximum: u64,
    observed: u64,
    hash: Sha256,
    failed: bool,
}
impl<'a, W: Write> CipherWriter<'a, W> {
    pub(super) fn new(inner: W, budget: &'a ArchiveReadBudget, maximum: u64) -> Self {
        Self {
            inner,
            budget,
            maximum,
            observed: 0,
            hash: Sha256::new(),
            failed: false,
        }
    }
    pub(super) fn observation(self) -> (u64, [u8; 32]) {
        (self.observed, self.hash.finalize().into())
    }
}
impl<W: Write> Write for CipherWriter<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let requested: u64 = u64::try_from(bytes.len()).map_err(|_| refused())?;
        if self.failed
            || self.budget.check().is_err()
            || self
                .observed
                .checked_add(requested)
                .is_none_or(|value| value > self.maximum)
        {
            self.failed = true;
            return Err(refused());
        }
        match self.inner.write(bytes) {
            Ok(written) if written <= bytes.len() => {
                self.hash.update(&bytes[..written]);
                self.observed = self
                    .observed
                    .checked_add(u64::try_from(written).map_err(|_| refused())?)
                    .ok_or_else(refused)?;
                if self.budget.check().is_ok() {
                    return Ok(written);
                }
            }
            Ok(_) | Err(_) => {}
        }
        self.failed = true;
        Err(refused())
    }
    fn flush(&mut self) -> io::Result<()> {
        if self.failed
            || self.budget.check().is_err()
            || self.inner.flush().is_err()
            || self.budget.check().is_err()
        {
            self.failed = true;
            Err(refused())
        } else {
            Ok(())
        }
    }
}

pub(super) fn encryptor(recipient: &x25519::Recipient) -> Result<Encryptor, RecoveryError> {
    Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
        .map_err(|_| RecoveryError::Transport)
}

pub(super) fn decrypt<'a, 'b, R: Read>(
    reader: &'a mut CipherReader<'b, R>,
    phase: &CipherPhase,
    identity: &x25519::Identity,
) -> Result<age::stream::StreamReader<&'a mut CipherReader<'b, R>>, RecoveryError> {
    let decryptor: Decryptor<&'a mut CipherReader<'b, R>> =
        Decryptor::new(reader).map_err(|_| RecoveryError::Transport)?;
    if decryptor.is_scrypt() {
        return Err(RecoveryError::Transport);
    }
    phase.parsed_header();
    decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|_| RecoveryError::Transport)
}

pub(super) fn parse_recipient(value: &str) -> Result<x25519::Recipient, RecoveryError> {
    value
        .parse::<x25519::Recipient>()
        .map_err(|_| RecoveryError::InvalidInput)
}

pub(super) struct LoadedIdentity {
    pub(super) identity: x25519::Identity,
    file: AttachedRegularFile,
}
impl LoadedIdentity {
    pub(super) fn ensure_attached(&self) -> Result<(), RecoveryError> {
        self.file
            .ensure_attached()
            .map_err(|_| RecoveryError::Attachment)
    }
}

pub(super) fn read_identity(
    path: &Path,
    recipient: &x25519::Recipient,
    budget: &ArchiveReadBudget,
) -> Result<LoadedIdentity, RecoveryError> {
    let uid: u32 = effective_uid()?;
    let mut file: AttachedRegularFile = AttachedRegularFile::open(
        path,
        1025,
        budget,
        AttachedFilePolicy::private_identity(uid),
    )
    .map_err(|_| RecoveryError::InvalidInput)?;
    let mut bytes: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(1025));
    let mut buffer: Zeroizing<[u8; 128]> = Zeroizing::new([0; 128]);
    loop {
        let left: usize = 1025usize
            .checked_sub(bytes.len())
            .ok_or(RecoveryError::InvalidInput)?;
        if left == 0 {
            return Err(RecoveryError::InvalidInput);
        }
        let count: usize = left.min(buffer.len());
        let read: usize = file
            .read(&mut buffer[..count])
            .map_err(|_| RecoveryError::InvalidInput)?;
        if read == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..read]);
        if bytes.len() > 1024 {
            return Err(RecoveryError::InvalidInput);
        }
    }
    file.ensure_attached()
        .map_err(|_| RecoveryError::Attachment)?;
    let text: &str = std::str::from_utf8(&bytes).map_err(|_| RecoveryError::InvalidInput)?;
    let line: &str = text.strip_suffix('\n').unwrap_or(text);
    if line.is_empty() || line.contains('\n') || line.contains('\r') {
        return Err(RecoveryError::InvalidInput);
    }
    let identity: x25519::Identity = line.parse().map_err(|_| RecoveryError::InvalidInput)?;
    if identity.to_public() != *recipient {
        return Err(RecoveryError::InvalidInput);
    }
    budget.check().map_err(|_| RecoveryError::Quota)?;
    Ok(LoadedIdentity { identity, file })
}

#[cfg(target_os = "linux")]
pub(super) fn effective_uid() -> Result<u32, RecoveryError> {
    // Safe, bounded process-self metadata, not manager env, credentials or a
    // libc call requiring unsafe. Linux procfs Uid reports the effective uid.
    let file: std::fs::File =
        std::fs::File::open("/proc/self/status").map_err(|_| RecoveryError::Unsupported)?;
    let mut bytes: Vec<u8> = Vec::new();
    file.take(16_385)
        .read_to_end(&mut bytes)
        .map_err(|_| RecoveryError::Unsupported)?;
    if bytes.len() > 16_384 {
        return Err(RecoveryError::Unsupported);
    }
    let status: &str = std::str::from_utf8(&bytes).map_err(|_| RecoveryError::Unsupported)?;
    let value: &str = status
        .lines()
        .find_map(|line: &str| line.strip_prefix("Uid:"))
        .ok_or(RecoveryError::Unsupported)?;
    let mut values = value.split_ascii_whitespace();
    let _: u32 = values
        .next()
        .ok_or(RecoveryError::Unsupported)?
        .parse()
        .map_err(|_| RecoveryError::Unsupported)?;
    values
        .next()
        .ok_or(RecoveryError::Unsupported)?
        .parse()
        .map_err(|_| RecoveryError::Unsupported)
}
#[cfg(not(target_os = "linux"))]
pub(super) fn effective_uid() -> Result<u32, RecoveryError> {
    Err(RecoveryError::Unsupported)
}
