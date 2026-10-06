//! The sole bounded chunk decoder, used by plaintext and TLS framing alike.
//! Wire metadata never changes response headers or application authority.

use super::{BoundedTransportIo, TransportError, is_http_token, is_safe_header_value};
use std::time::{Duration, Instant};

const MAX_LINE_BYTES: usize = 1024;
const BASE_METADATA_BYTES: usize = 16 * 1024;
const METADATA_PER_BODY_BYTE: usize = 8;

struct ChunkReader<'a, S: BoundedTransportIo> {
    stream: &'a mut S,
    pending: Vec<u8>,
    position: usize,
    deadline: Instant,
    read_timeout: Duration,
    metadata_bytes: usize,
    max_metadata_bytes: usize,
}

impl<S: BoundedTransportIo> ChunkReader<'_, S> {
    fn fill(&mut self) -> Result<(), TransportError> {
        if self.position < self.pending.len() {
            return Ok(());
        }
        let mut buffer: [u8; 4096] = [0; 4096];
        let read: usize = self
            .stream
            .read_once(&mut buffer, self.deadline, self.read_timeout)?;
        if read == 0 {
            return Err(TransportError::TruncatedChunkedResponse);
        }
        self.pending.clear();
        self.pending.extend_from_slice(&buffer[..read]);
        self.position = 0;
        Ok(())
    }

    fn metadata_byte(&mut self) -> Result<u8, TransportError> {
        // Do not perform another read once the framing budget is exhausted.
        if self.metadata_bytes == self.max_metadata_bytes {
            return Err(TransportError::ResponseFramingTooLarge {
                maximum: self.max_metadata_bytes,
            });
        }
        self.fill()?;
        let byte: u8 = self.pending[self.position];
        self.position += 1;
        self.metadata_bytes += 1;
        Ok(byte)
    }

    fn line(&mut self) -> Result<Vec<u8>, TransportError> {
        let mut line: Vec<u8> = Vec::new();
        loop {
            if line.len() + 2 > MAX_LINE_BYTES {
                return Err(TransportError::ResponseFramingTooLarge {
                    maximum: MAX_LINE_BYTES,
                });
            }
            let byte: u8 = self.metadata_byte()?;
            if byte == b'\r' {
                if self.metadata_byte()? != b'\n' {
                    return Err(TransportError::MalformedChunkedResponse);
                }
                return Ok(line);
            }
            if byte != b'\t' && !(0x20..=0x7e).contains(&byte) {
                return Err(TransportError::MalformedChunkedResponse);
            }
            line.push(byte);
        }
    }

    fn append_data(
        &mut self,
        body: &mut Vec<u8>,
        mut remaining: usize,
    ) -> Result<(), TransportError> {
        while remaining > 0 {
            self.fill()?;
            let take: usize = remaining.min(self.pending.len() - self.position);
            body.extend_from_slice(&self.pending[self.position..self.position + take]);
            self.position += take;
            remaining -= take;
        }
        if self.metadata_byte()? != b'\r' || self.metadata_byte()? != b'\n' {
            return Err(TransportError::MalformedChunkedResponse);
        }
        Ok(())
    }
}

pub(super) fn read_chunked<S: BoundedTransportIo>(
    stream: &mut S,
    pending: Vec<u8>,
    maximum: usize,
    deadline: Instant,
    read_timeout: Duration,
) -> Result<Vec<u8>, TransportError> {
    let max_metadata_bytes: usize = maximum
        .checked_mul(METADATA_PER_BODY_BYTE)
        .and_then(|value: usize| value.checked_add(BASE_METADATA_BYTES))
        .ok_or(TransportError::ResponseFramingBudgetOverflow)?;
    let mut reader: ChunkReader<'_, S> = ChunkReader {
        stream,
        pending,
        position: 0,
        deadline,
        read_timeout,
        metadata_bytes: 0,
        max_metadata_bytes,
    };
    let mut body: Vec<u8> = Vec::new();
    loop {
        let line: Vec<u8> = reader.line()?;
        let length: usize = parse_size(&line)?;
        if length == 0 {
            loop {
                let trailer: Vec<u8> = reader.line()?;
                if trailer.is_empty() {
                    break;
                }
                validate_trailer(&trailer)?;
            }
            if reader.position != reader.pending.len() {
                return Err(TransportError::TrailingResponseBytes);
            }
            return Ok(body);
        }
        // A fixed 4 KiB wire buffer can already contain prefetched data. No
        // body allocation or additional payload read precedes this check.
        if length > maximum - body.len() {
            return Err(TransportError::ResponseBodyTooLarge {
                declared: body.len().saturating_add(length),
                maximum,
            });
        }
        reader.append_data(&mut body, length)?;
    }
}

fn parse_size(line: &[u8]) -> Result<usize, TransportError> {
    let end: usize = line
        .iter()
        .position(|byte: &u8| *byte == b';')
        .unwrap_or(line.len());
    let digits: &[u8] = &line[..end];
    if digits.is_empty() || (end < line.len() && end + 1 == line.len()) {
        return Err(TransportError::MalformedChunkedResponse);
    }
    let mut size: usize = 0;
    for byte in digits {
        let value: usize = match byte {
            b'0'..=b'9' => usize::from(*byte - b'0'),
            b'a'..=b'f' => usize::from(*byte - b'a' + 10),
            b'A'..=b'F' => usize::from(*byte - b'A' + 10),
            _ => return Err(TransportError::MalformedChunkedResponse),
        };
        size = size
            .checked_mul(16)
            .and_then(|current: usize| current.checked_add(value))
            .ok_or(TransportError::MalformedChunkedResponse)?;
    }
    Ok(size)
}

fn validate_trailer(line: &[u8]) -> Result<(), TransportError> {
    let text: &str =
        std::str::from_utf8(line).map_err(|_| TransportError::MalformedChunkedResponse)?;
    let (name, value): (&str, &str) = text
        .split_once(':')
        .ok_or(TransportError::MalformedChunkedResponse)?;
    if !is_http_token(name) || !is_safe_header_value(value) {
        return Err(TransportError::MalformedChunkedResponse);
    }
    if [
        "content-length",
        "transfer-encoding",
        "content-type",
        "content-encoding",
        "connection",
        "trailer",
    ]
    .iter()
    .any(|forbidden: &&str| name.eq_ignore_ascii_case(forbidden))
    {
        return Err(TransportError::ForbiddenResponseTrailer);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
