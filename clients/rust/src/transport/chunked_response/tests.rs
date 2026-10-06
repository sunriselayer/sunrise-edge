use super::super::{BoundedTransportIo, TransportError, WireResponse, read_response};
use std::collections::VecDeque;
use std::io::{Error, ErrorKind};
use std::time::{Duration, Instant};

struct ScriptedIo {
    chunks: VecDeque<Vec<u8>>,
    deadlines: Vec<Instant>,
    fail_at: Option<usize>,
    held_open: bool,
}

impl BoundedTransportIo for ScriptedIo {
    fn write_once(&mut self, _: &[u8], _: Instant, _: Duration) -> Result<usize, TransportError> {
        panic!("response tests do not write")
    }

    fn flush_io(&mut self, _: Instant, _: Duration) -> Result<(), TransportError> {
        panic!("response tests do not flush")
    }

    fn read_once(
        &mut self,
        buffer: &mut [u8],
        deadline: Instant,
        _: Duration,
    ) -> Result<usize, TransportError> {
        self.deadlines.push(deadline);
        if self.fail_at == Some(self.deadlines.len()) {
            return Err(TransportError::RequestDeadlineExceeded);
        }
        let Some(next) = self.chunks.front_mut() else {
            return if self.held_open {
                Err(TransportError::Read(Error::from(ErrorKind::TimedOut)))
            } else {
                Ok(0)
            };
        };
        let take: usize = next.len().min(buffer.len());
        buffer[..take].copy_from_slice(&next[..take]);
        next.drain(..take);
        if next.is_empty() {
            self.chunks.pop_front();
        }
        Ok(take)
    }
}

fn wire(headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes: Vec<u8> = format!("HTTP/1.1 200 OK\r\n{headers}\r\n").into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

fn run(
    chunks: Vec<Vec<u8>>,
    maximum: usize,
    fail_at: Option<usize>,
    held_open: bool,
) -> Result<WireResponse, TransportError> {
    let mut io: ScriptedIo = ScriptedIo {
        chunks: chunks.into(),
        deadlines: Vec::new(),
        fail_at,
        held_open,
    };
    let deadline: Instant = Instant::now() + Duration::from_secs(30);
    let result: Result<WireResponse, TransportError> =
        read_response(&mut io, 8192, maximum, deadline, Duration::from_secs(1));
    assert!(!io.deadlines.is_empty());
    assert!(
        io.deadlines
            .iter()
            .all(|observed: &Instant| *observed == deadline)
    );
    result
}

fn decode(body: &[u8], maximum: usize) -> Result<WireResponse, TransportError> {
    run(
        vec![wire("Transfer-Encoding: chunked\r\n", body)],
        maximum,
        None,
        false,
    )
}

#[test]
fn every_wire_split_and_single_byte_fragmentation_have_independent_literal_result() {
    let bytes: Vec<u8> = wire(
        "Transfer-Encoding: ChUnKeD\r\nContent-Type: application/example\r\n",
        b"2;ignored=yes\r\nhe\r\n3\r\nllo\r\n0\r\nX-Test: benign\r\n\r\n",
    );
    for boundary in 1..bytes.len() {
        let result: WireResponse = run(
            vec![bytes[..boundary].to_vec(), bytes[boundary..].to_vec()],
            5,
            None,
            false,
        )
        .unwrap();
        assert_eq!(result.body, b"hello", "boundary {boundary}");
        assert_eq!(result.content_type.as_deref(), Some("application/example"));
    }
    let chunks: Vec<Vec<u8>> = bytes.iter().map(|byte: &u8| vec![*byte]).collect();
    assert_eq!(run(chunks, 5, None, false).unwrap().body, b"hello");
    assert!(decode(b"0\r\n\r\n", 1).unwrap().body.is_empty());
}

#[test]
fn incomplete_delimiters_never_release_even_an_already_valid_body_prefix() {
    for body in [
        b"5\r\nhello".as_slice(),
        b"5\r\nhello\r".as_slice(),
        b"5\r\nhello\r\n".as_slice(),
        b"5\r\nhello\r\n0\r\n".as_slice(),
        b"0\r\nX-Test: ignored\r\n".as_slice(),
        b"0\r\n\r".as_slice(),
    ] {
        assert!(matches!(
            decode(body, 10),
            Err(TransportError::TruncatedChunkedResponse)
        ));
    }
}

#[test]
fn malformed_hex_controls_crlf_and_overflow_are_closed() {
    for body in [
        b"\r\n".as_slice(),
        b"+1\r\na\r\n0\r\n\r\n".as_slice(),
        b"g\r\n".as_slice(),
        b"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF\r\n".as_slice(),
        b"1\n".as_slice(),
        b"1\rx".as_slice(),
        b"1;bad\x01\r\n".as_slice(),
        b"1;\r\na\r\n0\r\n\r\n".as_slice(),
        b"1\r\na\n0\r\n\r\n".as_slice(),
        b"0\r\nX-Test: bad\n\r\n".as_slice(),
        b"0\r\n\n".as_slice(),
        b"0\r\n Bad: folded\r\n\r\n".as_slice(),
    ] {
        assert!(
            matches!(
                decode(body, 10),
                Err(TransportError::MalformedChunkedResponse)
            ),
            "{body:?}"
        );
    }
}

#[test]
fn declared_and_running_decoded_bounds_precede_additional_payload_reads() {
    let bytes: Vec<u8> = wire("Transfer-Encoding: chunked\r\n", b"6\r\n");
    assert!(matches!(
        run(vec![bytes], 5, Some(2), false),
        Err(TransportError::ResponseBodyTooLarge {
            declared: 6,
            maximum: 5
        })
    ));
    assert!(matches!(
        decode(b"3\r\nabc\r\n3\r\n", 5),
        Err(TransportError::ResponseBodyTooLarge {
            declared: 6,
            maximum: 5
        })
    ));
}

#[test]
fn each_closed_forbidden_trailer_is_refused_and_never_merged() {
    for name in [
        "Content-Length",
        "Transfer-Encoding",
        "Content-Type",
        "Content-Encoding",
        "Connection",
        "Trailer",
    ] {
        let body: String = format!("0\r\n{name}: ignored\r\n\r\n");
        assert!(
            matches!(
                decode(body.as_bytes(), 5),
                Err(TransportError::ForbiddenResponseTrailer)
            ),
            "{name}"
        );
    }
}

#[test]
fn ordinary_one_byte_chunks_use_the_full_body_budget() {
    let mut body: Vec<u8> = Vec::new();
    for _ in 0..1024 {
        body.extend_from_slice(b"1\r\na\r\n");
    }
    body.extend_from_slice(b"0\r\n\r\n");
    assert_eq!(decode(&body, 1024).unwrap().body, vec![b'a'; 1024]);
}

fn exact_metadata_body(extra: usize) -> Vec<u8> {
    // Independent arithmetic: max_body=1 gives 16392 framing bytes. Fixed
    // size/data/zero/final delimiters consume 10; trailers consume 16382.
    let mut body: Vec<u8> = b"1\r\na\r\n0\r\n".to_vec();
    let mut remaining: usize = 16382 + extra;
    while remaining > 0 {
        let take: usize = remaining.min(1024);
        assert!(take >= 5);
        body.extend_from_slice(b"X: ");
        body.extend(std::iter::repeat_n(b'a', take - 5));
        body.extend_from_slice(b"\r\n");
        remaining -= take;
    }
    body.extend_from_slice(b"\r\n");
    body
}

#[test]
fn line_and_aggregate_metadata_boundaries_are_independent_of_payload() {
    let mut line: Vec<u8> = b"1;".to_vec();
    line.extend(std::iter::repeat_n(b'a', 1020));
    line.extend_from_slice(b"\r\na\r\n0\r\n\r\n");
    assert_eq!(decode(&line, 1).unwrap().body, b"a");
    line.insert(2, b'a');
    assert!(matches!(
        decode(&line, 1),
        Err(TransportError::ResponseFramingTooLarge { maximum: 1024 })
    ));
    assert_eq!(decode(&exact_metadata_body(0), 1).unwrap().body, b"a");
    assert!(matches!(
        decode(&exact_metadata_body(1), 1),
        Err(TransportError::ResponseFramingTooLarge { maximum: 16392 })
    ));
    assert!(matches!(
        decode(b"0\r\n\r\n", usize::MAX),
        Err(TransportError::ResponseFramingBudgetOverflow)
    ));
}

#[test]
fn trailing_close_and_original_total_deadline_controls_remain_strict() {
    assert!(matches!(
        decode(b"0\r\n\r\ntrailing", 1),
        Err(TransportError::TrailingResponseBytes)
    ));
    let bytes: Vec<u8> = wire("Transfer-Encoding: chunked\r\n", b"0\r\n\r\n");
    assert!(matches!(
        run(vec![bytes.clone(), b"late".to_vec()], 1, None, false),
        Err(TransportError::TrailingResponseBytes)
    ));
    assert!(matches!(
        run(vec![bytes], 1, None, true),
        Err(TransportError::ResponseDidNotClose)
    ));
    let chunks: Vec<Vec<u8>> = wire("Transfer-Encoding: chunked\r\n", b"1\r\na\r\n0\r\n\r\n")
        .into_iter()
        .map(|byte: u8| vec![byte])
        .collect();
    assert!(matches!(
        run(chunks, 1, Some(55), false),
        Err(TransportError::RequestDeadlineExceeded)
    ));
}

#[test]
fn framing_refusal_priority_is_independent_of_header_order() {
    for (left, right, expected) in [
        ("Content-Length: 0", "Transfer-Encoding: chunked", "mixed"),
        (
            "Transfer-Encoding: chunked",
            "Transfer-Encoding: chunked",
            "duplicate-coding",
        ),
        (
            "Content-Length: 0\r\nContent-Length: 0",
            "Transfer-Encoding: gzip",
            "duplicate-length",
        ),
        (
            "Content-Length: wrong",
            "Transfer-Encoding: chunked",
            "invalid-length",
        ),
        (
            "Content-Type: a\r\nContent-Type: b",
            "Transfer-Encoding: gzip",
            "duplicate-type",
        ),
    ] {
        for (first, second) in [(left, right), (right, left)] {
            let headers: String = format!("{first}\r\n{second}\r\n");
            let error: TransportError =
                run(vec![wire(&headers, b"")], 10, None, false).unwrap_err();
            assert!(
                match expected {
                    "mixed" => matches!(error, TransportError::AmbiguousResponseFraming),
                    "duplicate-coding" =>
                        matches!(error, TransportError::DuplicateTransferEncoding),
                    "duplicate-length" => matches!(error, TransportError::DuplicateContentLength),
                    "invalid-length" => matches!(error, TransportError::InvalidContentLength),
                    "duplicate-type" => matches!(error, TransportError::DuplicateContentType),
                    _ => unreachable!(),
                },
                "{headers}: {error}"
            );
        }
    }
    for value in [
        "gzip",
        "gzip, chunked",
        "chunked; param=1",
        "chunked, chunked",
    ] {
        assert!(matches!(
            run(
                vec![wire(&format!("Transfer-Encoding: {value}\r\n"), b"")],
                10,
                None,
                false
            ),
            Err(TransportError::TransferEncodingUnsupported)
        ));
    }
    for headers in [
        "Content-Length: 0\r\nTransfer-Encoding: chunked",
        "Transfer-Encoding: chunked\r\nContent-Length: 0",
    ] {
        let bytes: Vec<u8> = format!("HTTP/1.1 204 No Content\r\n{headers}\r\n\r\n").into_bytes();
        assert!(matches!(
            run(vec![bytes], 10, None, false),
            Err(TransportError::TransferEncodingUnsupported)
        ));
    }
}
