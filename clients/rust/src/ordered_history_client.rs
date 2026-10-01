//! Read-only transport and independent prefix verification for ordered history.
//! Transport locators never confer authority; every descriptor and chunk is
//! checked against the fixed identity and locally trusted ordered policy.

use std::time::Instant;

use node_core::ordered_economics::{
    MAX_ORDERED_HISTORY_CHUNK_BYTES, OrderedHistoryComponentKind, OrderedHistoryHeightDescriptor,
    OrderedHistoryIdentity, OrderedHistorySummary, decode_ordered_history_height_descriptor,
    decode_ordered_history_summary,
};
use node_wire::{
    NODE_EVENT_MEDIA_TYPE, NODE_RESULT_MEDIA_TYPE, ORDERED_HISTORY_COMPONENT_PATH,
    ORDERED_HISTORY_HEIGHT_PATH, ORDERED_HISTORY_SUMMARY_PATH, OrderedHistoryChunkResponse,
    OrderedHistoryComponentRequest, OrderedHistoryHeightRequest,
};

use crate::client::expect_success;
use crate::transport::{Method, Transport, WireRequest};
use crate::{Client, ClientError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OrderedHistoryComponentRead {
    pub identity: OrderedHistoryIdentity,
    pub height: u64,
    pub descriptor_digest: protocol_types::Digest32,
    pub kind: OrderedHistoryComponentKind,
    pub offset: u64,
    pub limit: u32,
    pub expected_total_length: u64,
}

fn require_deadline_live(deadline: Option<Instant>) -> Result<(), ClientError> {
    if deadline.is_some_and(|value| Instant::now() >= value) {
        return Err(crate::TransportError::RequestDeadlineExceeded.into());
    }
    Ok(())
}

impl<T: Transport> Client<T> {
    /// Reads the source advertised tip. The returned target is untrusted until
    /// the caller verifies its exact genesis-to-target prefix.
    pub fn query_ordered_history_summary(
        &self,
        deadline: Option<Instant>,
    ) -> Result<OrderedHistorySummary, ClientError> {
        require_deadline_live(deadline)?;
        let response = self.transport().send(&WireRequest {
            method: Method::Get,
            path: ORDERED_HISTORY_SUMMARY_PATH.to_owned(),
            content_type: None,
            body: Vec::new(),
            deadline,
        })?;
        require_deadline_live(deadline)?;
        let body = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        decode_ordered_history_summary(&body)
            .map_err(|_| ClientError::OrderedHistoryMismatch("invalid summary"))
    }

    /// Reads one source descriptor under an already pinned fixed target.
    pub fn fetch_ordered_history_height_descriptor(
        &self,
        identity: &OrderedHistoryIdentity,
        height: u64,
        deadline: Option<Instant>,
    ) -> Result<OrderedHistoryHeightDescriptor, ClientError> {
        require_deadline_live(deadline)?;
        let request = OrderedHistoryHeightRequest {
            identity: identity.clone(),
            height,
        };
        let body = request.encode().map_err(ClientError::OrderedHistoryWire)?;
        let response = self.transport().send(&WireRequest {
            method: Method::Post,
            path: ORDERED_HISTORY_HEIGHT_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        require_deadline_live(deadline)?;
        let body = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let descriptor = decode_ordered_history_height_descriptor(&body)
            .map_err(|_| ClientError::OrderedHistoryMismatch("invalid height descriptor"))?;
        if descriptor.identity != *identity || descriptor.height != height {
            return Err(ClientError::OrderedHistoryMismatch(
                "descriptor identity or height differs from request",
            ));
        }
        Ok(descriptor)
    }

    /// Fetches one bounded chunk and checks the server's range metadata against
    /// the caller's independently verified descriptor reference.
    pub fn fetch_ordered_history_component_chunk(
        &self,
        read: &OrderedHistoryComponentRead,
        deadline: Option<Instant>,
    ) -> Result<Vec<u8>, ClientError> {
        require_deadline_live(deadline)?;
        if read.expected_total_length == 0
            || read.offset >= read.expected_total_length
            || read.limit == 0
            || read.limit as usize > MAX_ORDERED_HISTORY_CHUNK_BYTES
        {
            return Err(ClientError::OrderedHistoryMismatch(
                "requested chunk range is outside descriptor bounds",
            ));
        }
        let request = OrderedHistoryComponentRequest {
            identity: read.identity.clone(),
            height: read.height,
            descriptor_digest: read.descriptor_digest,
            kind: read.kind,
            offset: read.offset,
            limit: read.limit,
        };
        let body = request.encode().map_err(ClientError::OrderedHistoryWire)?;
        let response = self.transport().send(&WireRequest {
            method: Method::Post,
            path: ORDERED_HISTORY_COMPONENT_PATH.to_owned(),
            content_type: Some(NODE_EVENT_MEDIA_TYPE),
            body,
            deadline,
        })?;
        require_deadline_live(deadline)?;
        let body = expect_success(response, NODE_RESULT_MEDIA_TYPE)?;
        let chunk =
            OrderedHistoryChunkResponse::decode(&body).map_err(ClientError::OrderedHistoryWire)?;
        let expected_chunk_length = usize::try_from(
            u64::from(read.limit).min(read.expected_total_length.saturating_sub(read.offset)),
        )
        .map_err(|_| ClientError::OrderedHistoryMismatch("chunk length overflow"))?;
        if chunk.offset != read.offset
            || chunk.total_length != read.expected_total_length
            || chunk.chunk_bytes.len() != expected_chunk_length
        {
            return Err(ClientError::OrderedHistoryMismatch(
                "chunk range or advertised length differs from descriptor",
            ));
        }
        Ok(chunk.chunk_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{TransportError, WireResponse};
    use protocol_types::{AtomicityDomainId, ChainId, Epoch, HashAlgorithmId, ProtocolVersion};
    use std::cell::Cell;

    struct RecordingTransport {
        calls: Cell<u32>,
        body: Vec<u8>,
    }
    impl Transport for RecordingTransport {
        fn send(&self, _request: &WireRequest) -> Result<WireResponse, TransportError> {
            self.calls.set(self.calls.get() + 1);
            Ok(WireResponse {
                status: 200,
                content_type: Some(NODE_RESULT_MEDIA_TYPE.to_owned()),
                body: self.body.clone(),
            })
        }
    }

    fn identity() -> OrderedHistoryIdentity {
        OrderedHistoryIdentity {
            context: execution::publication::PublicationContext::new(
                ChainId::new("history-sdk-test").unwrap(),
                ProtocolVersion::new(4),
                Epoch::new(9),
            )
            .unwrap(),
            domain: AtomicityDomainId::new([1; 32]).unwrap(),
            genesis_digest: protocol_types::Digest32::new(HashAlgorithmId::Sha2_256, [2; 32]),
            anchor: protocol_types::Digest32::new(HashAlgorithmId::Sha2_256, [3; 32]),
            through_height: 5,
            through_view: 8,
            through_digest: protocol_types::Digest32::new(HashAlgorithmId::Sha2_256, [4; 32]),
        }
    }

    #[test]
    fn invalid_expected_component_ranges_fail_before_transport_io() {
        let transport = RecordingTransport {
            calls: Cell::new(0),
            body: Vec::new(),
        };
        let client: Client<RecordingTransport> = Client::new(transport);
        let pinned = identity();
        let digest = protocol_types::Digest32::new(HashAlgorithmId::Sha2_256, [5; 32]);
        for (offset, limit, total) in [(0, 0, 4), (4, 1, 4), (0, 1_048_577, 4), (u64::MAX, 1, 4)] {
            let read = OrderedHistoryComponentRead {
                identity: pinned.clone(),
                height: 1,
                descriptor_digest: digest,
                kind: OrderedHistoryComponentKind::Candidate,
                offset,
                limit,
                expected_total_length: total,
            };
            assert!(
                client
                    .fetch_ordered_history_component_chunk(&read, None)
                    .is_err()
            );
        }
        assert_eq!(client.transport().calls.get(), 0);
    }

    #[test]
    fn mismatched_chunk_metadata_is_rejected_after_a_bounded_read() {
        let response = OrderedHistoryChunkResponse {
            offset: 1,
            total_length: 5,
            chunk_bytes: vec![7, 8],
        }
        .encode()
        .unwrap();
        let transport = RecordingTransport {
            calls: Cell::new(0),
            body: response,
        };
        let client: Client<RecordingTransport> = Client::new(transport);
        let read = OrderedHistoryComponentRead {
            identity: identity(),
            height: 1,
            descriptor_digest: protocol_types::Digest32::new(HashAlgorithmId::Sha2_256, [5; 32]),
            kind: OrderedHistoryComponentKind::Candidate,
            offset: 0,
            limit: 2,
            expected_total_length: 4,
        };
        assert!(
            client
                .fetch_ordered_history_component_chunk(&read, None)
                .is_err()
        );
        assert_eq!(client.transport().calls.get(), 1);
    }
}
