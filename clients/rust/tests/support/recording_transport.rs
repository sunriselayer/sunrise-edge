//! Request recording and queued responses only; business fixtures stay local.

use std::cell::RefCell;
use std::collections::VecDeque;
use sunrise_edge_client::{Transport, TransportError, WireRequest, WireResponse};

pub(crate) struct FakeTransport {
    pub(crate) responses: RefCell<VecDeque<WireResponse>>,
    pub(crate) requests: RefCell<Vec<WireRequest>>,
}
impl Transport for FakeTransport {
    fn send(&self, request: &WireRequest) -> Result<WireResponse, TransportError> {
        self.requests.borrow_mut().push(request.clone());
        Ok(self.responses.borrow_mut().pop_front().unwrap())
    }
}
