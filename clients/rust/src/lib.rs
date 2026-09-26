#![forbid(unsafe_code)]

//! Sunrise Edge Developer MVP Rust client (docs/architecture/product-surfaces.md §44;
//! docs/architecture/decisions/0081-0087-cli-first-roadmap.md DR-0083, DR-0084).
//!
//! This is a runtime-neutral library: seed-based Ed25519 key/address
//! handling, canonical Transaction v1 construction and signing through a
//! safe two-stage external-signer API
//! ([`transaction::PreparedTransaction`]), submission with a
//! caller-supplied request id, bounded receipt waiting, and the four bounded
//! query operations (`/v1/context`, `/v1/objects/{object_id}`,
//! `/v1/receipts/{request_id}`, `/v1/senders/{sender}/next-nonce`).
//!
//! It depends on `node-core` and `node-wire` for the canonical wire
//! contract and never on Axum or `native-http`. The provided
//! [`transport::LoopbackHttpTransport`] is a strict, synchronous,
//! loopback-only plaintext HTTP/1.1 implementation for local development;
//! [`transport::RemoteTlsHttpTransport`] is this crate's `CLI-First Node
//! Production Gate` S1 remote transport slice (see
//! `docs/architecture/decisions/0081-0087-cli-first-roadmap.md`
//! DR-0085): a strict, synchronous HTTP/1.1-over-TLS implementation that
//! shares the identical request/response framing but requires an explicit
//! DNS server name and CA trust anchor and performs normal TLS
//! server-identity and hostname validation instead of trusting loopback. The
//! [`transport::Transport`] trait exists so tests and other embedders can
//! supply a deterministic fake instead.
//!
//! [`context::ExpectedProtocolContext`] implements that same S1 slice's
//! other, separate concern: a mandatory, locally trusted expected-
//! protocol-context check ([`Client::query_verified_context`]) that a
//! caller must perform before any nonce/object query or signing, since a
//! successful transport connection — including the implemented remote TLS one — proves
//! only that the client reached some server holding a trusted key for that
//! hostname, never that it is the caller's intended chain/protocol.
//!
//! This client keeps `ProtocolConfig` bytes opaque, requires the caller to
//! supply module/object references and the active signature scheme, never
//! derives a request id, and adds no asset-specific helpers or CLI policy.
//! The public-code APIs additionally verify exact publication commitments and
//! typed local-execution results with an explicitly trusted resolver; they do
//! not infer that resolver from a remote response. Other
//! capabilities, general-purpose DNS/root-store/mTLS transport expansion, and
//! blob fetch remain deferred (see `docs/architecture/product-surfaces.md` §44 /
//! `docs/architecture/decisions/0081-0087-cli-first-roadmap.md` DR-0083).
//! [`key::LocalSigner`] is
//! an explicit development-only, in-memory key, never a keystore; real
//! external/hardware signing remains outside this vendor-neutral crate.
//! S4c Phase 1's dedicated Ledger host adapter now lives downstream in
//! `clients/ledger` (see `docs/architecture/decisions/0088-0093-hardware-signing.md` DR-0092), depending on this crate
//! rather than reversing the dependency. [`transaction::PreparedTransaction`]
//! exposes exactly the bytes such an external signer needs and independently
//! verifies whatever signature comes back before producing output, preserving
//! the local signing path and this crate's vendor independence.

pub mod client;
pub mod context;
pub mod error;
pub mod fastvote_client;
pub mod key;
pub mod local_execution_client;
pub mod paid_execution_client;
pub mod publication_client;
pub mod support;
pub mod transaction;
pub mod transport;

pub use abi::package_types::PackageOrigin;
pub use abi::{decode_access_manifest, executable_abi};
pub use client::{Client, ReceiptPollBounds, SubmitTransactionRequest};
pub use context::{ExpectedProtocolContext, ExpectedProtocolContextError, ProtocolContextMismatch};
pub use error::ClientError;
pub use execution::GENERIC_OBJECT_RESULT_WASM_PROFILE_VERSION;
pub use execution::paid_execution::{
    FeeSourceConsent, MAX_PAID_EXECUTION_RESULT_BYTES, MAX_SIGNED_PAID_INTENT_BYTES,
    MIN_EXECUTION_PRICE, MIN_RESERVE_ALLOWANCE, MIN_SETTLE_ALLOWANCE, PaidApplication,
    PaidChargedOutcome, PaidExecutionResult, PaidExecutionStatus, PaidFeePolicy, PaidIntent,
    PaidResultKind, PaidResultTarget, ReservationAccessKind, SignedPaidIntent,
    decode_paid_execution_result, decode_paid_fee_policy, decode_signed_paid_intent,
    encode_paid_execution_result, encode_paid_fee_policy, encode_signed_paid_intent,
    paid_fee_policy_digest,
};
pub use execution::publication::{
    ArtifactParts, CodeArtifact, PublicationContext, PublicationSubmission,
    UnverifiedDependencyRef, decode_dependency_ref,
};
pub use execution::{call, call_authorization, local_execution};
pub use fastvote_client::{
    FastVoteApplyAttempt, FastVoteAttempt, FastVoteEndpoint, FastVoteEndpointConfigError,
    FastVoteGenesisTrustError, FastVoteNetworkError, FastVoteQuorumError, FastVoteQuorumFailure,
    MAX_FASTVOTE_NETWORK_ENDPOINTS, apply_fastvote_to_all, collect_fastvote_certificate,
    load_trusted_fastvote_genesis, validate_fastvote_endpoints,
};
pub use hashing::HashSuiteResolver;
pub use key::LocalSigner;
pub use local_execution_client::{build_signed_general_execution, build_signed_local_execution};
pub use node_core::publication::{
    decode_publication_query_result, encode_publication_query_result,
};
pub use paid_execution_client::{
    PAID_EXECUTION_PATH, PAID_FEE_POLICY_PATH, build_signed_paid_execution,
};
pub use protocol_types::{HashSuite, HashSuiteSchedule};
pub use publication_client::{
    PublicationQueryResult, build_signed_publication, local_publication_resolver,
};
pub use signing_view::{
    ClearSigningPolicy, ClearSigningPolicyError, ClearSigningView, DeviceSigningProfile,
    HISTORICAL_ASSET_ACCOUNT_TRANSFER_POLICY_V3, SigningViewError,
};
pub use support::{
    ED25519_ADDRESS_IS_PUBLIC_KEY_BINDING_ID, ED25519_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_BINDING_ID,
    ED25519_CANONICAL_PRIME_ORDER_ADDRESS_IS_PUBLIC_KEY_PROFILE_ID, current_inline_object_ref,
};
pub use transaction::{
    ExternalSigner, PreparedTransaction, TransactionRequest, build_signed_submission_transaction,
    build_signed_transaction,
};
pub use transport::{
    LoopbackHttpTransport, MAX_CA_CERTIFICATE_DER_BYTES, Method, RemoteTlsHttpTransport, Transport,
    TransportError, WireRequest, WireResponse,
};

// Re-exported for convenience: every `Client` query method returns one of
// these node-wire types, and callers need `RequestId`/`ObjectId`/`Address`
// to call them in the first place.
pub use consensus::{
    ConsensusError, FastCertificate, FastPathCertifier, FastVote, decode_fast_certificate,
    decode_fast_vote, encode_fast_certificate, encode_fast_vote,
};
pub use execution::{
    CONTRACT_WASM_ADMISSION_PROFILE_VERSION, ContractWasmValidationError, EventRecord,
    ExecutionEffects, ExecutionStatus, MAX_CONTRACT_ENTRYPOINT_NAME_BYTES,
    MAX_CONTRACT_ENTRYPOINTS, MAX_CONTRACT_WASM_BYTES, ObjectEffect, ValidatedContractWasm,
    decode_event_record, decode_execution_effects, decode_object_effect, publication,
    validate_contract_wasm,
};
pub use node_core::publication::local_publication_profile_semantics;
pub use node_core::{NodeCoreError, NodeResponse, NodeResponseStatus, RequestId};
pub use node_wire::{
    FASTVOTE_CERTIFICATES_PATH, FASTVOTE_PREPARE_PATH, FastVoteApplyRequest,
    FastVoteApplyRequestError, HttpContextQueryResult, HttpNextNonceQueryResult, HttpNodeResult,
    HttpObjectQueryResult, HttpReceiptQueryResult, MAX_FASTVOTE_CERTIFICATE_BYTES,
    NEXT_NONCE_QUERY_RESULT_TYPE_ID, NODE_RESULT_MEDIA_TYPE, ObjectQueryStatus, QUERY_CONTEXT_PATH,
    QUERY_NEXT_NONCE_PATH, QUERY_OBJECT_PATH, QUERY_RECEIPT_PATH, QUERY_RESULT_MEDIA_TYPE,
    QueryResultError, ReceiptQueryStatus,
};
pub use objects::{
    AccessMode, Address, Object, ObjectError, ObjectId, ObjectRef, Owner, decode_object,
};
pub use validator_set::{ValidatorInfo, ValidatorSet};

// Re-exported so `apps/cli` (and other application-specific consumers) can
// build a `TransactionRequest`'s access manifest and canonical argument
// frames without a direct dependency on any lower protocol crate. `abi` and
// `canonical-encoding` are foundational, dependency-light crates this client
// already depends on for its own construction/signing path; re-exporting a
// handful of their generic types here is the "smallest generic client
// surface" carve-out from `docs/architecture/product-surfaces.md` §44 and
// `docs/architecture/decisions/0081-0087-cli-first-roadmap.md` DR-0083 and DR-0084 — it
// adds no devnet or other application-specific semantics.
pub use abi::{AccessEntry, AccessManifest, call_values, package_types, public_abi};
pub use canonical_encoding::{CanonicalEncodingError, CanonicalStruct};
pub use fees::{Amount, FeePayment};
pub use protocol_types::{
    AtomicityDomainId, ChainId, Digest32, Epoch, HashAlgorithmId, HashSuiteId, ProtocolVersion,
    SignatureSchemeId, TypeError, ValidatorId,
};
pub use standard_assets::{
    AssetId, StandardAssetCoinV1, StandardAssetError, StandardAssetTransferArgsV1,
    decode_standard_asset_coin_v1, encode_standard_asset_coin_v1,
    encode_standard_asset_transfer_args_v1,
};
