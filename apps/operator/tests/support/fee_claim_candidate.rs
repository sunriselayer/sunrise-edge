//! Test-controlled, quiescent claim preview using production APIs. This is
//! not an online snapshot and never advances the host's writer fence.

use super::{cli, genesis_fixture::FastVoteGenesisFixture};
use abi::call_values::{CallValue, encode_call_value};
use abi::{AccessEntry, AccessManifest};
use ed25519_zebra::{SigningKey, VerificationKey};
use execution::call::CallIntent;
use execution::local_execution::{
    LocalExecutionIntent, LocalExecutionMode, LocalExecutionPolicy, SignedLocalExecutionIntent,
    encode_signed_local_execution, local_execution_signing_frame,
};
use node_core::fee_claims::{self, FeeClaimKind, FeeClaimPreparationRequest};
use node_core::ordered_economics::{OrderedCandidate, OrderedOperationKind};
use objects::{AccessMode, Address};
use protocol_types::ValidatorId;
use r2d2_postgres::{PostgresConnectionManager, r2d2::Pool};
use runtime_postgres::{
    PostgresBlobStore, PostgresDurableStore, PostgresNamespace, PostgresTransactionPolicy,
};
use std::num::NonZeroU32;

pub struct ClaimRequest {
    pub escrow: [u8; 32],
    pub claimant: ValidatorId,
    pub request: [u8; 32],
    pub recipient: Address,
    /// Historical fixtures may explicitly pin their physical checkpoint.
    /// Logical fixtures derive a later checkpoint from the actual preview.
    pub checkpoint: Option<u64>,
}

pub fn prepare(
    pool: &Pool<PostgresConnectionManager<postgres::NoTls>>,
    namespace: &PostgresNamespace,
    fixture: &FastVoteGenesisFixture,
    request: ClaimRequest,
) -> OrderedCandidate {
    let durable: PostgresDurableStore<PostgresConnectionManager<postgres::NoTls>> =
        PostgresDurableStore::new(
            pool.clone(),
            namespace.clone(),
            PostgresTransactionPolicy::new(NonZeroU32::new(3).unwrap()).unwrap(),
        );
    let blobs: PostgresBlobStore<PostgresConnectionManager<postgres::NoTls>> =
        PostgresBlobStore::new(pool.clone(), namespace.clone()).unwrap();
    let context: runtime::DurableOperationContext = cli::read_context(pool, namespace);
    let key: SigningKey = SigningKey::from(
        fixture
            .validators
            .iter()
            .find(|entry| entry.validator_id == request.claimant)
            .unwrap()
            .seed,
    );
    let public: [u8; 32] = VerificationKey::from(&key).into();
    let policy: LocalExecutionPolicy =
        LocalExecutionPolicy::generic_object_results(fixture.context.clone());
    let view: fee_claims::FeeClaimInspection = fee_claims::inspect_fee_claim(
        &durable,
        &blobs,
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        request.escrow,
        request.claimant,
        public,
        &policy,
    )
    .unwrap();
    let kind: FeeClaimKind = view.entitlement.kind.unwrap();
    let signed_leg: Option<Vec<u8>> = match kind {
        FeeClaimKind::ZeroShare => None,
        FeeClaimKind::Split | FeeClaimKind::FinalTransfer => {
            let execution: &fee_claims::FeeClaimExecutionView = view.execution.as_ref().unwrap();
            let split: bool = kind == FeeClaimKind::Split;
            let entrypoint: String = if split {
                execution.resource.split_entrypoint.clone()
            } else {
                execution.resource.transfer_entrypoint.clone()
            };
            let argument: CallValue = CallValue::Tuple(if split {
                vec![
                    CallValue::U64(view.entitlement.amount),
                    CallValue::Bytes(request.recipient.as_bytes().to_vec()),
                ]
            } else {
                vec![CallValue::Bytes(request.recipient.as_bytes().to_vec())]
            });
            let arguments: Vec<u8> = encode_call_value(
                execution.interface.argument_layout(&entrypoint).unwrap(),
                &argument,
            )
            .unwrap();
            let intent: LocalExecutionIntent = LocalExecutionIntent {
                mode: LocalExecutionMode::Call,
                policy_digest: execution.policy.digest(&fixture.resolver).unwrap(),
                call: CallIntent {
                    context: fixture.context.clone(),
                    request_id: request.request,
                    sender: public,
                    nonce: execution.next_nonce,
                    code: execution.resource.code.clone(),
                    instance: execution.resource.instance.clone(),
                    entrypoint,
                    type_arguments: execution.resource.ty.args().to_vec(),
                    access: AccessManifest {
                        entries: vec![AccessEntry {
                            object_ref: view.escrow.settlement.fee_output.clone().unwrap(),
                            mode: AccessMode::Write,
                        }],
                    },
                    arguments,
                    gas_limit: 500_000,
                },
                authorizations: Vec::new(),
            };
            let frame: Vec<u8> = local_execution_signing_frame(&fixture.context, &intent).unwrap();
            Some(
                encode_signed_local_execution(&SignedLocalExecutionIntent {
                    intent,
                    signature: key.sign(&frame).into(),
                })
                .unwrap(),
            )
        }
    };
    let checkpoint: u64 = request.checkpoint.unwrap_or_else(|| {
        view.execution.as_ref().map_or(1, |execution| {
            execution.minimum_checkpoint.checked_add(1).unwrap()
        })
    });
    let prepared: fee_claims::PreparedFeeClaim = fee_claims::prepare_fee_claim(
        &durable,
        &blobs,
        &context,
        fixture.domain,
        &fixture.resolver,
        &[],
        &fixture.context,
        &policy,
        &execution::LocalWasmExecutionEngine::new(),
        FeeClaimPreparationRequest {
            escrow_request_id: request.escrow,
            request_id: request.request,
            validator_id: request.claimant,
            claimant_public_key: public,
            recipient: request.recipient,
            signed_leg: signed_leg.as_deref(),
        },
        checkpoint,
    )
    .unwrap();
    let digest: protocol_types::Digest32 =
        fee_claims::fee_claim_intent_digest(&fixture.resolver, &prepared.intent).unwrap();
    let frame: Vec<u8> = fee_claims::fee_claim_signing_frame(&fixture.context, digest).unwrap();
    let signed: fee_claims::codec::SignedFeeClaimIntent = fee_claims::codec::SignedFeeClaimIntent {
        intent: prepared.intent,
        signature: key.sign(&frame).into(),
    };
    OrderedCandidate {
        context: fixture.context.clone(),
        request_id: request.request,
        kind: OrderedOperationKind::FeeClaim,
        intent: fee_claims::codec::encode_signed_fee_claim_intent(&signed).unwrap(),
        created_checkpoint: checkpoint,
    }
}
