# DR-0190: One bounded read-only fee-claim preparation transport

Date: 2026-10-04 (Asia/Singapore)

Status: **Proposed implementation contract**, subject to the independent
exact-head review. Work status and acceptance evidence remain in
[TODO.md](../../../TODO.md).

## Context

[DR-0181](0181-writer-free-operation-preparation.md) separates actual
writer-free evaluation from durable completion. [DR-0189](0189-first-successor-serving.md)
requires the same owning evaluator for a new-epoch claim on an imported
predecessor escrow, without re-signing historical certificates or treating a
retired claimant as a consensus signer. A remote CLI needs to request that
evaluation, but the request must not acquire authority from its own epoch,
clock, checkpoint, domain or server response.

## Decision

Use `POST /v1/fee-claims/prepare` with one closed, bounded request frame owned
by `node-wire::fee_claims`: type `0x6461`, encoding version `1`. The ascending
fields are publication context, escrow request ID, new claim request ID,
validator ID, claimant public key, recipient address and optional signed
execution-leg bytes. All seven fields are required; empty field 7 means no
leg, so `Some(empty)` is rejected as ambiguous. Unknown/duplicate/missing
fields, unsupported versions, invalid fixed lengths and noncanonical encodings
are refused. Bound the full input before parsing and the leg before copying it.

The request media type is
`application/vnd.sunrise-edge.fee-claim-prepare-request`. The response is
exactly the existing unsigned core `FeeClaimIntent` frame `0x6437`, under
`application/vnd.sunrise-edge.fee-claim-intent`: no second response schema,
new signature domain or duplicated settlement representation.

The host treats every request field as an untrusted claim. It resolves fresh
local authority, checks the requested publication context against the verified
live context, derives its own fence/checkpoint and invokes the existing
read-only preparation evaluator. The endpoint never reserves state, signs a
claim, commits a settlement or reports network finality. Preparation errors
retain the owning handler's typed semantics.

The SDK verifies its original genesis/domain/schedule and successor evidence
independently, then compares the returned intent with the requested context,
identities, recipient and exact execution-leg intent before signing. A response
cannot replace those pins. The new claim and leg use the live epoch; the
escrow's certificate epoch and historical signatures remain unchanged. Signed
claims use the existing authenticated ordered submission path and replay rules.

## Consequences and verification

Preparation has one business owner and one transport shape. Hosts and clients
must not add a parallel fee engine, accept caller-supplied historical authority
or silently fall back to original-genesis policy. The existing core claim,
transaction, object, receipt and certificate bytes are unchanged.

Codec tests include a frozen literal v1 request vector, present/absent-leg
round trips and malformed/oversized cases. Transport tests must separately
prove fresh authority, context refusal, read-only behavior and comparison
before signing; synthetic codec fixtures are not those authorization proofs.
Real process, replay and independent review gates stay explicit in TODO.
