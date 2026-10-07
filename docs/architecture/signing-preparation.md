# Immutable operation signing preparation

[DR-0211](decisions/0211-external-signing-preparation.md) defines the shared
mechanical boundary. [DR-0208](decisions/0208-native-sqlite-first-and-protected-signing.md)
removes mandatory Ledger product completion, not protected keys, trustworthy
content review, recovery, rotation or revocation. Release status belongs in
[`TODO.md`](../../TODO.md).

## Defining owners

The client-private [`PreparedSigningFrame`](../../clients/rust/src/signing_frame.rs)
owns the explicitly configured expected public identity, supported signature
scheme and immutable exact frame. It reuses the existing
[`ExternalSigner`](../../clients/rust/src/transaction.rs) and crypto verifier;
there is no additional provider trait, signature scheme or signing wire format.
Provider-declared scheme and identity are checked before `sign_frame`. Returned
signatures are independently verified against the original expected key and
frame before signed output is returned. Generated provider failures expose no
provider diagnostics through Display, Debug or the error-source chain.

Operation-specific prepared owners retain the trust inputs and preimages, and
own their original authentication and error order:

| Prepared owner | Immutable content and final authentication |
| --- | --- |
| [`PreparedTransaction`](../../clients/rust/src/transaction.rs) | Original transaction, domain and signable payload for both transaction profiles; its ordinary `SignatureSigner` convenience retains the crypto error contract and its separate historical clear-policy path remains bounded |
| [`PreparedLocalExecution`](../../clients/rust/src/local_execution_client.rs) | Explicit sender, intent, resolver, local/general policy and resolved execution scopes; original scope/ABI checks precede signing and local authentication remains in finalization |
| [`PreparedPaidExecution`](../../clients/rust/src/paid_execution_client.rs) | Exact application, consent, policy pins, nonce, request, gas and authorizations; original encode/authenticate and post-sign fee quote remain, rather than claiming every business check is pre-sign |
| [`PreparedPublication`](../../clients/rust/src/publication_client.rs) | Complete artifact and dependency preimages, publisher, commitment, semantics, nonce, request, resolver and context; original publication authentication remains |
| [`PreparedLocalBondRegistration` / `PreparedSuccessorBondRegistration`](../../clients/rust/src/bond_registration.rs) | Core-derived validator identity, signed custody leg, predicted row and original root or immutable successor workflow; original registration-scope and outer/inner authentication remain |
| [`PreparedFeeClaim`](../../clients/rust/src/fee_claim_client.rs) | Exact request, intent and immutable verified workflow; claimant identity comes from `certificate_set(intent.certificate_epoch)`, never the current committee or an untrusted response |

Content accessors are immutable. Consuming `finalize(signature)` accepts no
replacement context, policy, scopes, artifact, predicted row or custody leg.
Unsupported schemes, identity mismatch, wrong key/frame, malformed signature
length and provider refusal produce no signed output. No failed external call
falls back to a development key. Existing operation-specific errors remain
distinct rather than being replaced by a uniform business validation layer.

## Actual consumers and evidence boundaries

Development `LocalSigner`/seed conveniences delegate to these prepared owners.
Actual CLI local/general execution, paid Call/Instantiate/Publish, publication,
Standard Asset paid operations, original/successor bond registration and
successor fee claims use the same preparation and finalization. Fee-source
ownership checks take the expected public `Address`, not secret-bearing keys.
CLI development seed flags are still development flags; no production provider
driver or custody flag follows from this refactor.

Tests compare independent original raw frame/sign/encode sequences with the new
owners and development wrappers. External fakes exercise refusal and zero-call
pre-sign boundaries, not key protection. Genuine registration and historical
fee-claim controls remain inside the original owning operator recurrence; merely
compiling those controls does not prove that expensive workflow passed.

## Separate M2 requirements

Mechanical signature validity is not independent human content review. A future
trusted review surface must use the same retained content, recompute commitments
from bounded preimages and fail closed on unknown semantics. The historical
Ledger transaction policy is not generic-contract review authority.

Automatic validator signing stays with `ConsensusSigner`, committed public
identity and actual live protocol authority. Readiness has its own narrower
eligible-key and retention boundary. Native operator/genesis raw-key custody
and these automatic signers are not migrated by SDK operation preparation.

A real protected provider, operator/key-role separation, exposure controls,
refusal/restart behavior, trusted content review and recovery/rotation/revocation
still need design, implementation and qualification. Provider revocation does
not erase historical signatures or silently rotate an AddressIsPublicKey
identity. No custody backend or public network launch is selected here.

[Proposed DR-0214](decisions/0214-protected-custody-and-review-boundary.md)
separates client review, automatic consensus, readiness and genesis/admin roles,
and compares local-OS, separated-host and hardware-backed threat boundaries.
Its contract is independently design-reviewed, not provider selection or M2
qualification. It explicitly defers an additional presentation layer without a
concrete trusted review consumer; repeating these prepared-owner guarantees is
not another security boundary.
