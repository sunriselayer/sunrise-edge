# DR-0267: Positive Standard Asset fee-claim Split proposal policy

Date: 2026-10-17 (Asia/Singapore)

Status: Accepted for a pure operation-specific proposal/preparation boundary.

## Decision

Add a public application-specific owner in the existing CLI library for the
positive Split of the original genesis Standard Asset fee resource. The CLI
already depends on that public package. Reuse the verified successor workflow,
historical committee lookup, native public package builder, scope/argument/type
helpers, `PreparedLocalExecution` and `PreparedFeeClaim`. Expose the existing
protocol custody owner types through the Rust client's existing object reexport;
add no dependency, provider interface, protocol ID, schema or signing bytes.

Recognize the complete original signed resource/code/empty closure/initializer
instance under its own publication context. Keep the successor execution context
and original certificate epoch separate. Require an explicit historical claimant
pin matching the verified original certificate committee. Do not substitute a
current member or reuse genesis-equals-execution assumptions from paid custody.

Separate two immutable steps: construct/review/finalize only the recognized
positive local Split leg, then construct/review/finalize only its matching outer
fee claim. Authenticate both returned signatures through the original prepared
owners. Reuse the existing deterministic creation/type/object helpers to predict
the one payout of this exact signed leg and require that payout in a v2 Split.
No caller supplies an arbitrary signable frame, generic entrypoint or replacement
trust input to finalization.

## Explicit evidence boundary

The captured canonical fee object, its hash epoch, amount and nonce are retained
proposal inputs. Hash/type/reference and exact FeeEscrow scope checks do not prove
a current head, certified claim history or a current entitlement. Generation and
row digests remain host proposals. The recognized meaning review says so, retains
every material field and includes the existing non-authorizing `FeeClaimReview`
without changing its claim. The prediction of payout/remainder is conditional on
execution, not a receipt or a native replacement for WASM business execution.

This first policy supports the original genesis resource and certificate epoch,
positive strict partial Split, exact in-tree code and v2 payout only. It grants no
protected FinalTransfer/general execution/other signing-family permission.
Missing or unknown semantics/preimages refuse. Full currentness and entitlement
checks remain with real store-backed preparation and ordered execution.

## Protected consumer remains separate

The historical claimant signs both the embedded leg and outer claim. Protecting
only the latter while that same key remains in a development or node process
does not isolate it. This policy adds neither backend nor approval, key load,
IPC endpoint, network request or CLI signing mode. A later reviewed integration
must connect both specific key uses, require independent whole-content approval,
and qualify UID, expiry/refusal, permanent revocation, restart, stopped recovery
and historical-key rotation behavior. An agent may implement these routine
steps under the selected trusted local OS model; real roles/ceremonies retain
their separate public owners.

Pure content tests retain independent legacy frame/signature parity and targeted
input refusals. Real successor/historical authority parity is asserted inside
the original positive Split compiled acceptance using its existing host-prepared
claim and signatures, without shortening recurrence or inventing trusted workflow
fixtures. Source, compilation, actual owning results and final-source gates remain
separate. Current results and remaining gates belong only in TODO.

See [the implementation contract](../positive-fee-claim-split-policy.md).
