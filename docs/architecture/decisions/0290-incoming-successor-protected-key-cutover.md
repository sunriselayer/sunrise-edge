# DR-0290: Incoming successor protected-key cutover fixture

Date: 2026-11-09 (Asia/Singapore)

Status: Selected for a bounded development fixture. Source changes require
their own actual execution, complete required validation and exact-source CI;
current qualification remains in [TODO.md](../../../TODO.md).

## Decision

This is a test-owner application of the successor protected-host boundary
selected in [DR-0285](0285-successor-protected-host-proposal.md), not a new
key-custody boundary. Use the existing registered original A/B/C/D to successor
A/B/C/E membership transition as the first positive protected-identity cutover
observation. The original recurring acceptance owner verifies the successor
committee and authority before starting its hosts. In the optional real-UID
variant, place incoming E's successor signer, SQLite writer and live warrant
in the existing distinct-UID worker, with the existing keyless frontend. Do not add a signing
route, authority rule, second acceptance owner or another ordered round.

The pre-host direct-TLS read/receipt probe still runs against a genuine
activated successor and retains its original context, receipt, state, artifact
tamper and stop assertions. In this variant it uses retained A, so that probe
does not load incoming E's key into an ordinary host before E's protected
serving phase. The ordinary variant keeps its original first target. The first
of the existing three successor ordered rounds retains four-host fan-out and
checks E's actual certified vote in the quorum certificate. The existing
wrong-key startup refusal uses removed original D's key against E's target, after
checking D was in the original set and is absent from the verified successor
set. This refusal alone is not positive rotation evidence.

The existing stop, alternate-path same-key recovery, restart and signerless
catch-up phase applies to E. It remains a recovery of E's identity, not a
second identity transition. The host vector is restored in verified committee
order before the original recurring owner continues unchanged through seven
epochs, e8 terminal unlock and both withdrawal candidates and acknowledgements.

## Evidence boundary

This fixture can establish only the later e1 protected serving phase after the
authorized e0-to-e1 membership transition. The test's setup, activation and
later recurring epochs retain their existing development composition; it does
not prove E's key was isolated for its whole lifetime or that every later
epoch uses a protected worker. It does not migrate an asset address, account,
fee balance, application creator, TreasuryCap or historical claimant. It adds
no real key, host user, policy, provider deployment, public network or M2
completion claim. The selected trusted-local-OS boundary and existing
membership/epoch authority remain those of
[DR-0285](0285-successor-protected-host-proposal.md) and
[DR-0214](0214-protected-custody-and-review-boundary.md).
