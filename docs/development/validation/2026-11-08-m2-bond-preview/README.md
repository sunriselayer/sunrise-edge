# Original bond registration structural preview (2026-11-08)

The [decision](../../../architecture/decisions/0287-bond-registration-structural-preview.md)
adds a seed-free, nonauthorizing original-scope inspection command. It reuses
the prepared registration owner and prints canonical signed-leg, predicted-row,
unsigned outer-intent and signing-frame bytes. It creates no output artifact
and does not sign or approve an operation.

Exact source `642f2a8830289838b4034bc5c7d04c7cee641f9b`, tree
`50741691e28bc46d056318754bebec3b1eda6453`, was clean before and after
the bounded targeted run. The focused `seed_free_preview` filter passed 2/2;
the entire existing `bond_registration` CLI test target passed 10/10. Both
commands exited and waited 0, were reaped, reached stdout/stderr EOF without
truncation, and released their process groups. The private cache/target copy
matched the released source before and after its Btrfs reflink copy. The
terminal receipt is `m2-bond-preview-targeted-v6-inert-1108/final.json` below
the external validation root, SHA-256
`9e2ec1cb3160c26ddbda058ff9c664a83c46e79937d1c05fd43662d21608aff0`.

The earlier source `b0034e59` passed one focused preview test and failed the
other because its assertion expected the original-only diagnostic for a
partial successor flag set. The shared parser correctly refused that partial
set first. Its failure raw and receipt remain preserved at
`m2-bond-preview-targeted-v3-inert-1108/` and are not counted as a pass. The
test now checks partial refusal and the original-only diagnostic for a
syntactically complete successor pin set.

This targeted result does not establish trusted content approval, protected
bond signing, actual registration, successor preview, the full required gate,
exact-source CI, or parent M2 completion. The remaining authority and review
contract stay in TODO M2-N3.
