# DR-0207: Local native, streamed relay and SDK integration

Date: 2026-10-07 (Asia/Singapore)

Status: Proposed bounded integration-test contract. Implementation and combined
source acceptance remain separate; this permits no deployed profile or launch.

## Boundary

DR-0203/0206 narrow the core and native host; DR-0204/0205 add closed relay and
bounded SDK framing. Their separately reviewed source heads must compose without
reviving retired constructors or advertising unsupported authority. Normal local
merge commits retain those heads; current architecture/code maps describe the
combined candidate, not already-integrated main or a release.

The existing SDK test uses a real native devnet router and file-backed local
SQLite to query context, absent object, absent receipt and zero next nonce over
TCP. Preserve those operations and independent assertions. Extend that same
scenario through the actual certified Vercel constructor, a test-owned Node
HTTPS/Fetch bridge and the CA/DNS-pinned Rust TLS transport.

Only the bridge's injected upstream capability may translate its fixed HTTPS
test origin to the numeric loopback HTTP native listener. Validate the local
scheme/host/port and closed four GET paths; forward actual native response bytes,
not fixture-generated canonical answers. This second leg is explicitly HTTP,
not upstream TLS/PKI, provider deployment, quorum or business execution evidence.

Keep the original framing fixture's GET/POST/204/late-error cases unchanged.
Share only its bounded process/stdio/TLS setup in a test-private owner, not a
general process framework or production dependency. Disposable keys travel on
stdin, never logs. Pin Node 22.20.0, numeric loopback listeners, request/response
bounds, watchdog and owned child/task cleanup, including failure paths.

## Acceptance

Both original TCP queries and the real native-through-relay queries retain
independent expected chain/epoch/selectors/absent/nonce values. The Node bridge
proves actual no-Content-Length chunked output for the four new query responses.
No bypass, fabricated successful write, generic NodeEvent relay, new signer,
privileged asset policy, canonical field or production API is introduced.

Combined native/SDK owning tests, workspace Clippy, pinned portable checks,
formatting and documentation links are scoped evidence. The complete required
gate, fresh complete source review and all required CI remain mandatory before
main integration. Parent or ancestor results are not combined exact-head passes.
Unsupported ordered/successor/DO lifecycle, custody, independent security audit
and every original mainnet/public-testnet release criterion remain open.
