# Changelog

All notable changes to `com.intyga:intyga-sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

- **Tokens are refreshed automatically.** `IntygaClient` now reads `expires_in` from the
  client-credentials exchange and re-exchanges `min(60s, expires_in / 10)` before expiry, so a
  long-lived client (or a `requireApproval` wait longer than the token's life) no longer fails
  every call once the token has expired. A 401 on an exchanged token is retried exactly once with a
  fresh exchange. A response without `expires_in` is cached for the life of the client, as before.
- An explicit `Builder.token(...)` is never re-exchanged: a 401 on it surfaces as
  `GatewayRefusedException` unchanged — there is no client secret behind it.
- Correction to the 1.0.0 entry below: "lifetime caching" described a defect, not a feature. 1.0.0
  never re-exchanged and never evicted on 401, so a client older than the gateway's token TTL was
  refused on every call until restarted.

## [1.0.0]

Initial public release.

- Blocking client: `authorize`, `status`, `consume`, `requireApproval`, `requireApprovalOrThrow`,
  `verify`; token exchange via HTTP Basic client-credentials with lifetime caching.
- `target` is required (DIV Target Isolation): `authorize` and `consume` reject a blank target
  client-side rather than letting the gateway default it to the replayable `"global"`.
- Typed exceptions mirroring sdk-python's refusal/outage split: `GatewayRefusedException` (non-2xx,
  carries the status) vs `GatewayUnreachableException` (transport failure) — DIV §5a's offline path
  exists only for "could not ask", so the two must never be conflated. `ApprovalRefusedException`
  makes a human "no" an exception rather than a return value for framework code.
- Bundles the offline verifier (`com.intyga:intyga-verify`), so a receipt can be verified in the
  same process that requested it. `ApprovalResult.receipt()` is raw JSON that
  `ApprovalReceipt.parse` accepts directly.
- The witness-lookup response is `WitnessLookupResult`, not `VerifyResult` as in the Go and Rust
  clients. Those reach their verifier through a package qualifier; in Java both packages share one
  classpath, where `VerifyResult` collided with `com.intyga.verify.VerifyResult` under a wildcard
  import — and implied that `client.verify(documentHash)` checks a signature. It does not; it asks
  the gateway what it recorded.
