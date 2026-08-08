# Changelog

All notable changes to `com.intyga:intyga-sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

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
