# Changelog

All notable changes to `com.intyga:intyga-sdk` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [2.1.0]

- `IntygaClient.reportDispatched` / `submitEvidence` (DEWP 1.1 §4.7) and
  `ApprovalResult.execution` (previous constructors remain).
- `EvidenceSource.buildExecutionEvidence` / `signExecutionEvidence` — the evidence source's side of
  DEWP §4.7, as in every other SDK. The statement carries `sampledAt` (when the measurement was
  taken; defaults to `observedAt`, and the verifier's window is evaluated on it) and the source's
  own gapless per-log `sequence` (required: it is what lets a verifier see a withheld statement),
  and is signed ES256 (IEEE P1363) with a P-256 key given as a `PrivateKey`, a PEM (PKCS#8 or SEC1)
  or key-file bytes; any other key is refused. `com.intyga.sdk.offline.P256` is now public so both
  signers share one key loader.
- `EvidenceSourcesFile.parse(text)` / `evidencePolicy()` — the relying party's `intyga-evidence-sources`
  trust file (docs/API.md §2e) loaded into `verify-java`'s `ExecutionEvidence.Policy`, as in every
  other SDK. It throws `InvalidEvidenceSourcesException` on the first problem: `v` must be the
  integer `1`, a key is a base64 SPKI string or an object with exactly `key`, `notBefore` and
  `notAfter` (a misspelt bound is refused, never read as "no bound"), and every bound is a real
  DEWP §4.3 instant with `notBefore` not later than `notAfter`. Source and key order are preserved.
  It passes every `executionEvidence.trustFiles` case of the shared `verifier-parity-vectors.json`
  on JDK 17 and 21.
- `ApprovalGuard.wrap` for framework-neutral JSON tool callbacks: detached arguments, caller-trusted
  receipt verification and checked single-use consumption before execution. Optional DEWP dispatch
  reporting preserves results and exceptions and provides the nonce for report retries.
  `tenantId` is the independently trusted tenant DIV v2 receipts require, as in the Python guard.

## [2.0.0]

- Bind delegation verification to the independently expected requester; a workload cannot reuse
  another workload's otherwise valid delegation.

- **Breaking: tenant-bound DIV v2 approvals.** Requests and offline approvals carry the tenant
  established by authenticated credentials or a verified trust bundle. Receipt verification requires
  an independently trusted tenant; a receipt cannot choose its own verification context.
- Trust bundles require a nonempty signed `tenantId`; trust-anchor files may pin the expected tenant.
  Offline-intent anchors require an explicit eligible-DID restriction, so delegate keys cannot
  broaden a selected rule's approver set. Ordinary anchors keep their existing behavior.
- Includes the matched 2.0.0 verifier and shared tenant-binding and offline-approval vectors.
  Historical v1 receipts remain verifiable without a tenant expectation; new tenant-bound execution
  refuses them. Publish the full matched set and upgrade consumers before the gateway cutover.

## [1.2.0]

- **Offline approval (DIV §5a), the SDK half**, to the contract in `docs/OFFLINE-APPROVAL-SDK.md`,
  in the new package `com.intyga.sdk.offline`. It passes every case of the shared
  `offline-approval-vectors.json` on JDK 17 and 21. No new dependency: JDK crypto and Jackson only.
  - Trust bundles: `TrustBundle.verify` (RS256 compact JWS against a pinned RSA JWK; the header
    cannot choose the algorithm), `checkFreshness` (expiry plus the inclusive 30-day age cap, under
    the strict DIV §6.2 timestamp grammar), `save` / `load` (private files), `approverAnchor` /
    `approverDirectory` (offline signing keys only under `AnchorPurpose.OFFLINE_INTENT`) and
    `requirementFor` (exact-ID v3 selection; refuses on any conflict). The policy checks are public
    in `ApprovalPolicy`: `validateExactApprovalPolicy`, `lostApprovalConstraints`,
    `selectExactApprovalRule`, `validApprovalActionId`, with `ApprovalPolicyConflict`.
  - Trust-anchor files: `TrustAnchorFile.parse(text, TrustAnchorPurpose)` (`ONLINE` default, or
    `OFFLINE`), refusing with `InvalidTrustAnchorException`.
  - Ceremony: `OfflineApproval.createOfflineChallenge` (requirement from the bundle, never the
    caller; timestamps exactly as JavaScript's `toISOString()`; a supplied empty nonce is refused,
    never replaced; a blank target is refused), `decodeChallengeEnvelope` (shapes before bytes:
    the string fields must be strings, the target not blank under JavaScript `trim()` semantics,
    `params` / `requirement` / `requester` objects),
    `encodeSignatureEnvelope` / `decodeSignatureEnvelope` (byte-identical `SIG1:` JSON across SDKs,
    strict base64url), `signChallengeEnvelope` (from a `PrivateKey`, a `KeyPair`, a PKCS#8 or SEC1
    `EC PRIVATE KEY` PEM — what `openssl ecparam -genkey` writes — or DER PKCS#8; other curves and
    encrypted keys are refused; the envelope's SPKI is derived from the private key), `signingPublicKey`,
    `assembleOfflineReceipt`, `verificationCode`.
  - `OfflineApproval.useOfflineApproval` runs the whole approval: delegation pick-up (name order),
    signature collection, verification with the offline opt-in against the bundle rule's floor,
    buffering, then single-use redemption through `FileRedemptionStore` (exclusive create).
    `pendingApprovals` / `readPendingApprovals` / `clearPendingApproval` read and clear the
    reconciliation buffer. On-disk layout matches every other SDK.
  - Client: `RequireApprovalOptions.Builder.offline(...)` opts in per call. The fallback runs only
    when the gateway could not be asked (a connection failure or timeout, a 5xx, or five consecutive
    polling failures of those kinds — a streak that includes a refusal rethrows its FIRST refusal),
    never on a response whose body could not be read (an answer, not an outage), a 4xx, `DENIED`, `EXPIRED`, a local error, an interrupt or an
    agent-continuity request, and returns the new `ApprovalStatus.OFFLINE_APPROVED`, never
    `APPROVED`. A fallback that ran and failed throws `OfflineApprovalFailedException`.
    `requireApprovalOrThrow` refuses offline options (it would throw an offline approval away).
    `reconcileOfflineApprovals` reports buffered approvals, clears each only on a 2xx, and counts an
    unreadable record as a failure rather than skipping it (`ReconcileResult`).
- `ApprovalStatus` gains `OFFLINE_APPROVED`. An exhaustive `switch` over it needs the new case.

## [1.1.0]

- No code change. The matched set moves together (`pnpm test:versions`); this release carries the
  new `@intyga/sdk` CLI options and the `require-approval` Action update.

## [1.0.0]

- Packaging: add Central developer/SCM metadata and a `release` profile producing source and Javadoc
  jars; include the license and changelog in the runtime jar and in both standalone reactor modules.
  Signing and publishing remain in the separate release enforcer.

- **Security (I11):** `IntygaClient.Builder.build()` throws `IllegalArgumentException` for a
  `gatewayUrl` that is not `https://`, except `http://` to a loopback host (`localhost`,
  `127.0.0.0/8`, `::1`) for local development.

- Refuse approvals received after the caller's monotonic wait deadline; include challenge creation
  in the wait window and cap polling sleeps to its remaining duration.

- Preserve challenge-issued agent context through approval polling for DIV continuity checks.
- Public witness lookups require no credentials and refuse non-success HTTP responses.
- Default HTTP transports use finite request timeouts and refuse redirects; caller-supplied
  transports remain the caller's responsibility.

- Rebuilt against the DIV Intent Payload's new REQUIRED `evidence` field (DIV §4.3.4), which is
  `null` in this version. No API change; receipts carry the field inside `canonicalPayload` only.

- `authorize` now omits `actionType` when unset, matching the gateway's optional field schema.
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
