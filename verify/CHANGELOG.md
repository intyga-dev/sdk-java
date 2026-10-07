# Changelog

All notable changes to `com.intyga:intyga-verify` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org/).

## [Unreleased]

## [1.2.0]

- No code change. The matched set moves together (`pnpm test:versions`); this release carries the
  DIV §5a offline-approval layer in every SDK (`docs/OFFLINE-APPROVAL-SDK.md`).

## [1.1.0]

- No code change. The matched set moves together (`pnpm test:versions`); this release carries the
  new `@intyga/sdk` CLI options and the `require-approval` Action update.

## [1.0.0]

- Packaging: add Central developer/SCM metadata and a `release` profile producing source and Javadoc
  jars; include the license and changelog in the runtime jar. Signing and publishing remain in the
  separate release enforcer.

- Verify profile-carried WebAuthn audit signatures with caller-trusted signer keys, origin and RP ID.
  Report explicit per-event signature status and key trust; add strict signature acceptance for
  single and bulk evidence. Audit signature checks do not replace full approval-receipt verification.

- **DIV/DEWP 1.0 pre-release correction (2026-09-27 review L15-L18, L20, I7, I8):** signed timestamps
  use one strict RFC 3339 grammar (`OffsetDateTime.parse` accepted a missing seconds field and
  lowercase separators; offsets beyond ±18:00 are now accepted like the other ports). RFC 3161
  `genTime` parses with the STRICT resolver (`uuuuMMddHHmmss`), so 30 February is refused rather than
  read as 28 February. `Canonical.stableStringify` refuses an unpaired surrogate instead of escaping
  it (DIV §4.1). A WebAuthn `topOrigin` differing from `origin` is refused. `verifyPlatformReceipt`
  ignores `requireUserVerification(false)`. A key mapped to two DIDs counts once toward a quorum.
  RSA-PSS anchors require a 32-byte salt and a 2048-bit modulus (the salt used to be recovered from
  the signature). Divergence evidence is held to the quorum's seq-range and witness-time rules; a
  Rekor entry establishes divergence only with submitter keys pinned. Pinned in all five languages by the `verifierInputHardening` parity vectors; no canonical bytes change for valid input.
- **DIV 1.0 pre-release correction (H1):** add `RequirementFloor` and a `requirement` component to
  `Expected` (`withRequirement(...)`, seven-argument constructor) and `AgentAuthorityExpected`
  (four-argument constructor), applied by `verifyApprovalReceipt`, `verifyDelegation` and
  `verifyAgentAuthority`. The existing constructors are unchanged. The signed `requirement` is
  authored by the signers, so one approver (possibly the requester) could self-compose a 1-of-1
  receipt for a 3-of-3 four-eyes action and it verified. A weaker signed requirement is now refused
  before any signature is counted when the caller supplies its own rule (DIV §5 step 3d), on approval,
  offline, delegation and agent-authority verification; the reason starts "signed requirement is
  weaker than the relying party's policy". Omitting the floor keeps the previous behaviour, which
  proves only the quorum the signers stated. No signed byte changes; shared parity vectors pin it in
  all five languages.
- **DEWP evidence verification (1.0 pre-release correction, Sep 2026):** an entry with a canonical
  preimage reads `tenantSeq` only from it (null ⇒ no counter) and fails when its redaction counter
  disagrees; a tenant-bound entry fails when the bundle declares no tenant; a preimage under an
  unknown profile fails; repeated leaves/seqs and inconsistent leaf counts fail; a checkpoint with no
  `chainHash`/`anchoredAt` is never anchored. New trailing record components
  `EvidenceOptions.trustedCheckpoints` and `BundleOptions.trustedCheckpoint`
  (`Ledger.TrustedCheckpoint`, previous constructors kept) take caller-held roots-file records; a
  single proof counts a Rekor/TSA anchor only against one. `Ledger.isWellFormedAnchor` requires a
  registered algorithm. Pinned by the shared `dewpEvidenceHardening` vectors.
- **DIV 1.0 pre-release correction (PK-11):** under a signed `requireHardwareKey`, a WEBAUTHN witness
  whose signed authenticatorData carries the Backup Eligible or Backup State flag no longer counts
  toward the quorum (DIV §4.4.5 rule 6) — a relying party now catches an issuer that let a synced
  passkey sign a hardware-pinned action. No signed byte changes; shared parity vectors pin it in all
  five languages.
- **Breaking (DEWP 1.0 pre-release correction):** the anchored preimage is now
  `[dailyRoot, timestamp, issuer, algorithm, seqStart, seqEnd, chainHash]`; anchors lacking the
  position fields never verify. External witness times (Rekor `integratedTime`, TSA `genTime`) must
  fall within `maxAnchorLagSeconds` (default 86400) after — or 300 s before — the checkpoint's claimed
  time; anchors must match the checkpoint's seq range, chain hash and `anchoredAt`; evidence-bundle
  chain hashes are recomputed; verdicts expose per-issuer witness times; an optional pinned Rekor
  submitter key is enforced. A supplied root is reported as `rootSource: "caller-supplied"` (was
  `"independent"`).
- A non-empty `allowedAaguids` is refused exactly like `requireHardwareKey`: bare-key witnesses do not
  count and offline proofs are rejected (DIV §4.3.2/§5a.3).

- Add opt-in RFC 3161 TimeStampToken verification through OpenSSL 3, with caller-pinned TSA
  certificate/CA trust, explicit offline CRL or unchecked revocation, and quorum/bundle integration.
- Scope Rekor log-key trust to one issuer for multi-issuer policies; legacy unscoped keys remain
  accepted only when the policy trusts exactly one issuer.

- Enforce DIV §5 identity trust for multi-approver quorums; preserve DIV §4.4.2 ES256
  compatibility for absent/null/unknown witness labels, while refusing AUTO_APPROVED witnesses.
- Validate DEWP protocol, version and declared hash/serialization/Merkle algorithms before
  accepting proof or evidence bundles. Legacy numeric revisions 1/2 remain supported without
  a protocol declaration. Shared cross-language fixtures cover these contracts.

- **Wire format: DIV v1 agent intents now sign `action`, `agent`, `session`, `nbf`, and `exp` instead of ordinary `expiresAt`; `div-agent-authority` requires `parentReceiptHash` (null for a root).** Older §5b seals lacking that key cannot verify under this pre-release profile and must be re-sealed. All canonical producers, five verifier ports and vectors must move together; the ordinary HUMAN/SERVICE intent keeps `expiresAt`.

- **Wire format: the DIV Intent Payload gained a REQUIRED `evidence` field, and it must be `null`.**
  `div-intent-verification` and `div-offline-intent` now carry `"evidence":null` in the signed bytes
  (DIV §4.3.4); `div-delegation`, `div-agent-authority` and `div-platform-intent` deliberately do
  not. `null` is signed and load-bearing, exactly as `requester.attestation`'s null is: it is the
  payload's explicit statement that the authorization was not conditioned on any external fact.
  Verification refuses a payload whose `evidence` key is absent, and refuses any non-`null` value
  rather than treating it as unconditioned — the same fail-closed-on-unknown rule as the
  `signerClass` registry, and checked before Local Payload Reconstruction so an unsupported payload
  shape does not surface as a parameter mismatch. Absent and `null` are distinguished explicitly;
  collapsing them would make the check a no-op. All golden vectors were regenerated.

- Align cross-language receipt and audit verification: platform receipts, agent-authority seals,
  self-certifying DID trust, single/multi-event bundles, embedded ES256 signatures, tenant sequence
  checks, checkpoint continuity, anchor quorum and Rekor. Shared executable fixtures cover valid
  artifacts and refusals; no wire format changes.
- Refuse unknown witness signature algorithms. Require identity-bound trust when the signed
  `requesterCannotApprove` rule is set; key-only trust cannot enforce requester identity.
- **`verifyRootsChain` range-checks the FIRST entry.** The non-integer and self-inverted seq-range
  checks were gated on having a predecessor, so the first entry was never range-checked — and a
  single-entry `roots.jsonl` (a new tenant, or the first day after a truncation) is exactly where
  the first entry is the only one. Such a file verified clean here while Go and Rust refused it.
  Only the overlap check is relational now. New `single-entry-inverted-seq-range` and
  `single-entry-non-integer-seq-range` parity vectors pin it in all five ports.
- Report a partially chained roots file as `roots file mixes chained and unchained entries` with
  `verifiedCount` 0, decided before the loop — it used to fall into the loop and credit the entries
  preceding the splice, under a reason string no other port used.

- Recheck a verified delegation's expiry when it is used, under the approval call's `asOf`, clock
  skew and explicit `allowExpired` forensic override.
- **Refuse a forward-dated offline proof or delegation (DIV §5a.3 rule 3, §5a.6 step 1).** The
  window caps bounded a proof's WIDTH but never its POSITION, so a quorum-signed proof dated years
  ahead with a compliant 60-minute (or 72-hour) window verified today and kept verifying until that
  date. The check is unconditional — the audit/`allowExpired` override re-examines a proof that was
  valid and has lapsed, and does not reach one dated in the future.
- **Refuse a signed `requirement.requiredApprovals` below 1 (DIV §4.3.2).** §5 step 7's "at least
  `requiredApprovals`" is satisfied vacuously by 0, so the minimum is now enforced explicitly
  instead of by an undocumented floor.
- **Range-check ECDSA `r` and `s` before handing a signature to the platform provider.** On JDK
  15-18 before 17.0.3 (CVE-2022-21449) an all-zero signature verifies under any key, which in this
  library is a total verification bypass. `verify-go` and `verify-rust` reject zero scalars inside
  their crypto libraries; Java delegated the whole check to the JDK, and this port targets release
  17.
- **Fail closed on a missing `expected.Target`, `expected.Nonce` or `expected.Approvers`.**
  `verifyApprovalReceipt` coerced an absent target and nonce to `""` and dereferenced a null trust
  anchor; all three now return the refusal the TypeScript reference does (DIV Target Isolation, §5
  step 10, Invariant 3). `verifyDelegation` gained the same anchor guard, which it previously
  null-checked in one place and dereferenced in another.
- **Return a refusal instead of throwing on malformed attacker-supplied JSON.** A null entry inside
  `signatures`, a null inside `allowedAaguids`/`delegatedTo`, and a null `bounds`/proof step in
  `Ledger.verifyMerkleProof` each raised a `NullPointerException` out of a method documented to
  return a result. Canonicalization is unchanged: a null set element sorts as the text `null`,
  exactly as the TypeScript reference's default comparator does.
- **Canonicalize `BigDecimal` params** — the type a mapper configured with
  `USE_BIG_DECIMAL_FOR_FLOATS` produces — accepting it only when the shortest form of the
  corresponding double reads back as the same number, so Java can never emit digits another port
  would not.


Initial public release.

- Offline DIV receipt verification: canonical payload recomputation (RFC 8785 JCS), ES256 and
  WebAuthn signature checking, distinct-identity quorum counting, four-eyes, expiry with clock skew,
  and the fail-closed `signerClass` rule.
- Offline approvals (DIV §5a) behind an explicit opt-in, with the 60-minute window enforced at
  verification; `verifyDelegation` for §5a.5 delegations, with the 72-hour window and the refusal to
  let a delegation authorize anything by itself.
- DEWP Core Profile ledger verification: domain-separated hashing, duplicate-last Merkle trees,
  position-bounded inclusion proofs (§11.1), the `trust.intyga.audit.v1` preimage, and single-anchor
  ES256 signatures over the raw 32-byte digest.
- Canonicalization is pinned by the shared golden vectors in `packages/mcp-schemas/vectors/`, so
  Java is a sixth mirror of the canonical payload builder and moves with the other five.
- Doubles are formatted as the shortest round-tripping decimal rather than via `Double.toString`,
  which emits extra digits before JDK 19 — a receipt verified on Java 17 and one verified on Java 21
  must recompute identical bytes.
- Cryptography is the JDK's own (SHA-256, P-256 ECDSA); the only declared runtime dependency is
  `jackson-databind` (which brings `jackson-core` and `jackson-annotations` transitively), because
  Java has no standard-library JSON.
