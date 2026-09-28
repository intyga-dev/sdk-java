# verify-java — Offline Intyga receipt verification for Java

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no Intyga secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

Java 17 or newer. One declared runtime dependency — `jackson-databind`, for JSON, since Java has no stdlib JSON — which brings `jackson-core` and `jackson-annotations` transitively, so three jars in total. All cryptography is the JDK's own: SHA-256 and P-256 ECDSA, no crypto library. Its canonicalization is held byte-identical to the TypeScript, Python, Go and Rust verifiers by the shared cross-language test vectors in `packages/mcp-schemas/vectors/`.

> Status: **not yet published** to Maven Central. Build it locally with `mvn install` in this directory.

## Install

```xml
<dependency>
  <groupId>com.intyga</groupId>
  <artifactId>intyga-verify</artifactId>
  <version>1.0.0</version>
</dependency>
```

`com.intyga:intyga-sdk` (the [Java client](../sdk-java)) already depends on this package, so a service that requests approvals can verify them without adding a second dependency.

## Verify an approval receipt

```java
import com.intyga.verify.*;
import java.util.List;
import java.util.Map;

// `expected` is what you are ABOUT to execute. target is YOUR OWN identifier (Target Isolation),
// nonce is the challenge YOU issued, and approvers is the key set YOU trust — all required, and
// none of them ever read from the receipt.
VerifyResult res = Verify.verifyApprovalReceipt(
    receipt,
    new Expected(
        "prod-db-cluster-01",
        nonce,
        "wipe_production",
        Map.of("database", "prod-db-1"),
        ApproverTrustAnchor.ofPublicKeys(List.of(approverSpkiB64))),
    // REQUIRED for passkey receipts (the normal flow): the approval console's exact origin and RP
    // ID, from the trust-anchor file exported in the console (its `webauthn` block).
    VerifyOptions.builder()
        .expectedOrigin(System.getenv("INTYGA_WEBAUTHN_ORIGIN"))
        .expectedRpId(System.getenv("INTYGA_WEBAUTHN_RP_ID"))
        .build());
if (!res.ok()) {
  throw new IllegalStateException("refusing to proceed: " + res.reason());
}
```

A receipt arrives from the client as raw JSON; `ApprovalReceipt.parse(...)` accepts either a `String` or the `JsonNode` that `com.intyga.sdk.ApprovalResult.receipt()` returns.

**Quorum trust.** Key-only trust is accepted only for a one-approval requirement without
`requesterCannotApprove`. Multi-approver quorums and separation of duties require a DID/identity
anchor and otherwise fail closed (DIV §5 step 3b). Several credentials for one DID count as one
approver. Delegations require identity trust regardless of quorum size.

**Requirement floor (DIV §5 step 3d).** The signed `requirement` is the signers' own statement: its
signature stops a third party from altering it, not the approvers it constrains from writing a weaker
one. One approver who is also the requester can sign a 1-of-1 payload alone. **Without a floor this
verifier proves only the quorum the signers stated.** When you know the rule, pass
`expected.withRequirement(new RequirementFloor(3, true, false))` (or the seven-argument `Expected`
constructor; `AgentAuthorityExpected` takes it as a fourth argument). Null keeps the previous
behaviour, and the existing constructors are unchanged.
A signed requirement weaker on any field — fewer approvals, no four-eyes or no hardware key where the
floor demands one — is refused before any signature is counted, with a reason starting "signed
requirement is weaker than the relying party's policy"; an equal or stricter one passes. A malformed
floor (quorum below 1) is refused rather than ignored. The same field exists on the delegation
expectation (pass the ordinary rule) and the agent-authority expectation (your sealing policy).

One byte of drift — a swapped target, an appended region — and verification fails, because the signature was over the exact bytes you just recomputed.

**Refusals that are the design, not a bug.** A receipt whose signed `requirement.signerClass` is absent, or is anything other than `human`, is refused (DIV §4.3.2): `human` is the only class defined today, and a verifier that treated an unrecognized one as human-approved would be the failure mode the registry exists to prevent. A deployed verifier refusing a class it predates is the intended migration path for the future delegated-agent work. A signed `requiredApprovals` below 1 is refused for the same fail-closed reason — "at least 0" is satisfied by counting nothing.

## WebAuthn (passkey) receipts

A passkey assertion harvested at *any* relying party would otherwise verify, so WebAuthn receipts require you to pin the expected origin and RP ID:

```java
VerifyOptions opts = VerifyOptions.builder()
    .expectedOrigin("https://app.example.com")
    .expectedRpId("app.example.com")
    .build();
```

`requireUserVerification` defaults to true (demands the User-Verified flag); set it to `false` to accept mere user presence (`verifyPlatformReceipt` ignores it: DIV §5c.3 requires user verification unconditionally). Policy `AUTO_APPROVED` receipts carry no human signature and fail closed unless you opt in with `allowAutoApproved(true)`.

## Offline approvals and delegations

`Verify.verifyDelegation(...)` checks a DIV §5a.5 delegation — a statement, signed in advance by the ordinary quorum, naming local operators who may approve one pre-declared action while the gateway is unreachable. It is a separate method because a delegation authorizes nothing on its own: `verifyApprovalReceipt` refuses that payload type outright, with no opt-in. Pass the resulting `VerifiedDelegation` as `VerifyOptions.delegation(...)` together with `allowOffline(true)` when verifying the offline approval the delegated operators signed. The 60-minute offline window and 72-hour delegation window are enforced here, not merely at mint, and neither may be dated in the future.

`verifyDelegation` requires a **DID-mode** trust anchor (`ApproverTrustAnchor.ofDids` / `ofDidsMultiKey`) and refuses a public-keys anchor at seal verification, whatever the quorum size: the sealing quorum names people, and a key set cannot associate identities (DIV §4.4.6). Every port refuses this identically.

## DEWP conformance

This port implements the TypeScript verifier's in-memory DEWP surface: the Core primitives,
single-proof and evidence-bundle JSON readers, the §7.1 verification properties and levels,
embedded ES256 verification, gapless committed `tenantSeq` validation, the `0x04` checkpoint
continuity chain, and anchor quorum for ES256, Ed25519, RSA-PSS, and caller-pinned Rekor SET
evidence. Byte parity is pinned by the shared vectors in `packages/mcp-schemas/vectors/`.

Additional receipt APIs and remaining limits:

- **NDJSON evidence streaming** (§6.4). The TypeScript reference also does not implement it, so
  no implementation currently claims the complete §9.2 Extended Profile.
- **DIV §4.4.4 verification-code derivation.** The short display code is a human-factors aid that MUST NOT be treated as authentication, so this port carries `verificationCode` as an unvalidated field (TypeScript and Python assert those vectors).
- **DIV §5b Agent Authority** is verified separately with `Verify.verifyAgentAuthority`; the
  ordinary approval verifier continues to refuse it because a scope grant approves no action.
- **DIV §5c Platform Hash-Only Intent** is verified separately with
  `Verify.verifyPlatformReceipt`, including mandatory WebAuthn origin/RP binding.
- **The document-signing payload** (`canonicalDocumentPayload`). This port carries no document canonicalization and does not assert the `documentPayloads` vector section — as `verify-go`, `verify-rust` and `sdk-python` also deliberately do not: the section's own note marks it TS-only (document signing is a gateway-side ceremony, not part of the relying-party offline surface). Approval and ledger canonicalization are unaffected — it is document *signing* that is out of scope here.

One further precision about the portable-number rule (DEWP §4.3.1). This port refuses a non-portable number rather than best-effort serializing it, like `verify-go` — with a single exception it is not able to see: Jackson normalizes an integer-form `-0` to `0` while parsing, so the sign is gone before the check runs and that one value is serialized as `0`. The float form `-0.0` is refused correctly. No conformant producer emits either (JavaScript's `JSON.stringify(-0)` is already `"0"`, and the reference producer refuses at ingestion), so this is reachable only from a hand-authored or foreign document. The spec permits both responses, so the behaviour is conformant either way; it is stated here because "refuses" would otherwise be very slightly overclaiming.

Use `Dewp.verifyBundle` for one proof and `Dewp.verifyEvidenceBundle` for a multi-entry audit export.
Anchors sign the root, timestamp, issuer, algorithm, sequence range and checkpoint chain hash;
anchors missing the position fields are refused. Evidence bundles compare those fields against
their checkpoint and recompute its chain hash. For direct `Ledger.verifyAnchorQuorum` calls,
pass an `ExpectedCheckpoint` containing every checkpoint field you know.

`AnchorPolicy.maxAnchorLagSeconds` defaults to 86400 seconds. Rekor's authenticated
`integratedTime` and the TSA's `genTime` must fall between 300 seconds before the checkpoint's
claimed time and that lag limit after it. `witnessTimes` on quorum results, proof-bundle results
and evidence-bundle roots reports the earliest authenticated time per issuer, including evidence
rejected for excessive lag. SELF anchors supply no independent witness time. To restrict who
submitted a Rekor entry, configure `rekorSubmitterKeys` with the producer's PEM or base64 SPKI
public keys; without those pins the log proves inclusion and time, not producer identity.

A supplied root is labelled `rootSource: "caller-supplied"`; the verifier cannot determine whether
the caller obtained it independently. Both bundle APIs require caller-supplied roots for a
trustworthy verdict; quorum keys likewise come from the
caller's policy, never the bundle. Bundle-carried anchors cannot establish divergence; use the
checkpoint-keyed caller anchor map for that. RFC 3161 anchors count when caller-owned
`Rfc3161.Trust` is supplied by issuer. The optional adapter invokes an installed OpenSSL 3 binary
without network access, pins the CA and signer certificate digest, and requires an explicit
`crl` (with offline CRL) or `unchecked` revocation choice. A caller-selected evaluation time is
supported; the default rounds now up by at most one second for fresh fractional timestamps.
Historical verification checks certificate validity at issuance but cannot reconstruct historical
revocation state. WEBHOOK evidence does not count toward
quorum. For a multi-issuer policy, pass `rekorIssuer` with the Rekor public key; an unscoped legacy
key is accepted only when exactly one issuer is trusted, so producer-selected labels cannot turn one
log into multiple quorum witnesses. Authority verification checks the seal but cannot discover
later online revocation.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Python — [`verify-python`](https://github.com/intyga-dev/verify-python)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Rust — [`intyga-verify`](https://github.com/intyga-dev/verify-rust)

For a full client that *requests* approvals (not just verifies them), see [`sdk-java`](../sdk-java).

## License

Apache-2.0.
