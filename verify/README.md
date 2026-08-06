# verify-java — Offline Intyga receipt verification for Java

Independently confirm that a human cryptographically approved **exactly** the action you are about to run — in your own process, with no Intyga secret and no network call. You recompute the canonical payload from your own parameters, check it byte-matches what was signed, and verify the human's **ES256** or **WebAuthn** signature.

One runtime dependency (Jackson, for JSON — Java has no stdlib JSON). All cryptography is the JDK's own: SHA-256 and P-256 ECDSA, no crypto library. Its canonicalization is held byte-identical to the TypeScript, Python, Go and Rust verifiers by the shared cross-language test vectors in `packages/mcp-schemas/vectors/`.

> Status: **not yet published** to Maven Central. Build it locally with `mvn install` in this directory.

## Install

```xml
<dependency>
  <groupId>com.intyga</groupId>
  <artifactId>intyga-verify</artifactId>
  <version>0.1.0</version>
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
    VerifyOptions.defaults());
if (!res.ok()) {
  throw new IllegalStateException("refusing to proceed: " + res.reason());
}
```

A receipt arrives from the client as raw JSON; `ApprovalReceipt.parse(...)` accepts either a `String` or the `JsonNode` that `com.intyga.sdk.ApprovalResult.receipt()` returns.

**One-approver-per-key caveat.** In public-keys mode the identity IS the key, so an M-of-N quorum counts credentials, not people: one approver whose two registered credentials are both listed satisfies a 2-of-N alone. For `requiredApprovals` > 1 use the DID/identity form (`ApproverTrustAnchor.ofDidsMultiKey`), which counts distinct approvers (DIV §4.4.6).

One byte of drift — a swapped target, an appended region — and verification fails, because the signature was over the exact bytes you just recomputed.

## WebAuthn (passkey) receipts

A passkey assertion harvested at *any* relying party would otherwise verify, so WebAuthn receipts require you to pin the expected origin and RP ID:

```java
VerifyOptions opts = VerifyOptions.builder()
    .expectedOrigin("https://app.example.com")
    .expectedRpId("app.example.com")
    .build();
```

`requireUserVerification` defaults to true (demands the User-Verified flag); set it to `false` to accept mere user presence. Policy `AUTO_APPROVED` receipts carry no human signature and fail closed unless you opt in with `allowAutoApproved(true)`.

## Offline approvals and delegations

`Verify.verifyDelegation(...)` checks a DIV §5a.5 delegation — a statement, signed in advance by the ordinary quorum, naming local operators who may approve one pre-declared action while the gateway is unreachable. It is a separate method because a delegation authorizes nothing on its own: `verifyApprovalReceipt` refuses that payload type outright, with no opt-in. Pass the resulting `VerifiedDelegation` as `VerifyOptions.delegation(...)` together with `allowOffline(true)` when verifying the offline approval the delegated operators signed. The 60-minute offline window and 72-hour delegation window are enforced here, not merely at mint.

## DEWP conformance

This port implements the **DEWP Core primitives** ([`docs/DEWP.md`](../../docs/DEWP.md) §9.1): domain-separated hashing (`0x00`/`0x01`/`0x02`/`0x03`), two-tier Merkle tree construction with duplicate-last balancing, leaf-to-root inclusion proof verification **bounded by leaf position** (§11.1), the `trust.intyga.audit.v1` canonical preimage, the `0x03` anchor digest, and **anchor signature (single-anchor, ES256)** over the raw 32-byte digest. Byte parity with the TypeScript reference is locked by `packages/mcp-schemas/vectors/ledger-vectors.json`.

It does **not** implement, and a caller should not assume:

- **Anchor quorum verification** (§5.3). Single-anchor ES256 signature checking is provided; Ed25519/RSA-PSS anchors, evaluating `requiredAnchors` / issuer trust and divergence detection are not. `anchorVerified` therefore cannot be established by this port alone.
- **Proof bundle parsing and the §7.1 verification levels.** This port verifies proofs, not envelopes.
- **Evidence bundles, `tenantSeq` gapless validation, and NDJSON streaming** (§9.2 Extended Profile).
- **The §5.4 checkpoint continuity chain (`0x04` domain tag).** Roots-file transport, outside Core (DEWP §9.1); implemented by the TypeScript verifier only.
- **DIV §4.4.4 verification-code derivation.** The short display code is a human-factors aid that MUST NOT be treated as authentication, so this port carries `verificationCode` as an unvalidated field (TypeScript and Python assert those vectors).
- **DIV §5b Agent Authority** (`div-agent-authority` payloads). TypeScript-only. This port's approval verifier correctly REFUSES the payload type — an authority authorizes no action — it just cannot verify one as governance evidence.

One further precision about the portable-number rule (DEWP §4.3.1). This port refuses a non-portable number rather than best-effort serializing it, like `verify-go` — with a single exception it is not able to see: Jackson normalizes an integer-form `-0` to `0` while parsing, so the sign is gone before the check runs and that one value is serialized as `0`. The float form `-0.0` is refused correctly. No conformant producer emits either (JavaScript's `JSON.stringify(-0)` is already `"0"`, and the reference producer refuses at ingestion), so this is reachable only from a hand-authored or foreign document. The spec permits both responses, so the behaviour is conformant either way; it is stated here because "refuses" would otherwise be very slightly overclaiming.

For the rest of the surface — signed multi-anchor quorum, evidence bundles, gapless `tenantSeq` completeness over committed events, and the four-property verification model — use the TypeScript verifier (`@intyga/verify`). Note that no implementation, the TypeScript one included, currently claims the §9.2 **Extended Profile**: it also requires NDJSON evidence streaming (§6.4), which is specified but not yet implemented anywhere.

## Also available in
- TypeScript — [`@intyga/verify`](https://github.com/intyga-dev/verify)
- Python — [`intyga-sdk`](https://github.com/intyga-dev/sdk-python)
- Go — [`verify-go`](https://github.com/intyga-dev/verify-go)
- Rust — [`intyga-verify`](https://github.com/intyga-dev/verify-rust)

For a full client that *requests* approvals (not just verifies them), see [`sdk-java`](../sdk-java).

## License

Apache-2.0.
