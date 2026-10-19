# sdk-java — INTYGA client for Java

[![Release gated by INTYGA](https://www.intyga.com/badges/release-gated-by-intyga.svg)](https://www.intyga.com/use-cases/package-publishing)

Gate any high-risk backend action behind a real human approval. The primitive is uniform: **request a challenge → a human approves with a passkey or security key → poll until resolved** — the same client works for scripts, pipelines, and AI agents.

The example below uses a human or `SERVICE` key. `AI_AGENT` keys must pass
`AuthorizeOptions.agentContext(...)`; the executing service must independently check live
configuration, the signed session sequence and aggregate, and a budget across sessions (DIV §4.3.6).

This package **bundles the offline verifier** ([`com.intyga:intyga-verify`](https://github.com/intyga-dev/verify-java)), so you can request an approval *and* independently verify the receipt without adding a second dependency.

> Building from source: `mvn install` at this repository's root, whose aggregator reactor builds the bundled verifier before the client that
> depends on it. (Working in the INTYGA monorepo instead? There is no aggregator there — `mvn install`
> in `packages/verify-java`, then in `packages/sdk-java`.)

Runtime dependencies: `com.intyga:intyga-verify` and Jackson (`jackson-databind`) for JSON — Java has no stdlib JSON. HTTP is the JDK's built-in `java.net.http`, and all cryptography is the JDK's own. Nothing else.

## Install

```xml
<dependency>
  <groupId>com.intyga</groupId>
  <artifactId>intyga-sdk</artifactId>
  <version>2.1.0</version>
</dependency>
```

Gradle: `implementation("com.intyga:intyga-sdk:2.1.0")`.

## Require a human approval before a high-risk action

```java
import com.intyga.sdk.*;
import com.intyga.verify.*;
import java.util.Map;

IntygaClient client = IntygaClient.builder()
    .gatewayUrl("https://api.intyga.com")
    .clientId(System.getenv("INTYGA_CLIENT_ID"))
    .clientSecret(System.getenv("INTYGA_CLIENT_SECRET"))
    .build();

Map<String, Object> params = Map.of("database", "prod-db-1");

// Blocks until the human approves with their passkey / security key (or times out — a timed-out
// wait RETURNS status EXPIRED rather than throwing; the default wait is 120s).
// target names THIS relying party. It is required: it is what stops an approval minted here from
// being replayed at a different service (DIV §3 Invariant 5, Target Isolation).
ApprovalResult r = client.requireApproval("Delete production database",
    RequireApprovalOptions.builder()
        .authorize(AuthorizeOptions.builder()
            .target("prod-db-cluster-01")
            .actionType("wipe_production")
            .params(params)
            .build())
        .build());
if (r.status() != ApprovalStatus.APPROVED) {
  throw new IllegalStateException("not authorized: " + r.status());
}

// Re-verify locally before executing. This is not optional under DIV §5: the relying party checks
// the signature itself, against a key IT resolved. approvers is required for exactly that reason —
// a receipt checked against its own embedded key proves only that the receipt is self-consistent.
VerifyResult check = Verify.verifyApprovalReceipt(
    ApprovalReceipt.parse(r.receipt()),
    new Expected("prod-db-cluster-01", r.nonce(), "wipe_production", params,
        ApproverTrustAnchor.ofPublicKeys(trustedApproverKeys())).withTenantId(System.getenv("INTYGA_TENANT_ID")),
    // REQUIRED for passkey receipts (the normal flow): the approval console's exact origin and RP
    // ID, from the trust-anchor file exported in the console (its `webauthn` block).
    VerifyOptions.builder()
        .expectedOrigin(System.getenv("INTYGA_WEBAUTHN_ORIGIN"))
        .expectedRpId(System.getenv("INTYGA_WEBAUTHN_RP_ID"))
        .build());
if (!check.ok()) {
  throw new IllegalStateException("refusing to proceed: " + check.reason());
}

// Redeem the approval exactly once, immediately before the action runs. Same target, same params:
// this is the gateway-side re-binding that makes the approval single-use.
ConsumeResult c = client.consume(r.nonce(), "prod-db-cluster-01", "wipe_production", params);
if (!c.ok()) {
  throw new IllegalStateException("could not consume the approval");
}
```

Agent receipts add signed continuity context; use the agent context expected by your service when
verifying them. A configuration digest is an RP claim, not an agent integrity attestation.

`requireApprovalOrThrow(...)` throws `ApprovalRefusedException` for a non-APPROVED status. It still
requires the local verification and consumption steps above. For a tool callback, `ApprovalGuard`
performs all three steps before executing.

> **Quorum caveat.** In public-keys mode the identity IS the key, so an M-of-N quorum counts credentials, not people — one approver whose two credentials are both listed satisfies a 2-of-N alone. For `requiredApprovals` > 1 use the DID/identity form, `ApproverTrustAnchor.ofDidsMultiKey` (DIV §4.4.6).

## Guard a tool callback

`ApprovalGuard.wrap` accepts a callback over a JSON object. Register the returned callback with your
tool framework (or invoke it inside a LangChain4j tool method). It detaches the arguments before
requesting approval, verifies the signed receipt against your trust and execution context, and
requires successful single-use consumption before the callback runs.

```java
import com.intyga.sdk.ApprovalGuard;
import com.intyga.verify.ApproverTrustAnchor;
import com.intyga.verify.RequirementFloor;

ApprovalGuard.Tool<String> guarded = ApprovalGuard.builder(
        client, ApproverTrustAnchor.ofPublicKeys(trustedApproverKeys()))
    .target("prod-db-cluster-01").actionType("db.restart")
    .requirement(new RequirementFloor(1, false, false))
    .expectedOrigin(System.getenv("INTYGA_WEBAUTHN_ORIGIN"))
    .expectedRpId(System.getenv("INTYGA_WEBAUTHN_RP_ID"))
    .tenantId(System.getenv("INTYGA_TENANT_ID")) // Independently trusted workspace; never read from the receipt.
    .reportDispatch(600) // Optional DEWP evidence window; zero disables reporting.
    .onDispatchError((nonce, error) -> queueDispatchRetry(nonce, 600))
    .build().wrap(args -> restartDatabase((String) args.get("cluster")));
String result = guarded.call(Map.of("cluster", "prod-db-1"));
```

Supply `trustedApproverKeys`, `queueDispatchRetry` and `restartDatabase` from your application.
Use DID trust for a quorum of distinct people. Pass `tenantId` from your trust anchor or other
independently trusted configuration; DIV v2 receipts are refused without it, and it is never
inferred from the receipt. The callback must execute from `args`, not captured
mutable inputs. The guard is blocking; its `Tool.call` can throw your callback's checked exceptions.
Optional dispatch reporting runs after a return or exception, and reporting/diagnostic failures
cannot replace the original result or exception. Reporting is best effort, not a durable outbox;
process exit can prevent it. The report window is 10–86400 seconds. Persist a retry by nonce if
needed; do not rerun the tool to retry its report.

This ordinary approval guard uses a human or `SERVICE` key. It does not implement the `AI_AGENT`
v1 runtime, session and budget gate; that integration remains in the TypeScript MCP adapter.

## Offline verification

`ApprovalResult.receipt()` is the signed receipt as raw JSON (`JsonNode`); `ApprovalReceipt.parse(...)` turns it into a verifier receipt with no re-serialization. `packages/verify-java`'s README states exactly what it verifies; read it before relying on a property it does not establish.

## API

- `IntygaClient.builder()` — `gatewayUrl` + either a pre-minted `token` or `clientId`/`clientSecret`; `build()` performs no I/O, and throws `IllegalArgumentException` unless `gatewayUrl` is `https://` (plain `http://` is accepted only for a loopback host — `localhost`, `127.0.0.0/8`, `::1` — for local development). An exchanged token is re-exchanged automatically shortly before the `expires_in` the gateway reports (and once more on a 401), so a long-lived client never has to manage tokens; a pre-minted `token` is used as given and never refreshed.
- `requireApproval(description, options)` — create a challenge and block until resolved (default 120s wait, 2s poll).
- `requireApprovalOrThrow(description, options)` — same, but non-APPROVED throws `ApprovalRefusedException`.
- `ApprovalGuard.builder(client, approvers).…build().wrap(tool)` — verified, consuming callback guard.
- `authorize` / `status` / `consume` — the individual steps (create, poll, execution-time re-bind). `authorize` requires a `target`; `consume` takes `(nonce, target, actionType, params)` and must be given the same target the approval was bound to.
- `verify(documentHash)` — public witness lookup.
- Exceptions: `GatewayRefusedException` (the gateway answered non-2xx; carries the status) vs `GatewayUnreachableException` (could not ask at all) — kept distinct because a policy refusal handled as an outage is a policy bypass.
- Offline verification: `com.intyga.verify.Verify.verifyApprovalReceipt(...)` — see [`verify-java`](https://github.com/intyga-dev/verify-java).

### Execution evidence (DEWP 1.1 §4.7)

After `consume`, `client.reportDispatched(nonce, evidenceWithinSeconds)` records that the action was sent to its target and how long an evidence source has to confirm it; `client.submitEvidence(nonce, statement, signature)` relays a statement an evidence source signed. The service never signs one — it does not hold the source's key. The source's side is `EvidenceSource`:

```java
// On the evidence source (a relay, a meter, an attester) — a party independent of the executing service.
String statement = EvidenceSource.buildExecutionEvidence(
    receipt.canonicalPayload(),        // the approved DIV Intent Payload; its SHA-256 binds the statement
    nonce, "did:example:relay-7", "confirmed",
    Map.of("breaker", "open", "currentA", 0),
    sequence,                          // the source's own gapless per-log counter — keep it durable
    "2026-10-05T14:02:09.500Z",        // sampledAt: when the measurement was taken (null = observedAt)
    null);                             // observedAt: null = now
String signature = EvidenceSource.signExecutionEvidence(statement, privateKey); // P-256 only; PEM and key-file overloads
client.submitEvidence(nonce, statement, signature);
```

The verifier's evidence window is evaluated on `sampledAt`, and `sequence` is what lets it see a statement that was withheld (a source that restarts from 1 signs a divergence). Input a verifier would refuse — a non-portable number, `sampledAt` later than `observedAt`, a sequence below 1 — is refused at build time. `ApprovalResult.execution()` carries the gateway's view; the offline verdict comes from `verify-java`'s `Dewp.verifyEvidenceBundle` under your own evidence-source trust, which is separate from approver trust by design.

That trust lives in an `intyga-evidence-sources` file, the same one every INTYGA SDK loads and the conformance vectors in `vectors/verifier-parity-vectors.json` (`executionEvidence.trustFiles`) pin. It is unsigned, like the trust anchor: adopting it into your configuration is the act of trust. It is a separate file from the approver trust anchor, because an approver is not an independent observer of the action they approved.

```java
// sources.json: {"type":"intyga-evidence-sources","v":1,"sources":[{"did":"did:example:relay-7",
//   "publicKeys":["MFkw…", {"key":"MFkw…","notBefore":"2026-10-01T00:00:00.000Z","notAfter":"2026-10-05T18:00:00.000Z"}]}]}
ExecutionEvidence.Policy evidencePolicy =
    EvidenceSourcesFile.parse(Files.readString(Path.of("sources.json"))).evidencePolicy();
// Pass it as the evidence policy of Dewp.verifyEvidenceBundle (or to ExecutionEvidence directly).
```

A key is a bare base64 SPKI P-256 key or `{ key, notBefore?, notAfter? }`: a bounded key establishes trust only when the Evidence Record's anchored time lies inside the interval: write the source's registration time from the console's Evidence Sources page as `notBefore`, and as `notAfter` the earliest witness time of the first checkpoint anchored after its revocation, not the revocation instant, which would refuse every statement anchored later. `parse` throws `InvalidEvidenceSourcesException` on the first problem, and refuses rather than guesses: `v` must be the integer `1`, a key object may carry only `key`, `notBefore` and `notAfter` (a misspelt `notafter` is a refusal, never "no bound"), and every bound must be a real `YYYY-MM-DDTHH:mm:ss.sssZ` instant with `notBefore` not later than `notAfter`. The policy keeps the file's source order and each source's key order; bare keys stay `String`s and key objects become `ExecutionEvidence.SourceKey`s.

### Offline approval (DIV §5a)

When the gateway cannot be reached, a relying party can build the challenge itself, have the approvers sign it on a disconnected device, and verify the result locally against a trust bundle exported while the gateway was reachable. The challenge (`DIV1:`) and signature (`SIG1:`) envelopes and the on-disk layout are a shared format across every INTYGA SDK, pinned by the conformance vectors in `vectors/offline-approval-vectors.json`. Everything lives in `com.intyga.sdk.offline`.

```java
ApprovalResult r = client.requireApproval("Restart the primary database",
    RequireApprovalOptions.builder()
        .authorize(AuthorizeOptions.builder()
            .target("prod-db-cluster-01").actionType("db.restart").params(params).build())
        // Opt in for THIS call only; never as a client default.
        .offline(OfflineApprovalOptions.builder()
            .bundleDir(Path.of("/etc/intyga/bundle"))      // TrustBundle.save(...) while online
            .requesterDid("did:intyga:service:oncall")
            .collectSignatures(challenge -> collectFromApprovers(challenge.envelope()))
            .build())
        .build());
if (r.status() == ApprovalStatus.OFFLINE_APPROVED) { /* a conscious decision at this call site */ }
```

- `RequireApprovalOptions.Builder.offline(...)` — the fallback runs only when the gateway could not be asked (connection failure, timeout, 5xx, repeated polling failures), never on a 4xx, `DENIED` or `EXPIRED`, and the status is `OFFLINE_APPROVED`, never `APPROVED`. A fallback that fails throws `OfflineApprovalFailedException`.
- `OfflineApproval.useOfflineApproval(action, options)` — the whole ceremony: verify the bundle, build the challenge, call your collector, verify the signatures, buffer a record for reconciliation, redeem the nonce once.
- `client.reconcileOfflineApprovals(bundleDir)` — report buffered approvals when connectivity returns; each is cleared only on a 2xx.
- `OfflineApproval.signChallengeEnvelope(envelope, key, signerDid, asOf)` — the approver's side. Show the decoded challenge (`decodeChallengeEnvelope`) and have the approver confirm its verification code with the operator first.
- Building blocks: `TrustBundle.verify` / `save` / `load` / `approverAnchor` / `requirementFor`, `TrustAnchorFile.parse`, `OfflineApproval.createOfflineChallenge`, `encodeSignatureEnvelope` / `decodeSignatureEnvelope`, `assembleOfflineReceipt`, `FileRedemptionStore`, `pendingApprovals` / `clearPendingApproval`.

`TrustBundle.approverAnchor` requires an explicit eligible DID list for `OFFLINE_INTENT` and throws
when it is null. `ORDINARY` retains null as an intentional unrestricted anchor.

## Examples

Framework examples live in the monorepo under `examples/`: plain Java (`gate-prod-delete-java`), Spring Boot (`gate-spring-boot-endpoint`), Quarkus (`gate-quarkus-deploy`), and LangChain4j (`gate-langchain4j-tool`).

## Also available in
- TypeScript — [`@intyga/sdk`](https://github.com/intyga-dev/sdk)
- Python — [`sdk-python`](https://github.com/intyga-dev/sdk-python)
- Go — [`sdk-go`](https://github.com/intyga-dev/sdk-go)
- Rust — [`sdk-rust`](https://github.com/intyga-dev/sdk-rust)

## License

Apache-2.0.
