# sdk-java — INTYGA client for Java

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
  <version>1.0.0</version>
</dependency>
```

Gradle: `implementation("com.intyga:intyga-sdk:1.0.0")`.

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
        ApproverTrustAnchor.ofPublicKeys(trustedApproverKeys())),
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

For framework code (a Spring/Quarkus handler, a LangChain4j tool method), `requireApprovalOrThrow(...)` is the one-line form: any outcome other than APPROVED throws `ApprovalRefusedException`, so a refusal propagates as an exception and can never be mistaken for a successful result.

> **Quorum caveat.** In public-keys mode the identity IS the key, so an M-of-N quorum counts credentials, not people — one approver whose two credentials are both listed satisfies a 2-of-N alone. For `requiredApprovals` > 1 use the DID/identity form, `ApproverTrustAnchor.ofDidsMultiKey` (DIV §4.4.6).

## Offline verification

`ApprovalResult.receipt()` is the signed receipt as raw JSON (`JsonNode`); `ApprovalReceipt.parse(...)` turns it into a verifier receipt with no re-serialization. `packages/verify-java`'s README states exactly what it verifies; read it before relying on a property it does not establish.

## API

- `IntygaClient.builder()` — `gatewayUrl` + either a pre-minted `token` or `clientId`/`clientSecret`; `build()` performs no I/O, and throws `IllegalArgumentException` unless `gatewayUrl` is `https://` (plain `http://` is accepted only for a loopback host — `localhost`, `127.0.0.0/8`, `::1` — for local development). An exchanged token is re-exchanged automatically shortly before the `expires_in` the gateway reports (and once more on a 401), so a long-lived client never has to manage tokens; a pre-minted `token` is used as given and never refreshed.
- `requireApproval(description, options)` — create a challenge and block until resolved (default 120s wait, 2s poll).
- `requireApprovalOrThrow(description, options)` — same, but non-APPROVED throws `ApprovalRefusedException`.
- `authorize` / `status` / `consume` — the individual steps (create, poll, execution-time re-bind). `authorize` requires a `target`; `consume` takes `(nonce, target, actionType, params)` and must be given the same target the approval was bound to.
- `verify(documentHash)` — public witness lookup.
- Exceptions: `GatewayRefusedException` (the gateway answered non-2xx; carries the status) vs `GatewayUnreachableException` (could not ask at all) — kept distinct because a policy refusal handled as an outage is a policy bypass.
- Offline verification: `com.intyga.verify.Verify.verifyApprovalReceipt(...)` — see [`verify-java`](https://github.com/intyga-dev/verify-java).

## Examples

Framework examples live in the monorepo under `examples/`: plain Java (`gate-prod-delete-java`), Spring Boot (`gate-spring-boot-endpoint`), Quarkus (`gate-quarkus-deploy`), and LangChain4j (`gate-langchain4j-tool`).

## Also available in
- TypeScript — [`@intyga/sdk`](https://github.com/intyga-dev/sdk)
- Python — [`sdk-python`](https://github.com/intyga-dev/sdk-python)
- Go — [`sdk-go`](https://github.com/intyga-dev/sdk-go)
- Rust — [`sdk-rust`](https://github.com/intyga-dev/sdk-rust)

## License

Apache-2.0.
