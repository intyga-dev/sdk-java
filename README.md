# sdk-java — Intyga client for Java

Gate any high-risk backend action behind a real human approval. The primitive is uniform: **request a challenge → a human approves with a passkey or security key → poll until resolved** — the same client works for scripts, pipelines, and AI agents.

This package **bundles the offline verifier** ([`com.intyga:intyga-verify`](../verify-java)), so you can request an approval *and* independently verify the receipt without adding a second dependency.

> Status: **not yet published** to Maven Central. Until then, build both locally — `mvn install` in [`packages/verify-java`](../verify-java) first, then in this directory.

Runtime dependencies: `com.intyga:intyga-verify` and Jackson (`jackson-databind`) for JSON — Java has no stdlib JSON. HTTP is the JDK's built-in `java.net.http`, and all cryptography is the JDK's own. Nothing else.

## Install

```xml
<dependency>
  <groupId>com.intyga</groupId>
  <artifactId>intyga-sdk</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle: `implementation("com.intyga:intyga-sdk:0.1.0")` (with `mavenLocal()` until the package is published).

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
    VerifyOptions.defaults());
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

Works identically whether the token is a **human key** (backend/service) or an **agent key** — Intyga is a general zero-trust gate for *any* backend action, not just agents.

For framework code (a Spring/Quarkus handler, a LangChain4j tool method), `requireApprovalOrThrow(...)` is the one-line form: any outcome other than APPROVED throws `ApprovalRefusedException`, so a refusal propagates as an exception and can never be mistaken for a successful result.

> **Quorum caveat.** In public-keys mode the identity IS the key, so an M-of-N quorum counts credentials, not people — one approver whose two credentials are both listed satisfies a 2-of-N alone. For `requiredApprovals` > 1 use the DID/identity form, `ApproverTrustAnchor.ofDidsMultiKey` (DIV §4.4.6).

## Offline verification

`ApprovalResult.receipt()` is the signed receipt as raw JSON (`JsonNode`); `ApprovalReceipt.parse(...)` turns it into a verifier receipt with no re-serialization. The verifier implements the **DEWP Core Profile** — the same scope as `verify-go` and `verify-rust`, not the full TypeScript surface. `packages/verify-java`'s README states exactly what it does and does not verify (no anchor-quorum evaluation, no bundle parsing, no agent-authority payloads); read it before relying on a property it does not establish.

## API

- `IntygaClient.builder()` — `gatewayUrl` + either a pre-minted `token` or `clientId`/`clientSecret`; `build()` performs no I/O.
- `requireApproval(description, options)` — create a challenge and block until resolved (default 120s wait, 2s poll).
- `requireApprovalOrThrow(description, options)` — same, but non-APPROVED throws `ApprovalRefusedException`.
- `authorize` / `status` / `consume` — the individual steps (create, poll, execution-time re-bind). `authorize` requires a `target`; `consume` takes `(nonce, target, actionType, params)` and must be given the same target the approval was bound to.
- `verify(documentHash)` — public witness lookup.
- Exceptions: `GatewayRefusedException` (the gateway answered non-2xx; carries the status) vs `GatewayUnreachableException` (could not ask at all) — kept distinct because a policy refusal handled as an outage is a policy bypass.
- Offline verification: `com.intyga.verify.Verify.verifyApprovalReceipt(...)` — see [`verify-java`](../verify-java).

## Examples

Framework examples live in the monorepo under `examples/`: plain Java (`gate-prod-delete-java`), Spring Boot (`gate-spring-boot-endpoint`), Quarkus (`gate-quarkus-deploy`), and LangChain4j (`gate-langchain4j-tool`).

## Also available in
- TypeScript — [`@intyga/sdk`](https://github.com/intyga-dev/sdk)
- Python — [`sdk-python`](https://github.com/intyga-dev/sdk-python)
- Go — [`sdk-go`](https://github.com/intyga-dev/sdk-go)
- Rust — [`sdk-rust`](https://github.com/intyga-dev/sdk-rust)

## License

Apache-2.0.
