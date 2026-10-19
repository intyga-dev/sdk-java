package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.intyga.verify.ExecutionEvidence;
import com.intyga.verify.Ledger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The evidence source's side of DEWP §4.7, mirroring the TypeScript SDK's execution-evidence test. */
final class EvidenceSourceTest {
  private static final String APPROVAL_PAYLOAD = "{\"nonce\":\"n-1\",\"type\":\"div-intent-verification\",\"v\":1}";

  private static KeyPair p256() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }

  private static boolean verifies(KeyPair pair, String statement, String signatureB64) throws Exception {
    byte[] raw = Base64.getDecoder().decode(signatureB64);
    assertEquals(64, raw.length, "IEEE P1363 r||s");
    Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
    v.initVerify(pair.getPublic());
    v.update(statement.getBytes(StandardCharsets.UTF_8));
    return v.verify(raw);
  }

  @Test
  void buildsACanonicalStatementBoundToTheApprovedBytesAndSignsItEs256() throws Exception {
    String statement = EvidenceSource.buildExecutionEvidence(APPROVAL_PAYLOAD, "n-1", "did:example:relay-7", "confirmed",
        Map.of("breaker", "open", "currentA", 0), 418, "2026-10-05T14:02:09.500Z", "2026-10-05T14:02:11.000Z");
    ExecutionEvidence.Statement parsed = ExecutionEvidence.parseStatement(statement);
    assertEquals(ExecutionEvidence.payloadSha256(APPROVAL_PAYLOAD), parsed.payloadSha256());
    assertEquals("2026-10-05T14:02:09.500Z", parsed.sampledAt());
    assertEquals("2026-10-05T14:02:11.000Z", parsed.observedAt());
    assertEquals(418, parsed.sequence());
    assertEquals("{\"approval\":{\"nonce\":\"n-1\",\"payloadSha256\":\"" + parsed.payloadSha256()
        + "\"},\"observation\":{\"breaker\":\"open\",\"currentA\":0},\"observedAt\":\"2026-10-05T14:02:11.000Z\","
        + "\"sampledAt\":\"2026-10-05T14:02:09.500Z\",\"sequence\":418,\"source\":\"did:example:relay-7\","
        + "\"type\":\"dewp-execution-evidence\",\"v\":1,\"verdict\":\"confirmed\"}", statement);

    KeyPair pair = p256();
    String signature = EvidenceSource.signExecutionEvidence(statement, pair.getPrivate());
    assertTrue(verifies(pair, statement, signature));
    // PEM (PKCS#8) and DER key files work too.
    String pem = "-----BEGIN PRIVATE KEY-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(pair.getPrivate().getEncoded())
        + "\n-----END PRIVATE KEY-----\n";
    assertTrue(verifies(pair, statement, EvidenceSource.signExecutionEvidence(statement, pem)));
    assertTrue(verifies(pair, statement, EvidenceSource.signExecutionEvidence(statement, pair.getPrivate().getEncoded())));
    // A non-P-256 key is refused rather than producing a signature nobody verifies.
    KeyPair ed = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    var refused = assertThrows(IllegalArgumentException.class,
        () -> EvidenceSource.signExecutionEvidence(statement, ed.getPrivate()));
    assertTrue(refused.getMessage().contains("P-256"), refused.getMessage());
    assertThrows(IllegalArgumentException.class, () -> EvidenceSource.signExecutionEvidence(statement, "not a key"));

    // What the gateway commits is what the verifier reads: the statement checks out under the source's
    // key, and alone it is at best unbound (DEWP §4.7.3) — binding needs the dispatch and approval.
    String spki = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
    var leaf = new Ledger.AuditLeaf("7", "7", "2026-10-05T14:02:12.000Z", ExecutionEvidence.CONFIRMED, "SUCCESS", null, null,
        "did:example:relay-7", spki, statement, signature, "ES256", false, null, null, null, null, null);
    var check = ExecutionEvidence.checkLeaf(leaf, new ExecutionEvidence.Policy(Map.of("did:example:relay-7", List.of(spki))));
    assertEquals("unbound", check.status());
    assertTrue(check.trusted());
    assertEquals("did:example:relay-7", check.source());
    assertEquals(418L, check.sequence());
  }

  @Test
  void observedAtDefaultsToNowSampledAtToObservedAtAndInvalidInputIsRefusedAtBuildTime() {
    String statement = EvidenceSource.buildExecutionEvidence(APPROVAL_PAYLOAD, "n-1", "s", "contradicted", Map.of(), 1);
    ExecutionEvidence.Statement parsed = ExecutionEvidence.parseStatement(statement);
    assertEquals(parsed.observedAt(), parsed.sampledAt());
    assertNotNull(Ledger.parseAnchorTimestampMs(parsed.observedAt()), "DEWP §4.3 form");
    assertEquals(1, parsed.sequence());
    assertFalse(statement.contains(" "));

    // Each refused at build time, so a source never signs bytes a verifier rejects as malformed.
    assertThrows(IllegalArgumentException.class, () -> EvidenceSource.buildExecutionEvidence(
        APPROVAL_PAYLOAD, "n-1", "s", "confirmed", Map.of("x", 1e16), 1), "non-portable number");
    assertThrows(IllegalArgumentException.class, () -> EvidenceSource.buildExecutionEvidence(
        APPROVAL_PAYLOAD, "n-1", "s", "confirmed", Map.of(), 0), "sequence below 1");
    assertThrows(IllegalArgumentException.class, () -> EvidenceSource.buildExecutionEvidence(
        APPROVAL_PAYLOAD, "n-1", "s", "confirmed", Map.of(), 1, "2099-01-01T00:00:00.000Z", null), "sampled after observed");
    assertThrows(IllegalArgumentException.class, () -> EvidenceSource.buildExecutionEvidence(
        APPROVAL_PAYLOAD, "n-1", "s", "maybe", Map.of(), 1), "unknown verdict");
    assertThrows(IllegalArgumentException.class, () -> EvidenceSource.buildExecutionEvidence(
        APPROVAL_PAYLOAD, "", "s", "confirmed", Map.of(), 1), "empty nonce");
    assertThrows(IllegalArgumentException.class, () -> EvidenceSource.buildExecutionEvidence(
        null, "n-1", "s", "confirmed", Map.of(), 1), "no approval payload");
  }
}
