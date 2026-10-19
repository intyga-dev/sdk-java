package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.intyga.verify.ExecutionEvidence;
import com.intyga.verify.Ledger;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * The evidence-source trust file against the shared {@code executionEvidence.trustFiles} cases in
 * {@code packages/mcp-schemas/vectors/verifier-parity-vectors.json} — the cases every SDK's loader
 * must agree on (docs/API.md §2e) — plus a round trip through the verifier. One dynamic test per
 * case, so the report counts cases.
 *
 * <p>Reads the COMMITTED file, never a generator. The path is the one the public-tree script
 * rewrites ({@code vectors/} → {@code vectors/}); Maven runs tests from the module dir.
 */
final class EvidenceSourcesFileTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final String SOURCE = "did:example:relay-7";
  private static final String APPROVAL = "{\"nonce\":\"n-1\",\"type\":\"div-intent-verification\",\"v\":1}";
  private static final String T0 = "2026-10-05T14:00:00.000Z";
  private static final long T0_MS = Ledger.parseAnchorTimestampMs(T0);

  private static JsonNode trustFiles() {
    try {
      JsonNode cases = JSON.readTree(Files.readString(Path.of("vectors/verifier-parity-vectors.json")))
          .path("executionEvidence").path("trustFiles");
      assertTrue(cases.isArray() && !cases.isEmpty(), "executionEvidence.trustFiles is missing or empty");
      return cases;
    } catch (IOException e) {
      throw new IllegalStateException("cannot read verifier-parity-vectors.json", e);
    }
  }

  /** The loaded policy written back as the vectors write it: a key as a string or the object as written. */
  private static ObjectNode asJson(ExecutionEvidence.Policy policy) {
    ObjectNode out = JSON.createObjectNode();
    policy.trustedSources().forEach((did, keys) -> {
      ArrayNode arr = out.putArray(did);
      for (Object k : keys) {
        if (k instanceof String s) {
          arr.add(s);
        } else {
          ExecutionEvidence.SourceKey sk = assertInstanceOf(ExecutionEvidence.SourceKey.class, k);
          ObjectNode o = arr.addObject().put("key", sk.key());
          if (sk.notBefore() != null) o.put("notBefore", sk.notBefore());
          if (sk.notAfter() != null) o.put("notAfter", sk.notAfter());
        }
      }
    });
    return out;
  }

  private static List<String> names(JsonNode obj) {
    List<String> out = new ArrayList<>();
    for (Iterator<String> it = obj.fieldNames(); it.hasNext(); ) out.add(it.next());
    return out;
  }

  @TestFactory
  Stream<DynamicTest> sharedTrustFileCases() {
    List<DynamicTest> tests = new ArrayList<>();
    for (JsonNode c : trustFiles()) {
      String name = c.get("name").textValue();
      String text = c.get("text").textValue();
      boolean ok = c.get("ok").booleanValue();
      tests.add(DynamicTest.dynamicTest(name, () -> {
        if (!ok) {
          var e = assertThrows(InvalidEvidenceSourcesException.class, () -> EvidenceSourcesFile.parse(text), name);
          assertTrue(e.getMessage().startsWith("invalid evidence-sources file: "), e.getMessage());
          return;
        }
        ExecutionEvidence.Policy policy = EvidenceSourcesFile.parse(text).evidencePolicy();
        JsonNode expected = c.get("policy");
        // Object equality ignores member order, so the source order is checked on its own; the key
        // arrays compare in order.
        assertEquals(names(expected), List.copyOf(policy.trustedSources().keySet()), name + ": source order");
        assertEquals(expected, asJson(policy), name);
      }));
    }
    return tests.stream();
  }

  @Test
  void labelsAndUnknownMembersAreKeptOutOfThePolicy() {
    var file = EvidenceSourcesFile.parse("{\"type\":\"intyga-evidence-sources\",\"v\":1,\"exportedAt\":\"x\",\"sources\":["
        + "{\"did\":\"a\",\"label\":\"Relay 7\",\"kind\":\"relay\",\"publicKeys\":[\"AAAA\"]},"
        + "{\"did\":\"b\",\"publicKeys\":[{\"key\":\"BBBB\",\"notAfter\":\"2026-10-05T18:00:00.000Z\"}]}]}");
    assertEquals(2, file.sources().size());
    assertEquals("Relay 7", file.sources().get(0).label());
    assertNull(file.sources().get(1).label());
    assertEquals(List.of(new ExecutionEvidence.SourceKey("BBBB", null, "2026-10-05T18:00:00.000Z")),
        file.sources().get(1).publicKeys());
    assertThrows(UnsupportedOperationException.class, () -> file.evidencePolicy().trustedSources().clear());
  }

  @Test
  void versionIsTheNumberOneAndNothingCoercedToIt() {
    for (String v : List.of("\"1\"", "1.5", "true", "null", "[1]")) {
      String text = "{\"type\":\"intyga-evidence-sources\",\"v\":" + v + ",\"sources\":[{\"did\":\"a\",\"publicKeys\":[\"AAAA\"]}]}";
      assertThrows(InvalidEvidenceSourcesException.class, () -> EvidenceSourcesFile.parse(text), v);
    }
    // The number 1 in any JSON spelling is the version, as JavaScript's JSON.parse reads it.
    for (String v : List.of("1.0", "1e0")) {
      String text = "{\"type\":\"intyga-evidence-sources\",\"v\":" + v + ",\"sources\":[{\"did\":\"a\",\"publicKeys\":[\"AAAA\"]}]}";
      assertDoesNotThrow(() -> EvidenceSourcesFile.parse(text), v);
    }
    assertThrows(InvalidEvidenceSourcesException.class, () -> EvidenceSourcesFile.parse(null));
    assertThrows(InvalidEvidenceSourcesException.class, () -> EvidenceSourcesFile.parse(""));
    assertThrows(InvalidEvidenceSourcesException.class, () -> EvidenceSourcesFile.parse(
        "{\"type\":\"intyga-evidence-sources\",\"v\":1,\"sources\":[{\"did\":\"a\",\"publicKeys\":[\"AAAA\"]}]} x"));
  }

  // --- round trip: a loaded file trusts what EvidenceSource signs -----------------------------------

  private static String at(long offsetMs) {
    return java.time.format.DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'")
        .withZone(java.time.ZoneOffset.UTC).format(java.time.Instant.ofEpochMilli(T0_MS + offsetMs));
  }

  private static Ledger.AuditLeaf leaf(String seq, String event, String outcome, Object metadata, String signerDid,
      String key, String payload, String signature) {
    return new Ledger.AuditLeaf(seq, seq, at(0), event, outcome, null, metadata, signerDid, key, payload, signature,
        payload == null ? null : "ES256", false, null, null, null, null, null);
  }

  private static String file(String keysJson) {
    return "{\"type\":\"intyga-evidence-sources\",\"v\":1,\"sources\":[{\"did\":\"" + SOURCE
        + "\",\"label\":\"Relay 7\",\"publicKeys\":[" + keysJson + "]}]}";
  }

  @Test
  void aLoadedFileTrustsAStatementEvidenceSourceSigned() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair source = g.generateKeyPair();
    KeyPair other = g.generateKeyPair();
    String spki = Base64.getEncoder().encodeToString(source.getPublic().getEncoded());
    String otherSpki = Base64.getEncoder().encodeToString(other.getPublic().getEncoded());

    String statement = EvidenceSource.buildExecutionEvidence(APPROVAL, "n-1", SOURCE, "confirmed",
        Map.of("breaker", "open"), 1, at(60_000), at(60_000));
    String signature = EvidenceSource.signExecutionEvidence(statement, source.getPrivate());
    var evidence = leaf("103", ExecutionEvidence.CONFIRMED, "SUCCESS", null, SOURCE, spki, statement, signature);
    var bundle = List.of(
        new ExecutionEvidence.Leaf("101", leaf("101", "AUTHZ_APPROVED", "SUCCESS", null, "did:example:human", null, APPROVAL, null)),
        new ExecutionEvidence.Leaf("102", leaf("102", ExecutionEvidence.DISPATCHED, "PENDING", Map.of("nonce", "n-1",
            "payloadSha256", ExecutionEvidence.payloadSha256(APPROVAL), "evidenceDeadline", at(600_000)), null, null, null, null)),
        new ExecutionEvidence.Leaf("103", evidence));

    // A bare key: trusted at any time, and the nonce reads confirmed.
    var bare = EvidenceSourcesFile.parse(file("\"" + spki + "\"")).evidencePolicy();
    assertTrue(ExecutionEvidence.checkLeaf(evidence, bare).trusted());
    var r = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(bare, T0_MS + 3_600_000L, null, null, null));
    assertEquals("verified", r.checks().get(0).check().status());
    assertTrue(r.checks().get(0).check().trusted());
    assertEquals("confirmed", r.byNonce().get("n-1").status());
    assertEquals(List.of("n-1"), r.confirmed());

    // A bounded key: trust only at an anchored time inside the interval, never from the statement's own times.
    var bounded = EvidenceSourcesFile.parse(file("{\"key\":\"" + spki
        + "\",\"notBefore\":\"2026-10-05T00:00:00.000Z\",\"notAfter\":\"2026-10-05T18:00:00.000Z\"}")).evidencePolicy();
    assertTrue(ExecutionEvidence.checkLeaf(evidence, bounded, Ledger.parseAnchorTimestampMs("2026-10-05T18:00:00.000Z")).trusted());
    assertFalse(ExecutionEvidence.checkLeaf(evidence, bounded, Ledger.parseAnchorTimestampMs("2026-10-05T18:00:00.001Z")).trusted());
    var unplaced = ExecutionEvidence.checkLeaf(evidence, bounded);
    assertFalse(unplaced.trusted());
    assertTrue(unplaced.reason().contains("cannot be placed in time"), unplaced.reason());
    var anchored = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(bounded, T0_MS + 3_600_000L, null, null,
        seq -> seq.equals("103") ? Ledger.parseAnchorTimestampMs(at(120_000)) : null));
    assertEquals("confirmed", anchored.byNonce().get("n-1").status());

    // Another source's key verifies nothing, and a source not in the file has no trusted key at all.
    var wrong = EvidenceSourcesFile.parse(file("\"" + otherSpki + "\"")).evidencePolicy();
    assertEquals("invalid", ExecutionEvidence.checkLeaf(evidence, wrong).status());
    var elsewhere = EvidenceSourcesFile.parse(
        "{\"type\":\"intyga-evidence-sources\",\"v\":1,\"sources\":[{\"did\":\"did:example:meter-3\",\"publicKeys\":[\""
            + spki + "\"]}]}").evidencePolicy();
    assertEquals("not_checked", ExecutionEvidence.checkLeaf(evidence, elsewhere).status());
  }
}
