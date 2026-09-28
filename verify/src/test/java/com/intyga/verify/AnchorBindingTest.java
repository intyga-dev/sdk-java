package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/** Java API regressions using the same signed anchors as the other verifier ports. */
final class AnchorBindingTest {
  private static JsonNode vectors() throws Exception {
    return Records.JSON.readTree(Files.readString(
        Path.of("vectors/verifier-parity-vectors.json")));
  }

  private static JsonNode fixture(JsonNode vectors, String name) {
    for (JsonNode c : vectors.path("bundles").path("cases")) {
      if (name.equals(c.path("name").asText())) return c;
    }
    throw new AssertionError("missing fixture: " + name);
  }

  private static String key(JsonNode vectors, String id) {
    for (JsonNode k : vectors.path("keys")) {
      if (id.equals(k.path("id").asText())) return k.path("spkiB64").asText();
    }
    throw new AssertionError("missing key: " + id);
  }

  private static Ledger.SignedAnchor anchor(JsonNode fixture) {
    return Records.JSON.convertValue(fixture.path("bundle").path("anchors").get(0), Ledger.SignedAnchor.class);
  }

  @Test void selfAnchorMustBindEveryKnownCheckpointField() throws Exception {
    JsonNode v = vectors();
    Ledger.SignedAnchor a = anchor(fixture(v, "single-anchor-ES256"));
    var publicKey = Ledger.parseAnchorPublicKey(key(v, a.keyId()), a.algorithm());
    // SELF has no independent witness clock, even under a policy that no external anchor can meet.
    var policy = new Ledger.AnchorPolicy(1, List.of(a.issuer()), "N_OF_M", -600L);
    var expected = new Ledger.ExpectedCheckpoint(a.seqStart(), a.seqEnd(), a.chainHash(), a.timestamp());
    var valid = Ledger.verifyAnchorQuorum(List.of(a), a.dailyRoot(), policy, ignored -> publicKey,
        List.of(), null, null, null, null, expected);
    assertTrue(valid.ok(), valid.reason());
    assertEquals(Map.of(), valid.witnessTimes());
    for (var mismatch : List.of(
        new Ledger.ExpectedCheckpoint("2", a.seqEnd(), a.chainHash(), a.timestamp()),
        new Ledger.ExpectedCheckpoint(a.seqStart(), "2", a.chainHash(), a.timestamp()),
        new Ledger.ExpectedCheckpoint(a.seqStart(), a.seqEnd(), "0".repeat(64), a.timestamp()),
        new Ledger.ExpectedCheckpoint(a.seqStart(), a.seqEnd(), a.chainHash(), "2026-09-02T12:00:00.000Z"))) {
      var result = Ledger.verifyAnchorQuorum(List.of(a), a.dailyRoot(), policy, ignored -> publicKey,
          List.of(), null, null, null, null, mismatch);
      assertFalse(result.ok(), mismatch.toString());
      assertFalse(result.divergence());
      assertTrue(result.note().contains("different checkpoint"), result.note());
    }
    // Rewriting the signed position, rather than the expected position, breaks the signature too.
    ObjectNode changed = Records.JSON.valueToTree(a);
    for (var edit : Map.of("seqStart", "2", "seqEnd", "2", "chainHash", "0".repeat(64)).entrySet()) {
      ObjectNode tampered = changed.deepCopy();
      tampered.put(edit.getKey(), edit.getValue());
      assertFalse(Ledger.verifyAnchorSignature(
          Records.JSON.convertValue(tampered, Ledger.SignedAnchor.class), publicKey), edit.getKey());
    }
  }

  @Test void rejectedLateWitnessStillReportsTimeAndEarliestTimeIsOrderIndependent() throws Exception {
    JsonNode v = vectors();
    Ledger.SignedAnchor timely = anchor(fixture(v, "valid-rekor-anchor"));
    Ledger.SignedAnchor late = anchor(fixture(v, "rekor-anchor-witnessed-after-lag-refused"));
    String logKey = key(v, "rekor");
    var policy = new Ledger.AnchorPolicy(1, List.of(timely.issuer()), "N_OF_M");
    Long timelyAt = Rekor.verifyAnchor(timely, logKey).integratedTime();
    Long lateAt = Rekor.verifyAnchor(late, logKey).integratedTime();
    assertNotNull(timelyAt);
    assertNotNull(lateAt);
    var refused = Ledger.verifyAnchorQuorum(List.of(late), late.dailyRoot(), policy, null, List.of(), logKey);
    assertFalse(refused.ok());
    assertEquals(Map.of(late.issuer(), lateAt), refused.witnessTimes());
    for (var order : List.of(List.of(late, timely), List.of(timely, late))) {
      var result = Ledger.verifyAnchorQuorum(order, timely.dailyRoot(), policy, null, List.of(), logKey);
      assertTrue(result.ok(), result.note());
      assertEquals(List.of(timely.issuer()), result.verifiedIssuers());
      assertEquals(Map.of(timely.issuer(), timelyAt), result.witnessTimes());
    }
  }

  @Test void evidenceBundlePropagatesRekorProducerPinsAndWitnessTimes() throws Exception {
    JsonNode v = vectors();
    for (String name : List.of("rekor-pinned-submitter-key-verifies", "rekor-anchor-witnessed-after-lag-refused")) {
      JsonNode c = fixture(v, name);
      Ledger.SignedAnchor a = anchor(c);
      Dewp.ProofBundle proof = Dewp.ProofBundle.parse(c.path("bundle"));
      var checkpoint = new Dewp.Checkpoint("cp-1", a.dailyRoot(), "parity", a.timestamp(),
          a.seqStart(), a.seqEnd(), List.of(a), null, null, 1, "", a.chainHash());
      var bundle = new Dewp.EvidenceBundle("DEWP", Dewp.EVIDENCE_BUNDLE_KIND,
          Records.JSON.getNodeFactory().textNode("1.0"), "trust.intyga.audit.v1", null, proof.exportedAt(),
          new Dewp.Tenant("tenant-1", "T"), null, null,
          List.of(new Dewp.EvidenceEntry(proof.event(), proof.proof())), List.of(checkpoint));
      var policy = new Ledger.AnchorPolicy(1, List.of(a.issuer()), "N_OF_M");
      boolean timely = name.equals("rekor-pinned-submitter-key-verifies");
      List<String> pins = timely ? List.of(key(v, "anchor-es256")) : null;
      var options = new Dewp.EvidenceOptions(Set.of(a.dailyRoot()), null, policy, null,
          key(v, "rekor"), null, null, a.issuer(), pins);
      var result = Dewp.verifyEvidenceBundle(bundle, options);
      assertEquals(timely, result.ok(), result.failed() + " " + result.notes());
      assertEquals(1, result.contentVerified());
      assertEquals(timely, result.roots().get(0).anchorVerified());
      Long witnessedAt = Rekor.verifyAnchor(a, key(v, "rekor")).integratedTime();
      assertNotNull(witnessedAt);
      assertEquals(Map.of(a.issuer(), witnessedAt), result.roots().get(0).witnessTimes());
      if (timely) {
        var wrongPin = new Dewp.EvidenceOptions(Set.of(a.dailyRoot()), null, policy, null,
            key(v, "rekor"), null, null, a.issuer(), List.of(key(v, "rekor")));
        var refused = Dewp.verifyEvidenceBundle(bundle, wrongPin);
        assertFalse(refused.ok());
        assertEquals(false, refused.roots().get(0).anchorVerified());
        assertEquals(Map.of(), refused.roots().get(0).witnessTimes());
      }
    }
  }
}
