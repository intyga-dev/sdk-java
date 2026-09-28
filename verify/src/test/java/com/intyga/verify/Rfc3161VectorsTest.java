package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import com.fasterxml.jackson.databind.JsonNode;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

final class Rfc3161VectorsTest {
  private static JsonNode vectors() throws Exception {
    return Records.JSON.readTree(Files.readString(Path.of("vectors/rfc3161-vectors.json")));
  }
  private static Rfc3161.Trust trust(JsonNode value) {
    if (value == null || value.isNull()) return null;
    return new Rfc3161.Trust(value.path("caPem").asText(null), value.path("signerCertificateSha256").asText(null),
        value.path("revocation").asText(null), value.path("crlPem").asText(null), value.path("untrustedPem").asText(null),
        value.has("verificationTime") ? value.get("verificationTime").longValue() : null,
        value.path("opensslPath").asText(null));
  }

  @Test void sharedVectors() throws Exception {
    for (JsonNode c : vectors().path("cases")) {
      Ledger.SignedAnchor anchor = Records.JSON.convertValue(c.path("anchor"), Ledger.SignedAnchor.class);
      assertEquals(c.path("expected").asBoolean(), Rfc3161.verifyAnchor(anchor, trust(c.get("trust"))).ok(), c.path("name").asText());
    }
  }

  @Test void missingExecutableFailsClosed() throws Exception {
    JsonNode c = vectors().path("cases").get(0); Rfc3161.Trust source = trust(c.get("trust"));
    var bad = new Rfc3161.Trust(source.caPem(), source.signerCertificateSha256(), source.revocation(), source.crlPem(),
        source.untrustedPem(), source.verificationTime(), "/does/not/exist/openssl");
    assertFalse(Rfc3161.verifyAnchor(Records.JSON.convertValue(c.path("anchor"), Ledger.SignedAnchor.class), bad).ok());
  }

  @Test void emptyOptionalIntermediatesAreTreatedAsAbsent() throws Exception {
    JsonNode c = vectors().path("cases").get(0); Rfc3161.Trust source = trust(c.get("trust"));
    var emptyIntermediates = new Rfc3161.Trust(source.caPem(), source.signerCertificateSha256(), source.revocation(),
        source.crlPem(), "", source.verificationTime(), source.opensslPath());
    assertEquals(true, Rfc3161.verifyAnchor(
        Records.JSON.convertValue(c.path("anchor"), Ledger.SignedAnchor.class), emptyIntermediates).ok());
  }

  @Test void countsForQuorumAndCallerAttributedDivergence() throws Exception {
    JsonNode valid = null, divergent = null;
    for (JsonNode c : vectors().path("cases")) {
      if ("valid-unchecked".equals(c.path("name").asText())) valid = c;
      if ("valid-different-root-for-divergence".equals(c.path("name").asText())) divergent = c;
    }
    Ledger.SignedAnchor anchor = Records.JSON.convertValue(valid.path("anchor"), Ledger.SignedAnchor.class);
    Ledger.SignedAnchor conflict = Records.JSON.convertValue(divergent.path("anchor"), Ledger.SignedAnchor.class);
    var policy = new Ledger.AnchorPolicy(1, List.of(anchor.issuer()), "N_OF_M");
    var trusts = Map.of(anchor.issuer(), trust(valid.get("trust")));
    var timely = Ledger.verifyAnchorQuorum(List.of(anchor), anchor.dailyRoot(), policy, ignored -> null,
        List.of(), null, trusts);
    assertEquals(true, timely.ok());
    Long witnessedAt = Rfc3161.verifyAnchor(anchor, trust(valid.get("trust"))).genTime();
    assertEquals(Map.of(anchor.issuer(), witnessedAt), timely.witnessTimes());
    // The TSA's authenticated genTime, not the producer's timestamp, determines the policy lag.
    long lagMs = witnessedAt * 1000 - Ledger.parseAnchorTimestampMs(anchor.timestamp());
    long lagCeiling = -Math.floorDiv(-lagMs, 1000);
    var boundary = new Ledger.AnchorPolicy(1, List.of(anchor.issuer()), "N_OF_M", lagCeiling);
    assertEquals(true, Ledger.verifyAnchorQuorum(List.of(anchor), anchor.dailyRoot(), boundary, null,
        List.of(), null, trusts).ok());
    var tooStrict = new Ledger.AnchorPolicy(1, List.of(anchor.issuer()), "N_OF_M", lagCeiling - 1);
    var late = Ledger.verifyAnchorQuorum(List.of(anchor), anchor.dailyRoot(), tooStrict, null,
        List.of(), null, trusts);
    assertFalse(late.ok());
    assertEquals(timely.witnessTimes(), late.witnessTimes());
    assertEquals(true, Ledger.verifyAnchorQuorum(List.of(anchor), anchor.dailyRoot(), policy, ignored -> null,
        List.of(conflict), null, trusts).divergence());
    var wrong = new Rfc3161.Trust(trust(valid.get("trust")).caPem(), "00".repeat(32), "unchecked");
    var failed = Ledger.verifyAnchorQuorum(List.of(anchor), anchor.dailyRoot(), policy, ignored -> null,
        List.of(), null, Map.of(anchor.issuer(), wrong));
    assertFalse(failed.ok());
    assertEquals(true, failed.note().contains("not verified"));

    for (String kind : List.of("WEBHOOK", "FUTURE_KIND")) {
      var relabeled = new Ledger.SignedAnchor(conflict.dailyRoot(), conflict.timestamp(), conflict.issuer(),
          conflict.algorithm(), conflict.keyId(), conflict.signature(), kind, conflict.evidence(),
          conflict.seqStart(), conflict.seqEnd(), conflict.chainHash());
      var verdict = Ledger.verifyAnchorQuorum(List.of(anchor), anchor.dailyRoot(), policy,
          ignored -> { throw new AssertionError("unsupported anchor kind reached SELF resolver"); },
          List.of(relabeled), null, trusts);
      assertFalse(verdict.divergence());
    }

    JsonNode parity = Records.JSON.readTree(Files.readString(Path.of("vectors/verifier-parity-vectors.json")));
    Dewp.ProofBundle bundle = Dewp.ProofBundle.parse(parity.path("bundles").path("cases").get(0).path("bundle"));
    var integrated = Dewp.verifyBundle(bundle, new Dewp.BundleOptions(anchor.dailyRoot(), List.of(anchor),
        policy, null, null, trusts));
    assertEquals(true, integrated.notes().stream().noneMatch(note -> note.contains("could not be evaluated")));
    var integratedFailure = Dewp.verifyBundle(bundle, new Dewp.BundleOptions(anchor.dailyRoot(), List.of(anchor),
        policy, null, null, Map.of(anchor.issuer(), wrong)));
    assertEquals(true, integratedFailure.notes().stream().anyMatch(note -> note.contains("anchor quorum not met")));
  }
}
