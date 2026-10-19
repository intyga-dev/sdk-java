package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * DEWP §4.7 rules the shared vectors pin by status only: the §4.7.4 findings in full, the anchored-time
 * hook a bounded key is held to (§4.7.5), the key entry forms that fail closed, and the option
 * sanitising. Statement parsing itself is pinned by the vectors' {@code statements} section.
 */
final class ExecutionEvidenceTest {
  private static final String APPROVAL = "{\"evidence\":null,\"nonce\":\"n-1\",\"type\":\"div-intent-verification\",\"v\":1}";
  private static final String HASH = ExecutionEvidence.payloadSha256(APPROVAL);
  private static final String OTHER_HASH = ExecutionEvidence.payloadSha256(APPROVAL + " ");
  private static final String SOURCE = "did:example:relay-7";
  private static final String T0 = "2026-10-05T14:00:00.000Z";
  private static final long T0_MS = Ledger.parseAnchorTimestampMs(T0);

  private static KeyPair keyPair() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }

  private static String spki(KeyPair k) { return Base64.getEncoder().encodeToString(k.getPublic().getEncoded()); }

  private static String at(long offsetMs) {
    return java.time.format.DateTimeFormatter.ofPattern("uuuu-MM-dd'T'HH:mm:ss.SSS'Z'")
        .withZone(java.time.ZoneOffset.UTC).format(java.time.Instant.ofEpochMilli(T0_MS + offsetMs));
  }

  private static Ledger.AuditLeaf leaf(String seq, String event, String outcome, Object metadata, String signerDid,
      String key, String payload, String signature) {
    return new Ledger.AuditLeaf(seq, seq, at(0), event, outcome, null, metadata, signerDid, key, payload, signature,
        payload == null ? null : "ES256", false, null, null, null, null, null);
  }

  private static Ledger.AuditLeaf approval(String seq) {
    return leaf(seq, "AUTHZ_APPROVED", "SUCCESS", null, "did:example:human", null, APPROVAL, null);
  }

  private static Ledger.AuditLeaf dispatch(String seq, String hash, long deadlineOffsetMs) {
    return leaf(seq, ExecutionEvidence.DISPATCHED, "PENDING",
        Map.of("nonce", "n-1", "payloadSha256", hash, "evidenceDeadline", at(deadlineOffsetMs)), null, null, null, null);
  }

  private static Ledger.AuditLeaf evidence(String seq, KeyPair k, String verdict, long sequence, long sampledOffsetMs,
      Map<String, Object> observation) throws Exception {
    String statement = ExecutionEvidence.canonicalStatement(new ExecutionEvidence.Statement("n-1", HASH, observation,
        at(sampledOffsetMs), at(sampledOffsetMs), sequence, SOURCE, verdict));
    Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
    s.initSign(k.getPrivate());
    s.update(statement.getBytes(StandardCharsets.UTF_8));
    boolean confirmed = verdict.equals("confirmed");
    return leaf(seq, confirmed ? ExecutionEvidence.CONFIRMED : ExecutionEvidence.CONTRADICTED,
        confirmed ? "SUCCESS" : "FAILURE", null, SOURCE, spki(k), statement, Base64.getEncoder().encodeToString(s.sign()));
  }

  private static List<ExecutionEvidence.Leaf> entries(Ledger.AuditLeaf... leaves) {
    List<ExecutionEvidence.Leaf> out = new ArrayList<>();
    for (Ledger.AuditLeaf l : leaves) out.add(new ExecutionEvidence.Leaf(l.seq(), l));
    return out;
  }

  private static ExecutionEvidence.Policy policy(Object... keys) {
    return new ExecutionEvidence.Policy(Map.of(SOURCE, List.of(keys)));
  }

  @Test
  void findingsAreReportedBesideTheStatus() throws Exception {
    KeyPair k = keyPair();
    long hour = 3_600_000L, minute = 60_000L;
    // Two Dispatch Records that disagree: the early one carries another hash, the later one the right
    // hash with a deadline two days out, beyond the default 24 h window.
    var bundle = entries(
        approval("100"),
        dispatch("101", OTHER_HASH, 10 * minute),
        dispatch("102", HASH, 48 * hour),
        evidence("103", k, "confirmed", 1, minute, Map.of("breaker", "open")),
        // Trusted, bound, contradicted — but sampled after the effective (capped) deadline.
        evidence("104", k, "contradicted", 3, 25 * hour, Map.of("breaker", "closed")),
        // Sequence 3 again under different bytes: a divergence; 2 was never seen: a gap.
        evidence("105", k, "confirmed", 3, 2 * minute, Map.of("breaker", "open", "currentA", 0)));
    var r = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(policy(spki(k)), T0_MS + 30 * hour, null, null, null));
    var n = r.byNonce().get("n-1");
    assertEquals("confirmed", n.status());
    assertEquals("102", n.dispatchSeq(), "the governing record is the lowest-seq one whose hash matches");
    assertEquals(at(48 * hour), n.evidenceDeadline());
    assertEquals(at(24 * hour), n.effectiveDeadline());
    assertTrue(n.windowCapped());
    assertEquals(List.of("101", "102"), n.dispatchConflict());
    assertEquals(List.of("104"), n.lateContradiction());
    assertEquals(List.of("103", "104", "105"), n.evidenceSeqs());
    assertEquals(List.of("n-1"), r.dispatchConflicts());
    assertEquals(List.of("n-1"), r.lateContradicted());
    assertEquals(List.of("confirmed", "contradicted", "confirmed"),
        r.checks().stream().map(c -> c.check().verdict()).toList());
    assertEquals(List.of("verified", "stale", "verified"), r.checks().stream().map(c -> c.check().status()).toList());
    assertEquals(List.of(SOURCE, SOURCE, SOURCE), r.checks().stream().map(c -> c.check().source()).toList());
    assertEquals(List.of(1L, 3L, 3L), r.checks().stream().map(c -> c.check().sequence()).toList());
    var continuity = r.sources().get(SOURCE);
    assertEquals(1L, continuity.first());
    assertEquals(3L, continuity.last());
    assertEquals(List.of(List.of(2L, 2L)), continuity.gaps());
    assertEquals(List.of(3L), continuity.divergent());

    // A caller window of one hour cuts the deadline further; the status is evaluated against it.
    var capped = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(policy(spki(k)), T0_MS + 30 * hour, null, 3_600L, null));
    assertEquals(at(hour), capped.byNonce().get("n-1").effectiveDeadline());
    var silent = ExecutionEvidence.evaluate(entries(approval("100"), dispatch("101", HASH, 48 * hour)),
        new ExecutionEvidence.Options(null, T0_MS + 25 * hour, null, null, null));
    assertEquals("unconfirmed", silent.byNonce().get("n-1").status(), "unconfirmed fires at the effective deadline");
    assertTrue(silent.byNonce().get("n-1").windowCapped());
  }

  @Test
  void dispatchConflictWithoutStatementsAndIdenticalBytesAreNotDivergent() throws Exception {
    KeyPair k = keyPair();
    var same = evidence("103", k, "confirmed", 7, 60_000L, Map.of());
    var copy = new Ledger.AuditLeaf("104", "104", same.createdAt(), same.event(), same.outcome(), null, null, SOURCE,
        same.signerPublicKey(), same.signedPayload(), same.signature(), "ES256", false, null, null, null, null, null);
    var r = ExecutionEvidence.evaluate(entries(approval("100"), dispatch("101", HASH, 600_000L), dispatch("102", HASH, 600_000L),
        same, copy), new ExecutionEvidence.Options(policy(spki(k)), T0_MS, null, null, null));
    assertEquals(List.of(), r.byNonce().get("n-1").dispatchConflict(), "agreeing records are no conflict");
    assertEquals("101", r.byNonce().get("n-1").dispatchSeq());
    assertEquals(List.of(), r.sources().get(SOURCE).divergent(), "the same bytes twice are one statement");
    assertEquals(List.of(), r.sources().get(SOURCE).gaps());
  }

  @Test
  void boundedKeyIsHeldToTheAnchoredTimeOnly() throws Exception {
    KeyPair k = keyPair();
    var leaf = evidence("103", k, "confirmed", 1, 60_000L, Map.of());
    var bounded = policy(new ExecutionEvidence.SourceKey(spki(k), "2026-10-01T00:00:00.000Z", "2026-10-07T00:00:00.000Z"));
    var alone = ExecutionEvidence.checkLeaf(leaf, bounded);
    assertEquals("unbound", alone.status());
    assertFalse(alone.trusted());
    assertTrue(alone.reason().contains("cannot be placed in time"), alone.reason());
    assertTrue(ExecutionEvidence.checkLeaf(leaf, bounded, Ledger.parseAnchorTimestampMs("2026-10-06T00:00:00.000Z")).trusted());
    var revoked = ExecutionEvidence.checkLeaf(leaf, bounded, Ledger.parseAnchorTimestampMs("2026-10-07T00:00:00.001Z"));
    assertFalse(revoked.trusted());
    assertTrue(revoked.reason().contains("not valid at this record's anchored time"), revoked.reason());
    var malformed = policy(new ExecutionEvidence.SourceKey(spki(k), "2026-13-01T00:00:00.000Z", null));
    var bad = ExecutionEvidence.checkLeaf(leaf, malformed, Ledger.parseAnchorTimestampMs("2026-10-06T00:00:00.000Z"));
    assertEquals("unbound", bad.status());
    assertFalse(bad.trusted());
    assertTrue(bad.reason().contains("malformed validity interval"), bad.reason());
    // The statement's own timestamps never place the key: the sample lies inside the interval, yet
    // without an anchored time the key establishes nothing, and with one outside it still does not.
    var bundle = entries(approval("100"), dispatch("101", HASH, 600_000L), leaf);
    var unanchored = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(bounded, T0_MS, null, null, null));
    assertEquals("verified", unanchored.checks().get(0).check().status());
    assertFalse(unanchored.checks().get(0).check().trusted());
    assertEquals("pending", unanchored.byNonce().get("n-1").status());
    var anchored = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(bounded, T0_MS, null, null,
        seq -> seq.equals("103") ? Ledger.parseAnchorTimestampMs("2026-10-06T00:00:00.000Z") : null));
    assertTrue(anchored.checks().get(0).check().trusted());
    assertEquals("confirmed", anchored.byNonce().get("n-1").status());
    // A bare key beside the bounded one is unaffected by the interval.
    var mixed = policy(new ExecutionEvidence.SourceKey(spki(k), "2026-10-01T00:00:00.000Z", "2026-10-07T00:00:00.000Z"), spki(k));
    assertTrue(ExecutionEvidence.checkLeaf(leaf, mixed).trusted());
  }

  @Test
  void policyKeysComeInThreeFormsAndMalformedEntriesAreSkipped() throws Exception {
    KeyPair k = keyPair();
    var leaf = evidence("103", k, "confirmed", 1, 60_000L, Map.of());
    assertTrue(ExecutionEvidence.checkLeaf(leaf, policy(spki(k))).trusted());
    assertTrue(ExecutionEvidence.checkLeaf(leaf, policy(ExecutionEvidence.SourceKey.of(spki(k)))).trusted());
    assertTrue(ExecutionEvidence.checkLeaf(leaf, policy(Map.of("key", spki(k)))).trusted());
    var asMap = ExecutionEvidence.checkLeaf(leaf, policy(Map.of("key", spki(k), "notAfter", "2026-10-07T00:00:00.000Z")));
    assertFalse(asMap.trusted(), "a map-form key with an interval is bounded too");
    assertEquals("not_checked", ExecutionEvidence.checkLeaf(leaf, policy(1, "", Map.of("notBefore", T0))).status(),
        "only malformed entries is no key at all");
    assertTrue(ExecutionEvidence.checkLeaf(leaf, policy(1, "", spki(k))).trusted(), "a malformed entry does not hide a valid one");
    assertEquals("invalid", ExecutionEvidence.checkLeaf(leaf, policy(spki(keyPair()))).status());
    assertEquals("not_checked", ExecutionEvidence.checkLeaf(leaf, new ExecutionEvidence.Policy(Map.of())).status());
  }

  /** DEWP §4.7.5: a key entry that is not exactly {key, notBefore?, notAfter?} verifies but never trusts. */
  @Test
  void keyEntriesFailClosed() throws Exception {
    KeyPair k = keyPair();
    var leaf = evidence("103", k, "contradicted", 1, 60_000L, Map.of());
    long anchored = Ledger.parseAnchorTimestampMs("2026-10-06T00:00:00.000Z");
    // A misspelt bound is an unknown member, never "no bound": the key verifies and trusts nothing.
    var misspelt = ExecutionEvidence.checkLeaf(leaf, policy(Map.of("key", spki(k), "notafter", "2026-10-07T00:00:00.000Z")), anchored);
    assertEquals("unbound", misspelt.status());
    assertFalse(misspelt.trusted());
    assertTrue(misspelt.reason().contains("unexpected member(s) notafter"), misspelt.reason());
    // A bound that is present but is not a string fails closed too — a number, or an explicit null.
    var numeric = ExecutionEvidence.checkLeaf(leaf, policy(Map.of("key", spki(k), "notAfter", 1754006400000L)), anchored);
    assertEquals("unbound", numeric.status());
    assertFalse(numeric.trusted());
    assertTrue(numeric.reason().contains("notAfter is not a timestamp string"), numeric.reason());
    Map<String, Object> explicitNull = new HashMap<>();
    explicitNull.put("key", spki(k));
    explicitNull.put("notBefore", null);
    var nulled = ExecutionEvidence.checkLeaf(leaf, policy(explicitNull), anchored);
    assertFalse(nulled.trusted());
    assertTrue(nulled.reason().contains("notBefore is not a timestamp string"), nulled.reason());
    // A non-timestamp string bound is still the malformed interval.
    var text = ExecutionEvidence.checkLeaf(leaf, policy(Map.of("key", spki(k), "notAfter", "tomorrow")), anchored);
    assertFalse(text.trusted());
    assertTrue(text.reason().contains("malformed validity interval"), text.reason());
    // An entry with no usable string key is not provisioned at all.
    assertEquals("not_checked",
        ExecutionEvidence.checkLeaf(leaf, policy(Map.of("key", 7), Map.of("notAfter", T0), Map.of("key", "")), anchored).status());
    // A malformed entry beside a bare key: the bare key establishes trust on its own.
    assertTrue(ExecutionEvidence.checkLeaf(leaf, policy(Map.of("key", spki(k), "extra", 1), spki(k)), anchored).trusted());
    // The §4.6.1 signature report is held to the same anchored time, so the two reports agree.
    var bounded = new ExecutionEvidence.Policy(Map.of(SOURCE, List.of(Map.of("key", spki(k), "notAfter", "2026-10-07T00:00:00.000Z"))));
    assertTrue(AuditSignatures.verify(leaf, null, bounded, anchored).trusted());
    var unplaced = AuditSignatures.verify(leaf, null, bounded, null);
    assertEquals("verified", unplaced.status());
    assertFalse(unplaced.trusted());
    assertTrue(unplaced.reason().contains("cannot be placed in time"), unplaced.reason());
    assertFalse(AuditSignatures.verify(leaf, null, bounded).trusted(), "the three-argument form carries no anchored time");
    assertFalse(AuditSignatures.verify(leaf, null, bounded, Ledger.parseAnchorTimestampMs("2026-10-07T00:00:00.001Z")).trusted());
    var unknownMember = AuditSignatures.verify(leaf, null,
        new ExecutionEvidence.Policy(Map.of(SOURCE, List.of(Map.of("key", spki(k), "notafter", T0)))), anchored);
    assertEquals("verified", unknownMember.status());
    assertFalse(unknownMember.trusted());
  }

  /** DEWP §4.7.4: a contradiction under a provisioned key that established no trust is never silent. */
  @Test
  void untrustedContradictionIsAFinding() throws Exception {
    KeyPair k = keyPair();
    var contradiction = evidence("102", k, "contradicted", 1, 60_000L, Map.of("breaker", "closed"));
    var bundle = entries(approval("100"), dispatch("101", HASH, 600_000L), contradiction);
    // A bounded key the bundle cannot place in time: the statement is bound and inside the window and
    // its signature verified under the provisioned key, but the key established no trust.
    var bounded = policy(new ExecutionEvidence.SourceKey(spki(k), null, "2026-10-07T00:00:00.000Z"));
    var r = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(bounded, T0_MS, null, null, null));
    var n = r.byNonce().get("n-1");
    assertEquals("pending", n.status(), "an untrusted contradiction never decides the status");
    assertEquals("verified", r.checks().get(0).check().status());
    assertFalse(r.checks().get(0).check().trusted());
    assertEquals(List.of("102"), n.untrustedContradiction());
    assertEquals(List.of(), n.lateContradiction());
    assertEquals(List.of("n-1"), r.untrustedContradicted());
    // Outside the interval at the anchored time, and under a malformed entry: the same finding.
    var revoked = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(bounded, T0_MS, null, null,
        seq -> Ledger.parseAnchorTimestampMs("2026-10-08T00:00:00.000Z")));
    assertEquals(List.of("n-1"), revoked.untrustedContradicted());
    var malformed = ExecutionEvidence.evaluate(bundle,
        new ExecutionEvidence.Options(policy(Map.of("key", spki(k), "notafter", T0)), T0_MS, null, null, null));
    assertEquals(List.of("n-1"), malformed.untrustedContradicted());
    // Placed inside the interval, the contradiction counts and the finding is gone.
    var placed = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(bounded, T0_MS, null, null,
        seq -> Ledger.parseAnchorTimestampMs("2026-10-06T00:00:00.000Z")));
    assertEquals("contradicted", placed.byNonce().get("n-1").status());
    assertEquals(List.of(), placed.untrustedContradicted());
    // No policy means no provisioned key: an embedded-key contradiction is not this finding.
    var embedded = ExecutionEvidence.evaluate(bundle, new ExecutionEvidence.Options(null, T0_MS, null, null, null));
    assertFalse(embedded.checks().get(0).check().trusted());
    assertEquals(List.of(), embedded.untrustedContradicted());
    // Lateness does not silence a contradiction signed by a provisioned key without established trust.
    var late = ExecutionEvidence.evaluate(entries(approval("100"), dispatch("101", HASH, 600_000L),
        evidence("102", k, "contradicted", 1, 20 * 60_000L, Map.of())), new ExecutionEvidence.Options(bounded, T0_MS, null, null, null));
    assertEquals("stale", late.checks().get(0).check().status());
    assertFalse(late.checks().get(0).check().trusted());
    assertEquals(List.of("n-1"), late.untrustedContradicted());
    assertEquals(List.of("102"), late.byNonce().get("n-1").untrustedContradiction());
    assertEquals(List.of(), late.lateContradicted());
    // Unbound and confirmed statements are not this finding.
    var unbound = ExecutionEvidence.evaluate(entries(approval("100"), dispatch("101", OTHER_HASH, 600_000L), contradiction),
        new ExecutionEvidence.Options(bounded, T0_MS, null, null, null));
    assertEquals("unbound", unbound.checks().get(0).check().status());
    assertEquals(List.of(), unbound.untrustedContradicted());
    var confirmed = ExecutionEvidence.evaluate(entries(approval("100"), dispatch("101", HASH, 600_000L),
        evidence("102", k, "confirmed", 1, 60_000L, Map.of())), new ExecutionEvidence.Options(bounded, T0_MS, null, null, null));
    assertEquals(List.of(), confirmed.untrustedContradicted());
  }

  /** A skew or window that is not a non-negative number is no bound at all: the default applies. */
  @Test
  void negativeAllowancesFallBackToTheDefaults() throws Exception {
    KeyPair k = keyPair();
    long minute = 60_000L, hour = 3_600_000L;
    // Sampled 20 s before dispatch: inside the default 30 s skew. A negative skew must not narrow it
    // (or remove the early-sample limit); zero is a real bound.
    var early = entries(approval("100"), dispatch("101", HASH, 10 * minute), evidence("102", k, "confirmed", 1, -20_000L, Map.of()));
    assertEquals("verified", ExecutionEvidence.evaluate(early,
        new ExecutionEvidence.Options(policy(spki(k)), T0_MS, -1L, null, null)).checks().get(0).check().status());
    assertEquals("stale", ExecutionEvidence.evaluate(early,
        new ExecutionEvidence.Options(policy(spki(k)), T0_MS, 0L, null, null)).checks().get(0).check().status());
    // A deadline two days out is cut to the default 24 h; a negative window must not lift the cap.
    var far = entries(approval("100"), dispatch("101", HASH, 48 * hour));
    var n = ExecutionEvidence.evaluate(far, new ExecutionEvidence.Options(null, T0_MS + 25 * hour, null, -5L, null)).byNonce().get("n-1");
    assertEquals("unconfirmed", n.status());
    assertTrue(n.windowCapped());
    assertEquals(at(24 * hour), n.effectiveDeadline());
    var zero = ExecutionEvidence.evaluate(far, new ExecutionEvidence.Options(null, T0_MS + 1, null, 0L, null)).byNonce().get("n-1");
    assertEquals("unconfirmed", zero.status(), "a zero window is a real bound");
    assertEquals(at(0), zero.effectiveDeadline());
  }

  /**
   * DEWP §4.7.5: one root, one checkpoint. The vectors pin the anchored case; here the bare refusal
   * on a shared-vector bundle, and that an identical duplicate is tolerated.
   */
  @Test
  void aRootListedTwiceWithDifferentFieldsIsRefused() throws Exception {
    JsonNode vectors = Records.JSON.readTree(Files.readString(Path.of("vectors", "verifier-parity-vectors.json")));
    JsonNode base = null;
    for (JsonNode c : vectors.path("executionEvidence").path("cases")) if (c.path("name").asText().equals("confirmed")) base = c;
    assertNotNull(base);
    ObjectNode bundle = base.path("bundle").deepCopy();
    ArrayNode checkpoints = (ArrayNode) bundle.path("checkpoints");
    ObjectNode first = (ObjectNode) checkpoints.get(0);
    var opts = new Dewp.EvidenceOptions(Set.of(first.path("root").asText()), null, null, null, null, null, null, null, null, null);
    assertTrue(Dewp.verifyEvidenceBundle(Dewp.EvidenceBundle.parse(bundle), opts).ok());
    checkpoints.add(first.deepCopy());
    var tolerated = Dewp.verifyEvidenceBundle(Dewp.EvidenceBundle.parse(bundle), opts);
    assertTrue(tolerated.ok(), tolerated.failed().toString());
    assertEquals(1, tolerated.roots().size(), "one root is reported once");
    // A copy claiming a wider range, without the chain fields the first one is held to: refused.
    ObjectNode copy = first.deepCopy();
    copy.put("id", "cp-x-copy");
    copy.put("seqEnd", "999999999");
    copy.remove("chainHash");
    copy.remove("prevChainHash");
    copy.remove("entryCount");
    checkpoints.set(1, copy);
    var refused = Dewp.verifyEvidenceBundle(Dewp.EvidenceBundle.parse(bundle), opts);
    assertFalse(refused.ok());
    assertTrue(refused.failed().stream().anyMatch(f -> f.reason().equals(
        "checkpoint cp-x-copy lists a root the bundle already states with different fields")), refused.failed().toString());
    // The copy did not displace the first checkpoint: every entry is still bound to its range.
    assertEquals(4, refused.contentVerified());
  }

  @Test
  void parserReasonsNameTheNewRules() {
    String canonical = ExecutionEvidence.canonicalStatement(new ExecutionEvidence.Statement("n-1", HASH, Map.of(),
        "2026-10-05T14:02:11.000Z", "2026-10-05T14:02:09.500Z", 418, SOURCE, "confirmed"));
    assertTrue(canonical.contains("\"sampledAt\":\"2026-10-05T14:02:09.500Z\",\"sequence\":418,"));
    assertEquals(418, ExecutionEvidence.parseStatement(canonical).sequence());
    for (String spelling : List.of("418.0", "418.5", "\"418\"", "0", "-1", "9007199254740992")) {
      var e = assertThrows(ExecutionEvidence.MalformedStatementException.class,
          () -> ExecutionEvidence.parseStatement(canonical.replace("\"sequence\":418,", "\"sequence\":" + spelling + ",")), spelling);
      assertNotNull(e.getMessage());
    }
    var late = assertThrows(ExecutionEvidence.MalformedStatementException.class, () -> ExecutionEvidence.canonicalStatement(
        new ExecutionEvidence.Statement("n-1", HASH, Map.of(), "2026-10-05T14:02:11.000Z", "2026-10-05T14:02:11.001Z", 1, SOURCE, "confirmed")));
    assertEquals("sampledAt must not be later than observedAt", late.getMessage());
    var zero = assertThrows(ExecutionEvidence.MalformedStatementException.class, () -> ExecutionEvidence.canonicalStatement(
        new ExecutionEvidence.Statement("n-1", HASH, Map.of(), "2026-10-05T14:02:11.000Z", "2026-10-05T14:02:11.000Z", 0, SOURCE, "confirmed")));
    assertTrue(zero.getMessage().startsWith("sequence must be an integer"), zero.getMessage());
  }
}
