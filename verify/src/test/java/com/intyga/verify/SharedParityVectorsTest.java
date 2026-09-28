package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.*;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.HashMap;
import java.util.Base64;
import org.junit.jupiter.api.Test;

/** Executes the shared fixture cases that are represented by the Java Core Profile. */
final class SharedParityVectorsTest {
  private static JsonNode load() {
    try {
      return Records.JSON.readTree(Files.readString(Path.of("vectors", "verifier-parity-vectors.json")));
    } catch (IOException e) { throw new IllegalStateException(e); }
  }

  /** Merge a section's shared options with one case's overrides; the case wins. */
  private static ObjectNode merge(JsonNode section, JsonNode overrides) {
    ObjectNode merged = section.isObject() ? section.deepCopy() : Records.JSON.createObjectNode();
    if (overrides != null && overrides.isObject()) merged.setAll((ObjectNode) overrides);
    return merged;
  }

  private static List<String> submitterKeys(JsonNode o, Map<String, JsonNode> keyById) {
    if (!o.has("rekorSubmitterKeyIds")) return null;
    List<String> keys = new ArrayList<>();
    o.get("rekorSubmitterKeyIds").forEach(id -> keys.add(keyById.get(id.asText()).path("spkiB64").asText()));
    return keys;
  }

  private static VerifyOptions options(ObjectNode o) {
    VerifyOptions.Builder b = VerifyOptions.builder().asOf(java.time.Instant.parse(o.path("asOf").asText()));
    if (o.has("expectedOrigin")) b.expectedOrigin(o.path("expectedOrigin").asText());
    if (o.has("expectedRpId")) b.expectedRpId(o.path("expectedRpId").asText());
    if (o.has("clockSkewSeconds")) b.clockSkewSeconds(o.path("clockSkewSeconds").asInt());
    if (o.path("allowOffline").asBoolean(false)) b.allowOffline(true);
    if (o.has("requireUserVerification")) b.requireUserVerification(o.path("requireUserVerification").asBoolean());
    return b.build();
  }

  /** The fixture pins more than the verdict: a refusal that lands for the wrong reason, or an
   * acceptance crediting the wrong identities, is exactly the divergence these vectors catch. */
  private static void assertSigners(JsonNode c, List<String> got) {
    if (!c.has("signers")) return;
    List<String> want = new ArrayList<>();
    c.get("signers").forEach(s -> want.add(s.asText()));
    assertEquals(want, got, c.path("name").asText() + " signers");
  }

  /** A case's optional relying-party requirement floor (DIV §5 step 3d). */
  private static RequirementFloor floor(JsonNode expected) {
    JsonNode f = expected.get("requirement");
    if (f == null || f.isNull()) return null;
    return new RequirementFloor(f.path("requiredApprovals").asInt(), f.path("requesterCannotApprove").asBoolean(false), f.path("requireHardwareKey").asBoolean(false));
  }

  private static void assertReason(JsonNode c, String reason) {
    if (!c.has("reasonIncludes")) return;
    String fragment = c.path("reasonIncludes").asText();
    assertTrue(reason != null && reason.contains(fragment),
        c.path("name").asText() + ": reason \"" + reason + "\" does not contain \"" + fragment + "\"");
  }

  @Test void everyFixtureCaseHasAnExecutableVerdictAndChainsAreVerified() {
    JsonNode v = load();
    Map<String,JsonNode> keyById = new HashMap<>();
    for (JsonNode k : v.path("keys")) keyById.put(k.path("id").asText(), k);
    runApprovalCases(v.path("approvals"), keyById);
    runPlatformCases(v.path("platform"), keyById);
    runAuthorityCases(v.path("agentAuthority"), keyById);
    for (JsonNode c : v.path("rootsChain").path("cases")) {
      List<Ledger.RootsChainEntry> entries = new ArrayList<>();
      for (JsonNode e : c.path("entries")) {
        entries.add(new Ledger.RootsChainEntry(e.path("seqStart").asText(), e.path("seqEnd").asText(),
            e.path("entryCount").asInt(), e.path("root").asText(), e.path("anchoredAt").asText(),
            e.has("prevChainHash") ? e.path("prevChainHash").asText() : null,
            e.has("chainHash") ? e.path("chainHash").asText() : null));
      }
      Ledger.ChainVerification result = Ledger.verifyRootsChain(entries);
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText());
      assertEquals(c.path("brokenAt").asInt(), result.brokenAt(), c.path("name").asText());
      assertEquals(c.path("unchained").asBoolean(), result.unchained(), c.path("name").asText());
      if (c.has("verifiedCount")) assertEquals(c.path("verifiedCount").asInt(), result.verifiedCount(), c.path("name").asText() + " verifiedCount");
    }
    runBundleCases(v.path("bundles").path("cases"), keyById, v.path("bundles").path("anchorPolicy"));
    runEvidenceCases(v.path("evidence").path("cases"), keyById);
  }

  private static void runApprovalCases(JsonNode section, Map<String,JsonNode> keyById) {
    for (JsonNode c : section.path("cases")) {
      ObjectNode expected = section.path("expected").deepCopy();
      if (c.has("expected")) expected.setAll((ObjectNode)c.get("expected"));
      List<String> publicKeys = new ArrayList<>();
      // A WEBAUTHN witness verifies under the credential's COSE_Key; such cases say so explicitly.
      String encoding = "cose".equals(c.path("approverKeyEncoding").asText()) ? "coseB64" : "spkiB64";
      expected.path("approverKeyIds").forEach(id -> publicKeys.add(keyById.get(id.asText()).path(encoding).asText()));
      Map<String,Object> params = Records.JSON.convertValue(expected.path("params"), new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>() {});
      Map<String,Object> agentContext = expected.has("agentContext") ? Records.JSON.convertValue(expected.path("agentContext"), new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>() {}) : null;
      Expected e = new Expected(expected.path("target").asText(), expected.path("nonce").asText(), expected.path("actionType").asText(), params, ApproverTrustAnchor.ofPublicKeys(publicKeys), agentContext, floor(expected));
      var result = Verify.verifyApprovalReceipt(ApprovalReceipt.parse(c.path("receipt")), e,
          options(merge(section.path("options"), c.get("options"))));
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText() + ": " + result.reason());
      assertSigners(c, result.signers());
      assertReason(c, result.reason());
    }
  }

  private static void runPlatformCases(JsonNode section, Map<String,JsonNode> keyById) {
    for (JsonNode c : section.path("cases")) {
      JsonNode e = section.path("expected");
      ObjectNode merged = e.deepCopy(); if (c.has("expected")) merged.setAll((ObjectNode)c.get("expected"));
      String keyId = merged.path("approverKeyIds").get(0).asText();
      JsonNode key = keyById.get(keyId);
      PlatformReceipt receipt = PlatformReceipt.parse(c.path("receipt"));
      PlatformExpected expected = new PlatformExpected(ApproverTrustAnchor.ofPublicKeys(List.of(key.path("coseB64").asText())), merged.has("payloadHash") ? merged.path("payloadHash").asText() : e.path("payloadHash").asText(), merged.has("rpId") ? merged.path("rpId").asText() : e.path("rpId").asText(), merged.has("nonce") ? merged.path("nonce").asText() : e.path("nonce").asText(), merged.has("subjectExternalId") ? merged.path("subjectExternalId").asText() : e.path("subjectExternalId").asText());
      ObjectNode op = merge(section.path("options"), c.get("options"));
      VerifyOptions.Builder ob = VerifyOptions.builder().expectedOrigin(op.path("expectedOrigin").asText()).expectedRpId(expected.rpId()).asOf(java.time.Instant.parse(op.path("asOf").asText()));
      if (op.has("requireUserVerification")) ob.requireUserVerification(op.path("requireUserVerification").asBoolean());
      VerifyOptions opts = ob.build();
      PlatformVerification result = Verify.verifyPlatformReceipt(receipt, expected, opts);
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText() + ": " + result.reason());
      assertSigners(c, result.signers());
      assertReason(c, result.reason());
    }
  }

  private static void runAuthorityCases(JsonNode section, Map<String,JsonNode> keyById) {
    for (JsonNode c : section.path("cases")) {
      JsonNode e = section.path("expected");
      ObjectNode merged = e.deepCopy(); if (c.has("expected")) merged.setAll((ObjectNode)c.get("expected"));
      Map<String,List<String>> ids = new HashMap<>(); merged.path("approverDids").fields().forEachRemaining(x -> { List<String> ks = new ArrayList<>(); x.getValue().forEach(z -> ks.add(keyById.get(z.asText()).path("spkiB64").asText())); ids.put(x.getKey(), ks); });
      ApproverTrustAnchor anchor = ApproverTrustAnchor.ofDidsMultiKey(new ArrayList<>(ids.keySet()), did -> ids.get(did));
      if (merged.has("approverKeyIds")) {
        List<String> publicKeys = new ArrayList<>();
        merged.get("approverKeyIds").forEach(id -> publicKeys.add(keyById.get(id.asText()).path("spkiB64").asText()));
        anchor = ApproverTrustAnchor.ofPublicKeys(publicKeys);
      }
      AgentAuthorityExpected expected = new AgentAuthorityExpected(anchor, merged.path("target").asText(), merged.path("agentDid").asText(), floor(merged));
      ObjectNode op = merge(section.path("options"), c.get("options"));
      if (!op.has("clockSkewSeconds")) op.put("clockSkewSeconds", 30);
      AgentAuthorityVerification result = Verify.verifyAgentAuthority(ApprovalReceipt.parse(c.path("receipt")), expected, options(op));
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText() + ": " + result.reason());
      assertReason(c, result.reason());
      if (c.has("signers") || c.has("actionPatterns")) {
        assertNotNull(result.authority(), c.path("name").asText() + ": no verified authority to inspect");
        assertSigners(c, result.authority().signers());
        if (c.has("actionPatterns")) {
          List<String> want = new ArrayList<>();
          c.get("actionPatterns").forEach(p -> want.add(p.asText()));
          assertEquals(want, result.authority().actionPatterns(), c.path("name").asText() + " actionPatterns");
        }
      }
    }
  }

  /** The verifier input-hardening section (2026-09-27 review L15-L18, I7, I8): own keys, same harness. */
  @Test void verifierInputHardeningVectors() {
    JsonNode h = load().path("verifierInputHardening");
    for (String part : List.of("approvals", "platform", "agentAuthority", "bundles"))
      assertTrue(h.path(part).path("cases").size() > 0, part);
    Map<String,JsonNode> own = new HashMap<>();
    for (JsonNode k : h.path("keys")) own.put(k.path("id").asText(), k);
    runApprovalCases(h.path("approvals"), own);
    runPlatformCases(h.path("platform"), own);
    runAuthorityCases(h.path("agentAuthority"), own);
    runBundleCases(h.path("bundles").path("cases"), own, null);
  }

  /** The DEWP evidence-hardening section carries its own keys; a policy applies only when a case has one. */
  @Test void dewpEvidenceHardeningVectors() {
    JsonNode h = load().path("dewpEvidenceHardening");
    assertTrue(h.path("bundles").path("cases").size() > 0 && h.path("evidence").path("cases").size() > 0);
    Map<String,JsonNode> own = new HashMap<>();
    for (JsonNode k : h.path("keys")) own.put(k.path("id").asText(), k);
    runBundleCases(h.path("bundles").path("cases"), own, null);
    runEvidenceCases(h.path("evidence").path("cases"), own);
  }

  private static java.util.function.Function<Ledger.SignedAnchor, java.security.PublicKey> resolver(Map<String,JsonNode> keyById) {
    return a -> { JsonNode k = keyById.get(a.keyId()); return k == null ? null : Ledger.parseAnchorPublicKey(k.path("spkiB64").asText(), a.algorithm()); };
  }

  private static void runBundleCases(JsonNode cases, Map<String,JsonNode> keyById, JsonNode defaultPolicy) {
    for (JsonNode c : cases) {
      Dewp.ProofBundle b = Dewp.ProofBundle.parse(c.path("bundle"));
      JsonNode o = c.path("options");
      JsonNode policyNode = c.has("policy") ? c.get("policy") : defaultPolicy;
      Ledger.AnchorPolicy policy = policyNode == null ? null : Records.JSON.convertValue(policyNode, Ledger.AnchorPolicy.class);
      List<Ledger.SignedAnchor> callerAnchors = new ArrayList<>();
      for (JsonNode a : o.path("divergenceAnchors")) callerAnchors.add(Records.JSON.convertValue(a, Ledger.SignedAnchor.class));
      Dewp.BundleOptions options = new Dewp.BundleOptions(
          o.path("trustedRoot").isMissingNode() ? null : o.path("trustedRoot").asText(),
          callerAnchors.isEmpty() ? null : callerAnchors, policy, resolver(keyById),
          o.has("rekorKeyId") ? keyById.get(o.path("rekorKeyId").asText()).path("spkiB64").asText() : null,
          null, o.has("rekorIssuer") ? o.path("rekorIssuer").asText() : null, submitterKeys(o, keyById),
          o.has("trustedCheckpoint") ? Records.JSON.convertValue(o.get("trustedCheckpoint"), Ledger.TrustedCheckpoint.class) : null);
      Dewp.BundleVerification result = Dewp.verifyBundle(b, options);
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText() + " " + result.notes());
      if (c.has("witnessTimes")) {
        Map<String, Long> want = new java.util.TreeMap<>();
        c.get("witnessTimes").fields().forEachRemaining(e -> want.put(e.getKey(), e.getValue().asLong()));
        assertEquals(want, new java.util.TreeMap<>(result.witnessTimes()), c.path("name").asText() + " witnessTimes");
      }
      if (c.has("verificationLevel")) assertEquals(c.path("verificationLevel").asText(), result.verificationLevel(), c.path("name").asText());
      JsonNode props = Records.JSON.valueToTree(result.properties());
      c.path("properties").fields().forEachRemaining(e -> assertEquals(e.getValue().asBoolean(), props.path(e.getKey()).asBoolean(), c.path("name").asText()));
    }
  }

  private static void runEvidenceCases(JsonNode cases, Map<String,JsonNode> keyById) {
    for (JsonNode c : cases) {
      Dewp.EvidenceBundle b = Dewp.EvidenceBundle.parse(c.path("bundle"));
      JsonNode o = c.path("options");
      Set<String> roots = null;
      if (o.has("trustedRoots")) {
        roots = new java.util.HashSet<>();
        for (JsonNode r : o.path("trustedRoots")) roots.add(r.asText());
      }
      List<Ledger.TrustedCheckpoint> records = null;
      if (o.has("trustedCheckpoints")) {
        records = new ArrayList<>();
        for (JsonNode r : o.path("trustedCheckpoints")) records.add(Records.JSON.convertValue(r, Ledger.TrustedCheckpoint.class));
      }
      JsonNode anchorInput = o.path("anchors");
      Map<String,List<Ledger.SignedAnchor>> keyed = null;
      List<Ledger.SignedAnchor> flat = null;
      if (anchorInput.isObject()) {
        keyed = new HashMap<>();
        var fields = anchorInput.fields();
        while (fields.hasNext()) {
          var field = fields.next(); List<Ledger.SignedAnchor> list = new ArrayList<>();
          for (JsonNode a : field.getValue()) list.add(Records.JSON.convertValue(a, Ledger.SignedAnchor.class));
          keyed.put(field.getKey(), list);
        }
      } else if (anchorInput.isArray()) {
        flat = new ArrayList<>();
        for (JsonNode a : anchorInput) flat.add(Records.JSON.convertValue(a, Ledger.SignedAnchor.class));
      }
      Ledger.AnchorPolicy policy = c.has("policy") ? Records.JSON.convertValue(c.get("policy"), Ledger.AnchorPolicy.class) : null;
      Dewp.EvidenceVerification result = Dewp.verifyEvidenceBundle(b,
          new Dewp.EvidenceOptions(roots, keyed, policy, policy == null ? null : resolver(keyById),
              o.has("rekorKeyId") ? keyById.get(o.path("rekorKeyId").asText()).path("spkiB64").asText() : null,
              flat, null, o.has("rekorIssuer") ? o.path("rekorIssuer").asText() : null, submitterKeys(o, keyById),
              records));
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText() + " " + result.failed() + " " + result.notes());
      if (c.has("total")) assertEquals(c.path("total").asInt(), result.total(), c.path("name").asText());
      if (c.has("contentVerified")) assertEquals(c.path("contentVerified").asInt(), result.contentVerified(), c.path("name").asText());
      if (c.has("commitmentOnly")) assertEquals(c.path("commitmentOnly").asInt(), result.commitmentOnly(), c.path("name").asText() + " commitmentOnly");
    }
  }

  @Test void canonicalAuthorityAndPlatformBuildersMatchGoldenVectors() {
    JsonNode v;
    try { v = Records.JSON.readTree(Files.readString(Path.of("vectors", "canonical-vectors.json"))); }
    catch (IOException e) { throw new IllegalStateException(e); }
    for (JsonNode item : v.path("agentAuthorityPayloads")) {
      JsonNode i = item.path("input");
      String got = Verify.canonicalAgentAuthorityPayload(i.path("target").asText(), Records.JSON.convertValue(i.path("actionPatterns"), new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {}), i.path("actionDescription").asText(), i.path("agentDid").asText(), Records.JSON.convertValue(i.path("requester"), RequesterIdentity.class), Records.JSON.convertValue(i.path("requirement"), ApprovalRequirement.class), i.path("nonce").asText(), i.path("sealedAt").asText(), i.path("expiresAt").asText(), i.path("parentReceiptHash").isNull() ? null : i.path("parentReceiptHash").asText());
      assertEquals(item.path("expected").asText(), got);
    }
    for (JsonNode item : v.path("agentIntentPayloads")) {
      JsonNode i = item.path("input");
      String got = Canonical.canonicalIntentPayload(
          i.path("target").asText(), i.path("actionType").asText(), i.path("actionDescription").asText(),
          Records.JSON.convertValue(i.path("params"), new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {}),
          Records.JSON.convertValue(i.path("requester"), RequesterIdentity.class),
          Records.JSON.convertValue(i.path("requirement"), ApprovalRequirement.class),
          i.path("nonce").asText(), i.path("expiresAt").asText(),
          Records.JSON.convertValue(i.path("agentContext"), new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {}));
      assertEquals(item.path("expected").asText(), got);
    }
    for (JsonNode item : v.path("platformIntentPayloads").path("cases")) {
      JsonNode i = item.path("input");
      assertEquals(item.path("expected").asText(), Verify.canonicalPlatformIntentPayload(i.path("payloadHash").asText(), i.path("rpId").asText(), i.path("subjectExternalId").asText(), i.path("signedAt").asText(), i.path("expiresAt").asText(), i.path("nonce").asText()));
    }
  }
}
