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

  private static VerifyOptions options(ObjectNode o) {
    VerifyOptions.Builder b = VerifyOptions.builder().asOf(java.time.Instant.parse(o.path("asOf").asText()));
    if (o.has("expectedOrigin")) b.expectedOrigin(o.path("expectedOrigin").asText());
    if (o.has("clockSkewSeconds")) b.clockSkewSeconds(o.path("clockSkewSeconds").asInt());
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
    for (JsonNode c : v.path("approvals").path("cases")) {
      ObjectNode expected = v.path("approvals").path("expected").deepCopy();
      if (c.has("expected")) expected.setAll((ObjectNode)c.get("expected"));
      List<String> publicKeys = new ArrayList<>();
      expected.path("approverKeyIds").forEach(id -> publicKeys.add(keyById.get(id.asText()).path("spkiB64").asText()));
      Map<String,Object> params = Records.JSON.convertValue(expected.path("params"), new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>() {});
      Expected e = new Expected(expected.path("target").asText(), expected.path("nonce").asText(), expected.path("actionType").asText(), params, ApproverTrustAnchor.ofPublicKeys(publicKeys));
      var result = Verify.verifyApprovalReceipt(ApprovalReceipt.parse(c.path("receipt")), e,
          options(merge(v.path("approvals").path("options"), c.get("options"))));
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText() + ": " + result.reason());
      assertSigners(c, result.signers());
      assertReason(c, result.reason());
    }
    for (JsonNode c : v.path("platform").path("cases")) {
      JsonNode e = v.path("platform").path("expected");
      ObjectNode merged = e.deepCopy(); if (c.has("expected")) merged.setAll((ObjectNode)c.get("expected"));
      String keyId = e.path("approverKeyIds").get(0).asText();
      JsonNode key = null; for (JsonNode k : v.path("keys")) if (keyId.equals(k.path("id").asText())) key = k;
      PlatformReceipt receipt = PlatformReceipt.parse(c.path("receipt"));
      PlatformExpected expected = new PlatformExpected(ApproverTrustAnchor.ofPublicKeys(List.of(key.path("coseB64").asText())), merged.has("payloadHash") ? merged.path("payloadHash").asText() : e.path("payloadHash").asText(), merged.has("rpId") ? merged.path("rpId").asText() : e.path("rpId").asText(), merged.has("nonce") ? merged.path("nonce").asText() : e.path("nonce").asText(), merged.has("subjectExternalId") ? merged.path("subjectExternalId").asText() : e.path("subjectExternalId").asText());
      ObjectNode op = merge(v.path("platform").path("options"), c.get("options"));
      VerifyOptions opts = VerifyOptions.builder().expectedOrigin(op.path("expectedOrigin").asText()).expectedRpId(expected.rpId()).asOf(java.time.Instant.parse(op.path("asOf").asText())).build();
      PlatformVerification result = Verify.verifyPlatformReceipt(receipt, expected, opts);
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText() + ": " + result.reason());
      assertSigners(c, result.signers());
      assertReason(c, result.reason());
    }
    for (JsonNode c : v.path("agentAuthority").path("cases")) {
      JsonNode e = v.path("agentAuthority").path("expected");
      ObjectNode merged = e.deepCopy(); if (c.has("expected")) merged.setAll((ObjectNode)c.get("expected"));
      Map<String,List<String>> ids = new HashMap<>(); merged.path("approverDids").fields().forEachRemaining(x -> { List<String> ks = new ArrayList<>(); x.getValue().forEach(z -> ks.add(keyById.get(z.asText()).path("spkiB64").asText())); ids.put(x.getKey(), ks); });
      ApproverTrustAnchor anchor = ApproverTrustAnchor.ofDidsMultiKey(new ArrayList<>(ids.keySet()), did -> ids.get(did));
      if (merged.has("approverKeyIds")) {
        List<String> publicKeys = new ArrayList<>();
        merged.get("approverKeyIds").forEach(id -> publicKeys.add(keyById.get(id.asText()).path("spkiB64").asText()));
        anchor = ApproverTrustAnchor.ofPublicKeys(publicKeys);
      }
      AgentAuthorityExpected expected = new AgentAuthorityExpected(anchor, merged.path("target").asText(), merged.path("agentDid").asText());
      ObjectNode op = merge(v.path("agentAuthority").path("options"), c.get("options"));
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
    for (JsonNode c : v.path("bundles").path("cases")) {
      Dewp.ProofBundle b = Dewp.ProofBundle.parse(c.path("bundle"));
      JsonNode o = c.path("options");
      JsonNode policyNode = c.has("policy") ? c.get("policy") : v.path("bundles").path("anchorPolicy");
      Ledger.AnchorPolicy policy = Records.JSON.convertValue(policyNode, Ledger.AnchorPolicy.class);
      List<Ledger.SignedAnchor> callerAnchors = new ArrayList<>();
      for (JsonNode a : o.path("divergenceAnchors")) callerAnchors.add(Records.JSON.convertValue(a, Ledger.SignedAnchor.class));
      Dewp.BundleOptions options = new Dewp.BundleOptions(
          o.path("trustedRoot").isMissingNode() ? null : o.path("trustedRoot").asText(),
          callerAnchors.isEmpty() ? null : callerAnchors, policy,
          a -> { JsonNode k = keyById.get(a.keyId()); return k == null ? null : Ledger.parseAnchorPublicKey(k.path("spkiB64").asText(), a.algorithm()); },
          o.has("rekorKeyId") ? keyById.get(o.path("rekorKeyId").asText()).path("spkiB64").asText() : null);
      Dewp.BundleVerification result = Dewp.verifyBundle(b, options);
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText());
      if (c.has("verificationLevel")) assertEquals(c.path("verificationLevel").asText(), result.verificationLevel(), c.path("name").asText());
      JsonNode props = Records.JSON.valueToTree(result.properties());
      c.path("properties").fields().forEachRemaining(e -> assertEquals(e.getValue().asBoolean(), props.path(e.getKey()).asBoolean(), c.path("name").asText()));
    }
    for (JsonNode c : v.path("evidence").path("cases")) {
      Dewp.EvidenceBundle b = Dewp.EvidenceBundle.parse(c.path("bundle"));
      Set<String> roots = new java.util.HashSet<>();
      for (JsonNode r : c.path("options").path("trustedRoots")) roots.add(r.asText());
      JsonNode anchorInput = c.path("options").path("anchors");
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
          new Dewp.EvidenceOptions(roots, keyed, policy,
              policy == null ? null : a -> Ledger.parseAnchorPublicKey(keyById.get(a.keyId()).path("spkiB64").asText(), a.algorithm()), null, flat));
      assertEquals(c.path("ok").asBoolean(), result.ok(), c.path("name").asText());
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
      String got = Verify.canonicalAgentAuthorityPayload(i.path("target").asText(), Records.JSON.convertValue(i.path("actionPatterns"), new com.fasterxml.jackson.core.type.TypeReference<List<String>>() {}), i.path("actionDescription").asText(), i.path("agentDid").asText(), Records.JSON.convertValue(i.path("requester"), RequesterIdentity.class), Records.JSON.convertValue(i.path("requirement"), ApprovalRequirement.class), i.path("nonce").asText(), i.path("sealedAt").asText(), i.path("expiresAt").asText());
      assertEquals(item.path("expected").asText(), got);
    }
    for (JsonNode item : v.path("platformIntentPayloads").path("cases")) {
      JsonNode i = item.path("input");
      assertEquals(item.path("expected").asText(), Verify.canonicalPlatformIntentPayload(i.path("payloadHash").asText(), i.path("rpId").asText(), i.path("subjectExternalId").asText(), i.path("signedAt").asText(), i.path("expiresAt").asText(), i.path("nonce").asText()));
    }
  }
}
