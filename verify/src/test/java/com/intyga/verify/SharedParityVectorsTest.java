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

  /**
   * The vectors write refusal texts with the TypeScript API names; Java's own names come from the
   * {@code java} map of api-name-hints.json. Longest token first, through placeholders, so a
   * replacement is never rescanned (packages/verify/src/verifier-parity-vectors.test.ts localized()).
   */
  private static final JsonNode HINTS = loadHints();
  private static JsonNode loadHints() {
    try {
      return Records.JSON.readTree(Files.readString(Path.of("vectors", "api-name-hints.json")));
    } catch (IOException e) { throw new IllegalStateException(e); }
  }
  static String localized(String text) {
    List<String> order = new ArrayList<>();
    HINTS.path("tokens").forEach(t -> order.add(t.asText()));
    order.sort((a, b) -> Integer.compare(b.length(), a.length()));
    String out = text;
    for (int i = 0; i < order.size(); i++) out = out.replace(order.get(i), "\u0000" + i + "\u0000");
    for (int i = 0; i < order.size(); i++) out = out.replace("\u0000" + i + "\u0000", HINTS.path("java").path(order.get(i)).asText());
    return out;
  }

  @Test void javaApiNameMapCoversExactlyTheTokens() {
    Set<String> tokens = new java.util.TreeSet<>();
    HINTS.path("tokens").forEach(t -> tokens.add(t.asText()));
    Set<String> mapped = new java.util.TreeSet<>();
    HINTS.path("java").fieldNames().forEachRemaining(mapped::add);
    assertEquals(tokens, mapped, "api-name-hints.json java map must name exactly the tokens");
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
    if (o.path("allowExpired").asBoolean(false)) b.allowExpired(true);
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

  /**
   * A case's optional relying-party requirement floor (DIV §5 step 3d), through the library's own
   * JSON reading. The typed record cannot hold a wrongly typed flag, so {@link RequirementFloor#fromJson}
   * is where Java refuses one, with the verifier's malformed-floor text: the caller receives that
   * refusal instead of a verification result, and {@link #floorRefusal} asserts it like a verdict.
   */
  private static RequirementFloor floor(JsonNode expected) {
    return RequirementFloor.fromJson(expected.get("requirement"));
  }

  /** The malformed-floor refusal, or null when the case's floor reads. Asserted as a refused verdict. */
  private static String floorRefusal(JsonNode c, JsonNode expected) {
    try {
      floor(expected);
      return null;
    } catch (IllegalArgumentException malformed) {
      assertFalse(c.path("ok").asBoolean(), c.path("name").asText() + ": floor refused: " + malformed.getMessage());
      assertFalse(c.has("signers"), c.path("name").asText() + ": a refused floor credits no signers");
      assertReason(c, malformed.getMessage());
      return malformed.getMessage();
    }
  }

  /**
   * The enrolledDevice section's harness input: {@code enrolledDeviceKeyIds} map through the
   * section's keys to SPKI; a literal {@code enrolledDeviceKeys} passes verbatim (a non-string entry
   * as null, which the verifier refuses as malformed). Absent both, the expectation carries none.
   */
  private static Expected withEnrolledDevices(Expected e, JsonNode expected, Map<String, JsonNode> keyById) {
    List<String> keys = null;
    if (expected.has("enrolledDeviceKeyIds")) {
      keys = new ArrayList<>();
      for (JsonNode id : expected.get("enrolledDeviceKeyIds")) keys.add(keyById.get(id.asText()).path("spkiB64").asText());
    } else if (expected.has("enrolledDeviceKeys")) {
      keys = new ArrayList<>();
      for (JsonNode k : expected.get("enrolledDeviceKeys")) keys.add(k.isTextual() ? k.textValue() : null);
    }
    return keys == null ? e : e.withEnrolledDeviceKeys(keys);
  }

  private static void assertReason(JsonNode c, String reason) {
    // `reason` is the exact refusal text every port must produce (the TS reference's).
    if (c.has("reason")) {
      org.junit.jupiter.api.Assertions.assertEquals(localized(c.path("reason").asText()), reason,
          c.path("name").asText() + ": exact reason");
    }
    if (!c.has("reasonIncludes")) return;
    String fragment = localized(c.path("reasonIncludes").asText());
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
      ApproverTrustAnchor anchor;
      if (expected.has("approverDids")) {
        Map<String, List<String>> resolved = new HashMap<>();
        List<String> coseDids = new ArrayList<>();
        c.path("approverCoseDids").forEach(did -> coseDids.add(did.asText()));
        expected.path("approverDids").fields().forEachRemaining(entry -> {
          List<String> keys = new ArrayList<>();
          String encoding = coseDids.contains(entry.getKey()) ? "coseB64" : "spkiB64";
          entry.getValue().forEach(id -> keys.add(keyById.get(id.asText()).path(encoding).asText()));
          resolved.put(entry.getKey(), keys);
        });
        // Harness instruction: the resolver throws for these DIDs.
        List<String> throwsFor = new ArrayList<>();
        expected.path("resolverThrowsFor").forEach(did -> throwsFor.add(did.asText()));
        if (expected.path("resolverOmitted").asBoolean(false)) {
          // Harness instruction: a DID-mode anchor with no resolver at all.
          anchor = ApproverTrustAnchor.ofDids(new ArrayList<>(resolved.keySet()), null);
        } else {
          anchor = ApproverTrustAnchor.ofDidsMultiKey(new ArrayList<>(resolved.keySet()), did -> {
            if (throwsFor.contains(did)) throw new IllegalStateException("resolver unavailable for " + did);
            return resolved.get(did);
          });
        }
      } else {
        List<String> publicKeys = new ArrayList<>();
        // A WEBAUTHN witness verifies under the credential's COSE_Key; such cases say so explicitly.
        String encoding = "cose".equals(c.path("approverKeyEncoding").asText()) ? "coseB64" : "spkiB64";
        expected.path("approverKeyIds").forEach(id -> publicKeys.add(keyById.get(id.asText()).path(encoding).asText()));
        anchor = ApproverTrustAnchor.ofPublicKeys(publicKeys);
      }
      Map<String,Object> params = Records.JSON.convertValue(expected.path("params"), new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>() {});
      Map<String,Object> agentContext = expected.has("agentContext") ? Records.JSON.convertValue(expected.path("agentContext"), new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>() {}) : null;
      if (floorRefusal(c, expected) != null) continue;
      Expected e = new Expected(expected.path("target").asText(), expected.path("nonce").asText(), expected.path("actionType").asText(), params, anchor, agentContext, floor(expected));
      // expected.tenantId: absent means omitted.
      if (expected.hasNonNull("tenantId")) e = e.withTenantId(expected.path("tenantId").asText());
      if (expected.hasNonNull("requesterDid")) e = e.withRequesterDid(expected.path("requesterDid").asText());
      e = withEnrolledDevices(e, expected, keyById);
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
      if (floorRefusal(c, merged) != null) continue;
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

  /** The standalone WebAuthn witness cases (absent witness/expectation fields are omitted). */
  @Test void webauthnWitnessVectors() {
    JsonNode section = load().path("webauthnWitness");
    assertTrue(section.path("cases").size() > 0, "webauthnWitness section has no cases");
    for (JsonNode c : section.path("cases")) {
      JsonNode w = c.path("witness");
      java.util.function.Function<String, String> text = f -> w.hasNonNull(f) && w.get(f).isTextual() ? w.get(f).asText() : null;
      WebAuthnWitness witness = c.has("witness") && w.isObject()
          ? new WebAuthnWitness(text.apply("signedPayload"), text.apply("publicKey"),
              text.apply("authenticatorData"), text.apply("clientDataJSON"), text.apply("signature"))
          : null;
      WebAuthnWitnessExpectation expectation = null;
      JsonNode e = c.path("expectation");
      if (e.isObject()) {
        List<String> origins = null;
        JsonNode o = e.get("expectedOrigin");
        if (o != null && o.isTextual()) origins = List.of(o.asText());
        else if (o != null && o.isArray()) {
          origins = new ArrayList<>();
          for (JsonNode x : o) origins.add(x.isTextual() ? x.asText() : null);
        }
        expectation = new WebAuthnWitnessExpectation(origins,
            e.hasNonNull("expectedRpId") ? e.get("expectedRpId").asText() : null,
            e.has("requireUserVerification") ? e.get("requireUserVerification").asBoolean() : null,
            e.path("allowCrossOrigin").asBoolean(false));
      }
      VerifyResult result = Verify.verifyWebAuthnWitness(witness, expectation);
      String name = c.path("name").asText();
      assertEquals(c.path("ok").asBoolean(), result.ok(), name + ": " + result.reason());
      assertReason(c, result.reason());
      if (c.has("reasonPrefix")) {
        String prefix = localized(c.path("reasonPrefix").asText());
        assertTrue(result.reason() != null && result.reason().startsWith(prefix),
            name + ": reason \"" + result.reason() + "\" lacks prefix \"" + prefix + "\"");
      }
    }
  }

  /** The shared delegation (seal) cases: DID-mode anchor over expected.approverDids. */
  @Test void delegationVectors() {
    JsonNode v = load();
    Map<String,JsonNode> keyById = new HashMap<>();
    for (JsonNode k : v.path("keys")) keyById.put(k.path("id").asText(), k);
    runDelegationCases(v.path("delegation"), keyById);
  }

  /**
   * DIV §4.3.2 enrolled approver devices: the enrolledDevice section with its own keys, through the
   * same approval, delegation and agent-authority harnesses (verifier-parity-vectors.test.ts).
   */
  @Test void enrolledDeviceVectors() {
    JsonNode section = load().path("enrolledDevice");
    for (String part : List.of("approvals", "delegation", "agentAuthority"))
      assertTrue(section.path(part).path("cases").size() > 0, "enrolledDevice." + part + " has no cases");
    Map<String,JsonNode> own = new HashMap<>();
    for (JsonNode k : section.path("keys")) own.put(k.path("id").asText(), k);
    assertFalse(own.isEmpty(), "enrolledDevice section has no keys");
    runApprovalCases(section.path("approvals"), own);
    runDelegationCases(section.path("delegation"), own);
    runAuthorityCases(section.path("agentAuthority"), own);
  }

  private static void runDelegationCases(JsonNode section, Map<String,JsonNode> keyById) {
    assertTrue(section.path("cases").size() > 0, "delegation section has no cases");
    for (JsonNode c : section.path("cases")) {
      ObjectNode expected = section.path("expected").deepCopy();
      if (c.has("expected")) expected.setAll((ObjectNode) c.get("expected"));
      Map<String, List<String>> ids = new HashMap<>();
      expected.path("approverDids").fields().forEachRemaining(x -> {
        List<String> ks = new ArrayList<>();
        x.getValue().forEach(z -> ks.add(keyById.get(z.asText()).path("spkiB64").asText()));
        ids.put(x.getKey(), ks);
      });
      ApproverTrustAnchor anchor = ApproverTrustAnchor.ofDidsMultiKey(new ArrayList<>(ids.keySet()), ids::get);
      Map<String,Object> params = Records.JSON.convertValue(expected.path("params"), new com.fasterxml.jackson.core.type.TypeReference<Map<String,Object>>() {});
      if (floorRefusal(c, expected) != null) continue;
      Expected e = new Expected(expected.path("target").asText(), null, expected.path("actionType").asText(), params, anchor, null, floor(expected));
      if (expected.hasNonNull("tenantId")) e = e.withTenantId(expected.path("tenantId").asText());
      if (expected.hasNonNull("requesterDid")) e = e.withRequesterDid(expected.path("requesterDid").asText());
      DelegationVerification result = Verify.verifyDelegation(ApprovalReceipt.parse(c.path("receipt")), e,
          options(merge(section.path("options"), c.get("options"))));
      String name = c.path("name").asText();
      assertEquals(c.path("ok").asBoolean(), result.result().ok(), name + ": " + result.result().reason());
      assertReason(c, result.result().reason());
      if (c.has("signers") || c.has("delegatedTo") || c.has("delegatedQuorum")) {
        assertNotNull(result.delegation(), name + ": no verified delegation to inspect");
        assertSigners(c, result.delegation().signers());
        if (c.has("delegatedTo")) {
          List<String> want = new ArrayList<>();
          c.get("delegatedTo").forEach(d -> want.add(d.asText()));
          assertEquals(want, result.delegation().delegatedTo(), name + " delegatedTo");
        }
        if (c.has("delegatedQuorum"))
          assertEquals(c.get("delegatedQuorum").asInt(), result.delegation().delegatedQuorum(), name + " delegatedQuorum");
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

  /** DEWP §4.7 (version 1.1): the shared executionEvidence section, run exactly as TS runs it. */
  @Test
  void executionEvidenceVectors() {
    JsonNode section = load().path("executionEvidence");
    assertTrue(section.path("cases").size() > 0 && section.path("proofs").size() > 0);
    var mapType = new com.fasterxml.jackson.core.type.TypeReference<Map<String, List<String>>>() {};
    // Evidence-source keys are bare SPKI strings or {key, notBefore?, notAfter?} objects (DEWP §4.7.5).
    var policyType = new com.fasterxml.jackson.core.type.TypeReference<Map<String, List<Object>>>() {};
    for (JsonNode c : section.path("cases")) {
      String name = c.path("name").asText();
      JsonNode o = c.path("options");
      Set<String> roots = new java.util.HashSet<>();
      o.path("trustedRoots").forEach(r -> roots.add(r.asText()));
      ExecutionEvidence.Policy evidence = o.has("evidencePolicy")
          ? new ExecutionEvidence.Policy(Records.JSON.convertValue(o.path("evidencePolicy").path("trustedSources"), policyType)) : null;
      AuditSignatures.Policy signatures = o.has("signaturePolicy")
          ? new AuditSignatures.Policy(Records.JSON.convertValue(o.path("signaturePolicy").path("trustedSigners"), mapType), null, null) : null;
      // The anchored-time cases (DEWP §4.7.5) carry a Rekor-witnessed anchor in the bundle's checkpoint
      // and pin the log key inline: the case `policy` is the anchor policy, `rekorSpki` the Rekor key.
      Ledger.AnchorPolicy anchorPolicy = null;
      if (c.has("policy")) {
        List<String> issuers = new ArrayList<>();
        c.path("policy").path("trustedIssuers").forEach(i -> issuers.add(i.asText()));
        anchorPolicy = new Ledger.AnchorPolicy(c.path("policy").path("requiredAnchors").asInt(), issuers,
            c.path("policy").path("quorum").asText());
      }
      String rekorKey = o.has("rekorSpki") ? o.path("rekorSpki").asText() : null;
      var opts = new Dewp.EvidenceOptions(roots, null, anchorPolicy, null, rekorKey, null, null, null, null, null, signatures, false,
          evidence, o.path("requireExecutionConfirmed").asBoolean(false), Ledger.parseAnchorTimestampMs(o.path("now").asText()),
          o.has("skewSeconds") ? o.path("skewSeconds").asLong() : null,
          o.has("maxWindowSeconds") ? o.path("maxWindowSeconds").asLong() : null);
      var r = Dewp.verifyEvidenceBundle(Dewp.EvidenceBundle.parse(c.path("bundle")), opts);
      assertEquals(c.path("ok").asBoolean(), r.ok(), name + " " + r.failed());
      if (c.has("contentVerified")) assertEquals(c.path("contentVerified").asInt(), r.contentVerified(), name + " contentVerified");
      if (c.has("commitmentOnly")) assertEquals(c.path("commitmentOnly").asInt(), r.commitmentOnly(), name + " commitmentOnly");
      Map<String, String> byNonce = new HashMap<>();
      r.execution().byNonce().forEach((n, v) -> byNonce.put(n, v.status()));
      Map<String, String> wantByNonce = new HashMap<>();
      c.path("execution").path("byNonce").fields().forEachRemaining(f -> wantByNonce.put(f.getKey(), f.getValue().asText()));
      assertEquals(wantByNonce, byNonce, name + " byNonce");
      List<String> got = new ArrayList<>();
      r.execution().checks().forEach(k -> got.add(k.seq() + "/" + k.check().status() + "/" + k.check().trusted()));
      List<String> want = new ArrayList<>();
      c.path("execution").path("checks").forEach(k -> want.add(k.path("seq").asText() + "/" + k.path("status").asText() + "/" + k.path("trusted").asBoolean()));
      List<String> reasons = new ArrayList<>();
      r.execution().checks().forEach(k -> reasons.add(k.check().reason()));
      assertEquals(want, got, name + " checks " + reasons);
      // Every §4.7.4 finding the case pins: late and untrusted contradictions, dispatch conflicts, the
      // window cap per nonce and per-source continuity.
      JsonNode f = c.path("execution").path("findings");
      if (f.has("lateContradicted")) assertEquals(strings(f.path("lateContradicted")), r.execution().lateContradicted(), name + " late");
      if (f.has("untrustedContradicted")) assertEquals(strings(f.path("untrustedContradicted")), r.execution().untrustedContradicted(), name + " untrusted");
      if (f.has("dispatchConflicts")) assertEquals(strings(f.path("dispatchConflicts")), r.execution().dispatchConflicts(), name + " conflicts");
      if (f.has("windowCapped")) {
        Map<String, Boolean> capped = new HashMap<>(), wantCapped = new HashMap<>();
        r.execution().byNonce().forEach((n, v) -> capped.put(n, v.windowCapped()));
        f.path("windowCapped").fields().forEachRemaining(x -> wantCapped.put(x.getKey(), x.getValue().asBoolean()));
        assertEquals(wantCapped, capped, name + " windowCapped");
      }
      if (f.has("sources"))
        assertEquals(Canonical.stableStringify(Records.JSON.convertValue(f.path("sources"), Object.class)),
            Canonical.stableStringify(Records.JSON.convertValue(r.execution().sources(), Object.class)), name + " sources");
      if (c.has("signatures")) {
        List<String> sigs = new ArrayList<>();
        r.signatures().checks().forEach(k -> sigs.add(k.seq() + "/" + k.status() + "/" + k.trusted()));
        List<String> wantSigs = new ArrayList<>();
        c.path("signatures").forEach(k -> wantSigs.add(k.path("seq").asText() + "/" + k.path("status").asText() + "/" + k.path("trusted").asBoolean()));
        assertEquals(wantSigs, sigs, name + " signatures");
      }
    }
    for (JsonNode c : section.path("proofs")) {
      String name = c.path("name").asText();
      JsonNode o = c.path("options");
      ExecutionEvidence.Policy evidence = o.has("evidencePolicy")
          ? new ExecutionEvidence.Policy(Records.JSON.convertValue(o.path("evidencePolicy").path("trustedSources"), policyType)) : null;
      var opts = new Dewp.BundleOptions(o.path("trustedRoot").asText(), null, null, null, null, null, null, null, null, null, false, evidence);
      var r = Dewp.verifyBundle(Dewp.ProofBundle.parse(c.path("bundle")), opts);
      assertTrue(r.properties().contentVerified(), name);
      String got = r.execution() == null ? null : r.execution().status() + "/" + r.execution().trusted();
      String want = c.path("execution").isNull() ? null : c.path("execution").path("status").asText() + "/" + c.path("execution").path("trusted").asBoolean();
      assertEquals(want, got, name);
    }
    for (JsonNode c : section.path("statements")) {
      boolean ok;
      try { ExecutionEvidence.parseStatement(c.path("bytes").asText()); ok = true; }
      catch (ExecutionEvidence.MalformedStatementException e) { ok = false; }
      assertEquals(c.path("ok").asBoolean(), ok, "statement " + c.path("name").asText());
    }
    for (JsonNode c : section.path("builder")) {
      JsonNode i = c.path("input");
      String got = ExecutionEvidence.canonicalStatement(new ExecutionEvidence.Statement(
          i.path("nonce").asText(), i.path("payloadSha256").asText(),
          Records.JSON.convertValue(i.path("observation"), new com.fasterxml.jackson.core.type.TypeReference<Map<String, Object>>() {}),
          i.path("observedAt").asText(), i.path("sampledAt").asText(), i.path("sequence").asLong(),
          i.path("source").asText(), i.path("verdict").asText()));
      assertEquals(c.path("bytes").asText(), got, "builder " + c.path("name").asText());
    }
  }

  private static List<String> strings(JsonNode array) {
    List<String> out = new ArrayList<>();
    array.forEach(x -> out.add(x.asText()));
    return out;
  }
}
