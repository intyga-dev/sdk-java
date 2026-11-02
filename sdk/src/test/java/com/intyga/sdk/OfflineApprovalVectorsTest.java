package com.intyga.sdk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.intyga.sdk.offline.AnchorPurpose;
import com.intyga.sdk.offline.ApproverDirectory;
import com.intyga.sdk.offline.BundleApprover;
import com.intyga.sdk.offline.BundlePolicy;
import com.intyga.sdk.offline.ChallengeRequest;
import com.intyga.sdk.offline.ChallengeResult;
import com.intyga.sdk.offline.DecodedChallenge;
import com.intyga.sdk.offline.DecodedChallengeResult;
import com.intyga.sdk.offline.OfflineAction;
import com.intyga.sdk.offline.OfflineApproval;
import com.intyga.sdk.offline.OfflineApprovalOptions;
import com.intyga.sdk.offline.OfflineApprovalResult;
import com.intyga.sdk.offline.OfflineChallenge;
import com.intyga.sdk.offline.ResolvedRequirement;
import com.intyga.sdk.offline.SignResult;
import com.intyga.sdk.offline.SignatureEnvelopeResult;
import com.intyga.sdk.offline.TrustAnchorFile;
import com.intyga.sdk.offline.TrustAnchorPurpose;
import com.intyga.sdk.offline.TrustBundle;
import com.intyga.sdk.offline.TrustBundleResult;
import com.intyga.verify.ApprovalRequirement;
import com.intyga.verify.ApprovalWitness;
import com.intyga.verify.Canonical;
import com.intyga.verify.RequesterAttestation;
import com.intyga.verify.RequesterIdentity;
import com.intyga.verify.VerifiedDelegation;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Comparator;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicContainer;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import org.junit.jupiter.api.io.TempDir;

/**
 * The Java SDK against the shared offline-approval conformance vectors
 * ({@code packages/mcp-schemas/vectors/offline-approval-vectors.json}, docs/OFFLINE-APPROVAL-SDK.md),
 * run section by section the way the reference harness {@code packages/sdk/src/offline-vectors.test.ts}
 * runs them. One dynamic test per case, so the report counts cases rather than sections.
 *
 * <p>Reads the COMMITTED file, never a generator. The path is the one the public-tree script
 * rewrites ({@code vectors/} → {@code vectors/}); Maven runs tests from the module dir.
 */
class OfflineApprovalVectorsTest {

  private static final ObjectMapper JSON = new ObjectMapper();
  private static final JsonNode V = load();

  @TempDir Path scratch;

  private static JsonNode load() {
    try {
      return JSON.readTree(Files.readString(Path.of("vectors/offline-approval-vectors.json")));
    } catch (IOException e) {
      throw new IllegalStateException("cannot read offline-approval-vectors.json", e);
    }
  }

  // --- key derivation (keyDerivation in the vector file) ----------------------------------------

  private static final ECParameterSpec P256 = p256();

  private static ECParameterSpec p256() {
    try {
      AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
      params.init(new ECGenParameterSpec("secp256r1"));
      return params.getParameterSpec(ECParameterSpec.class);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /** d = (uint256_be(SHA-256(utf8(seed))) mod (n − 1)) + 1. */
  static PrivateKey keyFromSeed(String seed) {
    try {
      byte[] h = MessageDigest.getInstance("SHA-256").digest(seed.getBytes(StandardCharsets.UTF_8));
      BigInteger n = P256.getOrder();
      BigInteger d = new BigInteger(1, h).mod(n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
      return KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(d, P256));
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static JsonNode person(String id) {
    return V.get("people").get(id);
  }

  static JsonNode keyOf(String id, String kind) {
    JsonNode k = person(id).get("keys").get(kind);
    if (k == null) {
      throw new IllegalStateException(id + " has no " + kind + " key");
    }
    return k;
  }

  static String sign(String id, String kind, String payload) {
    try {
      Signature s = Signature.getInstance("SHA256withECDSAinP1363Format");
      s.initSign(keyFromSeed(keyOf(id, kind).get("seed").textValue()));
      s.update(payload.getBytes(StandardCharsets.UTF_8));
      return Base64.getEncoder().encodeToString(s.sign());
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static boolean verifyWithSpki(String spkiB64, String payload, String sigB64) {
    try {
      PublicKey pub = KeyFactory.getInstance("EC")
          .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(spkiB64)));
      Signature v = Signature.getInstance("SHA256withECDSAinP1363Format");
      v.initVerify(pub);
      v.update(payload.getBytes(StandardCharsets.UTF_8));
      return v.verify(Base64.getDecoder().decode(sigB64));
    } catch (Exception e) {
      return false;
    }
  }

  // --- comparison helpers -------------------------------------------------------------------------

  /**
   * Deep equality on JSON-shaped values by canonical bytes: IntNode(2) vs LongNode(2), Integer vs
   * Long, map vs object node all compare by value, and object key order is irrelevant.
   */
  static String canon(Object value) {
    Object plain = value instanceof JsonNode n ? JSON.convertValue(n, Object.class) : JSON.convertValue(value, Object.class);
    return Canonical.stableStringify(plain);
  }

  static void assertJsonEquals(Object expected, Object actual, String message) {
    assertEquals(canon(expected), canon(actual), message);
  }

  static List<String> strings(JsonNode n) {
    List<String> out = new ArrayList<>();
    if (n != null) {
      n.forEach(e -> out.add(e.textValue()));
    }
    return out;
  }

  static Map<String, Object> map(JsonNode n) {
    @SuppressWarnings("unchecked")
    Map<String, Object> m = JSON.convertValue(n, LinkedHashMap.class);
    return m;
  }

  /**
   * Every refusal carries the reference reason: exact {@code reason}, or {@code reasonPrefix} where
   * the text embeds a platform library's own message. Mirrors assertReason in offline-vectors.test.ts.
   */
  private static final JsonNode HINTS = loadHints();

  private static JsonNode loadHints() {
    try {
      return JSON.readTree(Files.readString(Path.of("vectors/api-name-hints.json")));
    } catch (IOException e) {
      throw new IllegalStateException("cannot read api-name-hints.json", e);
    }
  }

  /**
   * The vectors write texts with the TypeScript API names; Java's own spellings come from the
   * {@code java} map of api-name-hints.json, longest token first, through placeholders so a value
   * is never rescanned (localized() in offline-vectors.test.ts).
   */
  static String localized(String text) {
    List<String> order = new ArrayList<>();
    HINTS.get("tokens").forEach(t -> order.add(t.textValue()));
    order.sort((a, b) -> Integer.compare(b.length(), a.length()));
    String out = text;
    for (int i = 0; i < order.size(); i++) out = out.replace(order.get(i), "\u0000" + i + "\u0000");
    for (int i = 0; i < order.size(); i++) {
      out = out.replace("\u0000" + i + "\u0000", HINTS.get("java").get(order.get(i)).textValue());
    }
    return out;
  }

  @Test
  void javaApiNameMapCoversExactlyTheTokens() {
    java.util.Set<String> tokens = new java.util.TreeSet<>();
    HINTS.get("tokens").forEach(t -> tokens.add(t.textValue()));
    java.util.Set<String> mapped = new java.util.TreeSet<>();
    HINTS.get("java").fieldNames().forEachRemaining(mapped::add);
    assertEquals(tokens, mapped);
  }

  static void assertReason(JsonNode c, String got) {
    String label = c.path("name").asText();
    if (c.has("reason")) {
      assertEquals(localized(c.get("reason").textValue()), got, label + ": reason");
    } else if (c.has("reasonPrefix")) {
      String prefix = localized(c.get("reasonPrefix").textValue());
      assertTrue(got != null && got.startsWith(prefix), label + ": reason " + got + " lacks prefix " + prefix);
    } else {
      fail(label + ": a refusal vector must carry reason or reasonPrefix");
    }
  }

  static Instant at(JsonNode c) {
    return Instant.parse(c.get("asOf").textValue());
  }

  static String name(JsonNode c) {
    return c.get("name").textValue();
  }

  static Stream<JsonNode> cases(String section) {
    JsonNode s = V.get(section);
    assertNotNull(s, section);
    assertTrue(s.size() > 0, section + " has no cases");
    List<JsonNode> out = new ArrayList<>();
    s.forEach(out::add);
    return out.stream();
  }

  static JsonNode bundleToJson(TrustBundle b) {
    ObjectNode o = JSON.createObjectNode();
    o.put("v", b.v());
    o.put("type", b.type());
    o.put("tenantId", b.tenantId());
    if (b.webauthnOrigin() != null) {
      o.putObject("webauthn").put("origin", b.webauthnOrigin()).put("rpId", b.webauthnRpId());
    }
    ArrayNode approvers = o.putArray("approvers");
    for (BundleApprover a : b.approvers()) {
      ObjectNode an = approvers.addObject();
      an.put("did", a.did());
      an.set("publicKeys", JSON.valueToTree(a.publicKeys()));
      if (a.offlinePublicKeys() != null) {
        an.set("offlinePublicKeys", JSON.valueToTree(a.offlinePublicKeys()));
      }
    }
    ArrayNode policy = o.putArray("policy");
    for (BundlePolicy p : b.policy()) {
      ObjectNode pn = policy.addObject();
      pn.put("signerClass", p.signerClass());
      pn.put("requiredApprovals", p.requiredApprovals());
      pn.put("requireHardwareKey", p.requireHardwareKey());
      pn.set("allowedAaguids", JSON.valueToTree(p.allowedAaguids()));
      pn.put("requesterCannotApprove", p.requesterCannotApprove());
      pn.put("requireAttestedRequester", p.requireAttestedRequester());
      pn.set("allowedIssuers", JSON.valueToTree(p.allowedIssuers()));
      pn.set("escalationApproverDids", JSON.valueToTree(p.escalationApproverDids()));
      pn.set("escalateAfterSeconds", JSON.valueToTree(p.escalateAfterSeconds()));
      pn.put("autoApproveRequesterDid", p.autoApproveRequesterDid());
      pn.set("autoApproveDayOfWeek", JSON.valueToTree(p.autoApproveDayOfWeek()));
      pn.put("autoApproveWindowStart", p.autoApproveWindowStart());
      pn.put("autoApproveWindowEnd", p.autoApproveWindowEnd());
      pn.put("actionPattern", p.actionPattern());
      pn.set("approverDids", JSON.valueToTree(p.approverDids()));
      if (p.excludedSignerDids() != null) {
        pn.set("excludedSignerDids", JSON.valueToTree(p.excludedSignerDids()));
      }
      // Only ever true, and only in a version 2 bundle (DIV §5a.4).
      if (p.requireEnrolledDevice()) {
        pn.put("requireEnrolledDevice", true);
      }
      if (p.selectionRank() != null) {
        pn.put("selectionRank", p.selectionRank());
      }
      if (p.selectionKey() != null) {
        pn.put("selectionKey", p.selectionKey());
      }
    }
    if (!b.requesterControllers().isEmpty()) {
      o.set("requesterControllers", JSON.valueToTree(b.requesterControllers()));
    }
    o.put("unmatchedActionPolicy", b.unmatchedActionPolicy());
    o.put("issuedAt", b.issuedAt());
    o.put("expiresAt", b.expiresAt());
    return o;
  }

  static ApprovalRequirement requirementOf(JsonNode n) {
    return new ApprovalRequirement(
        n.get("requiredApprovals").intValue(),
        n.get("requireHardwareKey").booleanValue(),
        strings(n.get("allowedAaguids")),
        n.get("requesterCannotApprove").booleanValue(),
        n.get("signerClass").textValue(),
        n.has("excludedSignerDids") ? strings(n.get("excludedSignerDids")) : null,
        // Absent stays null (the field is not signed); present is the signed value.
        n.has("requireEnrolledDevice") ? Boolean.valueOf(n.get("requireEnrolledDevice").booleanValue()) : null);
  }

  static RequesterIdentity requesterOf(JsonNode n) {
    JsonNode a = n.get("attestation");
    return new RequesterIdentity(
        n.get("did").textValue(),
        a == null || a.isNull()
            ? null
            : new RequesterAttestation(
                a.get("method").textValue(), a.get("issuer").textValue(), a.get("subject").textValue()),
        n.has("credentialIssuerDid") ? n.get("credentialIssuerDid").textValue() : null);
  }

  static AnchorPurpose purposeOf(String wire) {
    switch (wire) {
      case "ordinary":
        return AnchorPurpose.ORDINARY;
      case "offline-intent":
        return AnchorPurpose.OFFLINE_INTENT;
      default:
        throw new IllegalArgumentException(wire);
    }
  }

  // --- the sections -------------------------------------------------------------------------------

  @Test
  void derivesEveryPublishedKeyFromItsSeed() {
    Iterator<Map.Entry<String, JsonNode>> people = V.get("people").fields();
    int checked = 0;
    while (people.hasNext()) {
      Map.Entry<String, JsonNode> p = people.next();
      Iterator<Map.Entry<String, JsonNode>> keys = p.getValue().get("keys").fields();
      while (keys.hasNext()) {
        Map.Entry<String, JsonNode> k = keys.next();
        String label = p.getKey() + "/" + k.getKey();
        PrivateKey key = keyFromSeed(k.getValue().get("seed").textValue());
        String spki = k.getValue().get("spki").textValue();
        // The SDK's own derivation (ECDH with the generator) must land on the published key…
        assertEquals(spki, OfflineApproval.signingPublicKey(key), label);
        // …and, independently of it, a JDK signature must verify under the published key.
        String sig = sign(p.getKey(), k.getKey(), "probe " + label);
        assertTrue(verifyWithSpki(spki, "probe " + label, sig), label);
        checked++;
      }
    }
    assertTrue(checked > 0);
  }

  @TestFactory
  Stream<DynamicNode> trustBundle() {
    return cases("trustBundle").map(c -> DynamicTest.dynamicTest(name(c), () -> {
      JsonNode jwk = c.hasNonNull("gatewayJwk") ? c.get("gatewayJwk") : V.get("gatewayJwk");
      TrustBundleResult r = TrustBundle.verify(c.get("jws").textValue(), jwk, at(c));
      assertEquals(c.get("ok").booleanValue(), r.ok(), name(c) + ": " + r.reason());
      if (r.ok()) {
        assertJsonEquals(c.get("bundle"), bundleToJson(r.bundle()), name(c));
      } else {
        assertReason(c, r.reason());
        assertNull(r.bundle(), name(c));
      }
    }));
  }

  @TestFactory
  Stream<DynamicNode> bundleAnchor() {
    return cases("bundleAnchor").map(c -> {
      JsonNode limit = c.get("limitToDids");
      String label = c.get("purpose").textValue() + (limit == null || limit.isNull() ? "" : " " + limit);
      return DynamicTest.dynamicTest(label, () -> {
        ObjectNode payload = V.get("bundle").deepCopy();
        if (c.has("approvers")) payload.set("approvers", c.get("approvers"));
        if (c.has("controllerKeys")) payload.set("controllerKeys", c.get("controllerKeys"));
        TrustBundle bundle = TrustBundle.parseUnverified(payload);
        ApproverDirectory dir = null;
        String reason = null;
        try {
          dir = bundle.approverDirectory(
              limit == null || limit.isNull() ? null : strings(limit), purposeOf(c.get("purpose").textValue()),
              c.has("excludedDids") ? strings(c.get("excludedDids")) : List.of());
        } catch (IllegalArgumentException refused) {
          assertFalse(c.get("ok").booleanValue(), label + " unexpectedly refused: " + refused.getMessage());
          reason = refused.getMessage();
        }
        assertEquals(c.get("ok").booleanValue(), dir != null, label);
        if (dir == null) {
          assertReason(c, reason);
          // The anchor form refuses the same way (an exception, never an empty fail-closed anchor).
          String anchorReason = null;
          try {
            bundle.approverAnchor(limit == null || limit.isNull() ? null : strings(limit),
                purposeOf(c.get("purpose").textValue()),
                c.has("excludedDids") ? strings(c.get("excludedDids")) : List.of());
          } catch (IllegalArgumentException refused) {
            anchorReason = refused.getMessage();
          }
          assertReason(c, anchorReason);
        }
        if (dir == null) return;
        assertEquals(strings(c.get("expect").get("dids")), dir.dids(), label);
        ApproverDirectory checkedDir = dir;
        c.get("expect").get("keys").fields().forEachRemaining(e -> {
          List<String> want = e.getValue().isNull() ? null : strings(e.getValue());
          assertEquals(want, checkedDir.resolveKey(e.getKey()), label + " " + e.getKey());
        });
        assertNotNull(dir.toTrustAnchor());
      });
    });
  }

  @TestFactory
  Stream<DynamicNode> requirementFor() {
    return cases("requirementFor").map(c -> DynamicTest.dynamicTest(name(c), () -> {
      ObjectNode payload = V.get("bundle").deepCopy();
      // Harness input (docs/OFFLINE-APPROVAL-SDK.md, "Running the vectors"): the bundle's `v`.
      if (c.has("bundleVersion")) payload.set("v", c.get("bundleVersion"));
      payload.set("policy", c.get("policy"));
      payload.set("unmatchedActionPolicy", c.get("unmatchedActionPolicy"));
      if (c.has("requesterControllers")) payload.set("requesterControllers", c.get("requesterControllers"));
      Optional<ResolvedRequirement> got = TrustBundle.parseUnverified(payload)
          .requirementFor(c.get("actionType").textValue(), c.get("display").textValue(),
              c.has("requesterDid") ? c.get("requesterDid").textValue() : null);
      JsonNode expect = c.get("expect");
      if (expect.isNull()) {
        assertTrue(got.isEmpty(), name(c) + " should refuse");
        return;
      }
      assertTrue(got.isPresent(), name(c) + " should resolve");
      assertEquals(requirementOf(expect.get("requirement")), got.get().requirement(), name(c));
      assertEquals(strings(expect.get("approverDids")), got.get().approverDids(), name(c));
    }));
  }

  @TestFactory
  Stream<DynamicNode> trustAnchorFile() {
    return cases("trustAnchorFile").map(c -> DynamicTest.dynamicTest(name(c), () -> {
      TrustAnchorPurpose purpose =
          "offline".equals(c.get("purpose").textValue()) ? TrustAnchorPurpose.OFFLINE : TrustAnchorPurpose.ONLINE;
      ObjectNode got = null;
      String reason = null;
      try {
        TrustAnchorFile parsed = TrustAnchorFile.parse(c.get("text").textValue(), purpose);
        ApproverDirectory dir = parsed.approverDirectory(null);
        got = JSON.createObjectNode();
        got.put("purpose", parsed.purpose().wire());
        got.put("epoch", parsed.epoch());
        if (parsed.tenantId() != null) got.put("tenantId", parsed.tenantId());
        got.set("dids", JSON.valueToTree(dir.dids()));
        ObjectNode keys = got.putObject("keys");
        for (String did : dir.dids()) {
          keys.set(did, JSON.valueToTree(dir.resolveKey(did)));
        }
        // trustAnchorEnrolledDeviceKeys: carried only when the file names some (an empty list reads as absent).
        if (!parsed.enrolledDeviceKeys().isEmpty()) got.set("enrolledDeviceKeys", JSON.valueToTree(parsed.enrolledDeviceKeys()));
        assertNotNull(parsed.approverAnchor(null));
      } catch (IllegalArgumentException refused) {
        reason = refused.getMessage();
      }
      assertEquals(c.get("ok").booleanValue(), got != null, name(c));
      if (c.get("ok").booleanValue()) {
        assertJsonEquals(c.get("expect"), got, name(c));
      } else {
        assertReason(c, reason);
      }
    }));
  }

  @TestFactory
  Stream<DynamicNode> createChallenge() {
    return cases("createChallenge").map(c -> DynamicTest.dynamicTest(name(c), () -> {
      JsonNode in = c.get("input");
      ObjectNode bundlePayload = V.get("bundle").deepCopy();
      // Harness inputs: the bundle's `v` and a replacement `policy`.
      if (in.has("bundleVersion")) bundlePayload.set("v", in.get("bundleVersion"));
      if (in.has("bundlePolicy")) bundlePayload.set("policy", in.get("bundlePolicy"));
      if (in.has("bundleTenantId")) {
        if (in.get("bundleTenantId").isNull()) bundlePayload.remove("tenantId");
        else bundlePayload.set("tenantId", in.get("bundleTenantId"));
      }
      if (in.has("bundleRequesterControllers")) {
        if (in.get("bundleRequesterControllers").isNull()) bundlePayload.remove("requesterControllers");
        else bundlePayload.set("requesterControllers", in.get("bundleRequesterControllers"));
      }
      TrustBundle bundle = TrustBundle.parseUnverified(bundlePayload);
      ChallengeRequest.Builder req = ChallengeRequest.builder()
          .bundle(bundle)
          .target(in.get("target").textValue())
          .actionType(in.get("actionType").textValue())
          .display(in.get("display").textValue())
          .params(map(in.get("params")))
          .requester(requesterOf(in.get("requester")))
          .asOf(Instant.parse(in.get("asOf").textValue()));
      if (in.has("nonce")) {
        req.nonce(in.get("nonce").textValue());
      }
      if (in.has("windowMinutes")) {
        // Through the Number overload, so a fractional window is refused at the reference's position.
        req.windowMinutes(in.get("windowMinutes").numberValue());
      }
      JsonNode d = in.get("delegation");
      if (d != null && !d.isNull()) {
        req.delegation(new VerifiedDelegation(
            strings(d.get("delegatedTo")),
            d.get("delegatedQuorum").intValue(),
            in.get("target").textValue(),
            in.get("actionType").textValue(),
            map(in.get("params")),
            d.get("nonce").textValue(),
            List.of(),
            null,
            d.hasNonNull("tenantId") ? d.get("tenantId").textValue() : null));
      }
      ChallengeResult r = OfflineApproval.createOfflineChallenge(req.build());
      assertEquals(c.get("ok").booleanValue(), r.ok(), name(c) + ": " + r.reason());
      if (!r.ok()) {
        assertReason(c, r.reason());
        assertNull(r.challenge(), name(c));
        return;
      }
      OfflineChallenge ch = r.challenge();
      c.get("expect").fields().forEachRemaining(e -> {
        String field = e.getKey();
        JsonNode want = e.getValue();
        String msg = name(c) + "." + field;
        switch (field) {
          case "nonce" -> assertEquals(want.textValue(), ch.nonce(), msg);
          case "canonicalPayload" -> assertEquals(want.textValue(), ch.canonicalPayload(), msg);
          case "verificationCode" -> assertEquals(want.textValue(), ch.verificationCode(), msg);
          case "envelope" -> assertEquals(want.textValue(), ch.envelope(), msg);
          case "challengedAt" -> assertEquals(want.textValue(), ch.challengedAt(), msg);
          case "expiresAt" -> assertEquals(want.textValue(), ch.expiresAt(), msg);
          case "requirement" -> assertEquals(requirementOf(want), ch.requirement(), msg);
          case "approverDids" -> assertEquals(strings(want), ch.approverDids(), msg);
          case "tenantId" -> assertEquals(want.isNull() ? null : want.textValue(), ch.tenantId(), msg);
          default -> fail("createChallenge vector expects a field this harness does not check: " + field);
        }
      });
    }));
  }

  @TestFactory
  Stream<DynamicNode> challengeEnvelope() {
    return cases("challengeEnvelope").map(c -> DynamicTest.dynamicTest(name(c), () -> {
      DecodedChallengeResult r = OfflineApproval.decodeChallengeEnvelope(c.get("envelope").textValue());
      assertEquals(c.get("ok").booleanValue(), r.ok(), name(c) + ": " + r.reason());
      if (!r.ok()) {
        assertReason(c, r.reason());
        return;
      }
      DecodedChallenge d = r.challenge();
      JsonNode e = c.get("expect");
      assertTrue(e.size() == 11 || e.size() == 12, name(c) + ": unexpected expectation fields");
      assertEquals(e.get("canonicalPayload").textValue(), d.canonicalPayload(), name(c));
      assertEquals(e.get("verificationCode").textValue(), d.verificationCode(), name(c));
      assertEquals(e.get("target").textValue(), d.target(), name(c));
      assertEquals(e.get("actionType").textValue(), d.actionType(), name(c));
      assertEquals(e.get("display").textValue(), d.display(), name(c));
      assertJsonEquals(e.get("params"), d.params(), name(c));
      assertEquals(requesterOf(e.get("requester")), d.requester(), name(c));
      assertEquals(requirementOf(e.get("requirement")), d.requirement(), name(c));
      assertEquals(e.get("nonce").textValue(), d.nonce(), name(c));
      assertEquals(e.get("challengedAt").textValue(), d.challengedAt(), name(c));
      assertEquals(e.get("expiresAt").textValue(), d.expiresAt(), name(c));
      if (e.has("tenantId"))
        assertEquals(e.get("tenantId").isNull() ? null : e.get("tenantId").textValue(), d.tenantId(), name(c));
    }));
  }

  static ApprovalWitness witnessOf(JsonNode w) {
    return new ApprovalWitness(
        w.get("signerDid").textValue(),
        w.get("signerPublicKey").textValue(),
        w.get("signature").textValue(),
        w.get("sigAlg").textValue(),
        null,
        null);
  }

  @TestFactory
  Stream<DynamicNode> signatureEnvelope() {
    JsonNode s = V.get("signatureEnvelope");
    List<DynamicNode> nodes = new ArrayList<>();
    int i = 0;
    for (JsonNode c : s.get("encode")) {
      nodes.add(DynamicTest.dynamicTest("encode #" + i++, () ->
          assertEquals(c.get("envelope").textValue(), OfflineApproval.encodeSignatureEnvelope(witnessOf(c.get("witness"))))));
    }
    for (JsonNode c : s.get("decode")) {
      nodes.add(DynamicTest.dynamicTest("decode " + name(c), () -> {
        SignatureEnvelopeResult r = OfflineApproval.decodeSignatureEnvelope(c.get("envelope").textValue());
        assertEquals(c.get("ok").booleanValue(), r.ok(), name(c) + ": " + r.reason());
        if (r.ok()) {
          assertEquals(witnessOf(c.get("witness")), r.witness(), name(c));
        } else {
          assertReason(c, r.reason());
        }
      }));
    }
    assertFalse(nodes.isEmpty());
    return Stream.of(DynamicContainer.dynamicContainer("signatureEnvelope", nodes));
  }

  @TestFactory
  Stream<DynamicNode> signChallenge() {
    return cases("signChallenge").map(c -> DynamicTest.dynamicTest(name(c), () -> {
      JsonNode signer = c.get("signer");
      PrivateKey key = keyFromSeed(keyOf(signer.get("person").textValue(), signer.get("key").textValue()).get("seed").textValue());
      SignResult r = OfflineApproval.signChallengeEnvelope(
          c.get("envelope").textValue(), key, c.get("signerDid").textValue(), at(c));
      assertEquals(c.get("ok").booleanValue(), r.ok(), name(c) + ": " + r.reason());
      if (!r.ok()) {
        assertReason(c, r.reason());
        assertNull(r.envelope(), name(c));
        return;
      }
      ApprovalWitness w = OfflineApproval.decodeSignatureEnvelope(r.envelope()).witness();
      JsonNode e = c.get("expect");
      assertEquals(e.get("signerDid").textValue(), w.signerDid(), name(c));
      assertEquals(e.get("signerPublicKey").textValue(), w.signerPublicKey(), name(c));
      assertEquals(e.get("sigAlg").textValue(), w.sigAlg(), name(c));
      String payload = OfflineApproval.decodeChallengeEnvelope(c.get("envelope").textValue()).challenge().canonicalPayload();
      assertTrue(verifyWithSpki(e.get("signerPublicKey").textValue(), payload, w.signature()), name(c));
    }));
  }

  @TestFactory
  Stream<DynamicNode> offlineApproval() {
    return cases("offlineApproval").map(c -> DynamicTest.dynamicTest(name(c), () -> {
      Path dir = Files.createTempDirectory(scratch, "case-");
      Files.writeString(dir.resolve("trust-bundle.jws"), c.path("bundleJws").asText(V.get("bundleJws").textValue()));
      Files.writeString(dir.resolve("gateway-key.jwk.json"), JSON.writeValueAsString(V.get("gatewayJwk")));
      Path delegationDir = null;
      if (c.hasNonNull("delegation") || c.path("delegationArtifacts").isArray()) {
        String delegation = c.path("delegation").asText();
        delegationDir = dir.resolve("delegations");
        Files.createDirectory(delegationDir);
        if (c.path("delegationArtifacts").isArray()) {
          for (int i = 0; i < c.path("delegationArtifacts").size(); i++) {
            Files.writeString(delegationDir.resolve(String.format("00-invalid-%02d.json", i)),
                JSON.writeValueAsString(c.path("delegationArtifacts").get(i)));
          }
        }
        if (c.hasNonNull("delegation")) {
          Files.writeString(delegationDir.resolve(delegation + ".json"),
              JSON.writeValueAsString(V.get("delegations").get(delegation)));
        }
      }
      JsonNode action = c.get("action");
      List<String> warnings = new ArrayList<>();
      String requesterDid = c.has("requesterDid")
          ? c.get("requesterDid").textValue() : V.get("requesterDid").textValue();
      OfflineApprovalOptions.Builder opts = OfflineApprovalOptions.builder()
          .bundleDir(dir)
          .requesterDid(requesterDid)
          .asOf(at(c))
          .warn(warnings::add)
          .collectSignatures(challenge -> {
            List<String> out = new ArrayList<>();
            for (JsonNode s : c.get("signers")) {
              if (s.has("raw")) {
                out.add(s.get("raw").textValue());
                continue;
              }
              String who = s.get("person").textValue();
              String kind = s.get("key").textValue();
              String claim = s.hasNonNull("claimDid") ? s.get("claimDid").textValue() : who;
              out.add(OfflineApproval.encodeSignatureEnvelope(new ApprovalWitness(
                  person(claim).get("did").textValue(),
                  keyOf(who, kind).get("spki").textValue(),
                  sign(who, kind, challenge.canonicalPayload()),
                  "ES256",
                  null,
                  null)));
            }
            return out;
          });
      if (delegationDir != null) {
        opts.delegationDir(delegationDir);
      }
      if (c.path("bufferFailure").asBoolean()) {
        Path buffer = dir.resolve("not-a-directory");
        Files.writeString(buffer, "buffer failure");
        opts.bufferDir(buffer);
      }
      OfflineApprovalResult r = OfflineApproval.useOfflineApproval(
          new OfflineAction(
              action.get("target").textValue(),
              action.get("actionType").textValue(),
              action.get("display").textValue(),
              map(action.get("params"))),
          opts.build());
      assertEquals(c.get("ok").booleanValue(), r.ok(), name(c) + ": " + r.reason());
      if (c.path("bufferFailure").asBoolean()) {
        assertTrue(r.reason().contains("could not buffer"));
        try (var entries = Files.list(dir.resolve(".redeemed"))) { assertEquals(0, entries.count()); }
      }
      if (!r.ok()) {
        assertReason(c, r.reason());
        assertNull(r.receipt(), name(c));
        return;
      }
      List<String> signers = new ArrayList<>(r.signers());
      signers.sort(Comparator.naturalOrder());
      assertEquals(strings(c.get("expect").get("signers")), signers, name(c));
      JsonNode via = c.get("expect").get("viaDelegation");
      assertEquals(via == null || via.isNull() ? null : via.textValue(), r.viaDelegation(), name(c));
      assertTrue(warnings.stream().anyMatch(w -> w.contains("OFFLINE APPROVAL USED")), "never quiet: " + warnings);
    }));
  }
}
