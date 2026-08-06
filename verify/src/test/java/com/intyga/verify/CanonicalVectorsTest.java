package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.core.type.TypeReference;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Drives the shared cross-language golden vectors in packages/mcp-schemas/vectors — the same file
 * the TS, Go, Rust and Python suites consume — so every language stays byte-identical. Any
 * divergence here means a signature produced by one implementation fails to verify under another
 * and reads as tampering.
 */
class CanonicalVectorsTest {

  private static JsonNode load() {
    try {
      return Records.JSON.readTree(
          Files.readString(Path.of("vectors", "canonical-vectors.json")));
    } catch (IOException e) {
      throw new IllegalStateException("read canonical vectors: " + e.getMessage(), e);
    }
  }

  private static int canonicalVersion(String canonical) {
    try {
      return Records.JSON.readTree(canonical).path("v").asInt(0);
    } catch (IOException e) {
      return 0;
    }
  }

  private static String canonicalNonce(String canonical) {
    try {
      return Records.JSON.readTree(canonical).path("nonce").asText("");
    } catch (IOException e) {
      return "";
    }
  }

  private static Map<String, Object> paramsOf(JsonNode input) {
    if (input.get("params") == null || input.get("params").isNull()) {
      return new LinkedHashMap<>();
    }
    return Records.JSON.convertValue(input.get("params"), new TypeReference<Map<String, Object>>() {});
  }

  private static RequesterIdentity requesterOf(JsonNode input) {
    return Records.JSON.convertValue(input.get("requester"), RequesterIdentity.class);
  }

  private static ApprovalRequirement requirementOf(JsonNode input) {
    return Records.JSON.convertValue(input.get("requirement"), ApprovalRequirement.class);
  }

  /**
   * Rebuilds the relying party's expectation from the receipt's echoes, exactly as the Go/TS
   * consumers do. Legitimate for a golden vector only: the committed file IS the out-of-band
   * record a real relying party would hold.
   */
  private static Expected expectationFor(ApprovalReceipt receipt, ApproverTrustAnchor anchor) {
    Map<String, Object> params =
        receipt.params() == null ? new LinkedHashMap<>() : receipt.params();
    return new Expected(
        receipt.target() == null ? "" : receipt.target(),
        canonicalNonce(receipt.canonicalPayload()),
        receipt.actionType() == null ? "" : receipt.actionType(),
        params,
        anchor);
  }

  private static ApproverTrustAnchor didAnchor(JsonNode approvers) {
    List<String> dids = new ArrayList<>();
    Map<String, List<String>> byDid = new HashMap<>();
    for (JsonNode a : approvers) {
      String did = a.get("did").asText();
      dids.add(did);
      byDid.put(did, Records.JSON.convertValue(a.get("keys"), new TypeReference<List<String>>() {}));
    }
    return ApproverTrustAnchor.ofDidsMultiKey(dids, byDid::get);
  }

  private static String sortedCsv(List<String> items) {
    List<String> copy = new ArrayList<>(items);
    copy.sort(String::compareTo);
    return String.join(",", copy);
  }

  @Test
  void sharedStableStringifyVectors() {
    JsonNode doc = load();
    JsonNode cases = doc.get("stableStringify");
    assertNotNull(cases);
    assertTrue(cases.size() > 0, "canonical-vectors.json carries no stableStringify cases");
    for (JsonNode c : cases) {
      Object value = Records.JSON.convertValue(c.get("value"), Object.class);
      String got = Canonical.stableStringify(value);
      assertEquals(c.get("expected").asText(), got, "stableStringify[" + c.get("name").asText() + "]");
    }
  }

  @Test
  void sharedGoldenReceiptVectors() {
    JsonNode doc = load();
    int checked = 0;
    for (JsonNode entry : doc.get("receipts")) {
      ApprovalReceipt receipt = Records.JSON.convertValue(entry.get("receipt"), ApprovalReceipt.class);
      String sigAlg = receipt.sigAlg() == null ? "" : receipt.sigAlg();
      if ("WEBAUTHN".equals(sigAlg)
          || (!"AUTO_APPROVED".equals(sigAlg)
              && canonicalVersion(receipt.canonicalPayload()) != Div.VERSION)) {
        continue;
      }
      String signerKey = receipt.signerPublicKey() == null ? "" : receipt.signerPublicKey();
      Expected expected = expectationFor(receipt, ApproverTrustAnchor.ofPublicKeys(List.of(signerKey)));
      VerifyResult result = Verify.verifyApprovalReceipt(receipt, expected, VerifyOptions.defaults());
      assertEquals(
          entry.get("expectOk").asBoolean(),
          result.ok(),
          "vector " + entry.get("name").asText() + " (reason=" + result.reason() + ")");
      checked++;
    }
    assertTrue(checked >= 3, "expected to exercise the current-version vectors, ran " + checked);
  }

  @Test
  void intentCanonicalParity() {
    JsonNode doc = load();
    JsonNode cases = doc.get("intentPayloads");
    assertTrue(cases != null && cases.size() > 0, "no intent-payload vectors present");
    for (JsonNode c : cases) {
      JsonNode in = c.get("input");
      String got = Canonical.canonicalIntentPayload(
          in.get("target").asText(),
          in.get("actionType").asText(),
          in.get("actionDescription").asText(),
          paramsOf(in),
          requesterOf(in),
          requirementOf(in),
          in.get("nonce").asText(),
          in.get("expiresAt").asText());
      assertEquals(c.get("expected").asText(), got, "intent vector " + in.get("actionType").asText());
      assertTrue(got.contains("\"type\":\"div-intent-verification\""));
    }
  }

  @Test
  void offlineCanonicalParity() {
    JsonNode doc = load();
    JsonNode cases = doc.get("offlineIntentPayloads");
    assertTrue(cases != null && cases.size() > 0, "no offline-approval vectors present");
    for (JsonNode c : cases) {
      JsonNode in = c.get("input");
      String got = Canonical.canonicalOfflineIntentPayload(
          in.get("target").asText(),
          in.get("actionType").asText(),
          in.get("actionDescription").asText(),
          paramsOf(in),
          requesterOf(in),
          requirementOf(in),
          in.get("nonce").asText(),
          in.get("challengedAt").asText(),
          in.get("expiresAt").asText());
      assertEquals(c.get("expected").asText(), got, "offline vector " + in.get("actionType").asText());
      assertTrue(got.contains("\"type\":\"div-offline-intent\""));
    }
  }

  @Test
  void delegationCanonicalParity() {
    JsonNode doc = load();
    JsonNode cases = doc.get("delegationPayloads");
    assertTrue(cases != null && cases.size() > 0, "no delegation vectors present");
    for (JsonNode c : cases) {
      JsonNode in = c.get("input");
      String got = Canonical.canonicalDelegationPayload(
          in.get("target").asText(),
          in.get("actionType").asText(),
          in.get("actionDescription").asText(),
          paramsOf(in),
          requesterOf(in),
          requirementOf(in),
          Records.JSON.convertValue(in.get("delegatedTo"), new TypeReference<List<String>>() {}),
          in.get("delegatedQuorum").asInt(),
          in.get("nonce").asText(),
          in.get("sealedAt").asText(),
          in.get("expiresAt").asText());
      assertEquals(c.get("expected").asText(), got, "delegation vector " + in.get("actionType").asText());
      assertTrue(got.contains("\"type\":\"div-delegation\""));
      // UTF-16 code-unit order: U+1F600 before U+FFFD. UTF-8-byte order would put them the other
      // way round, so this line is what pins the comparator, not merely "sorted".
      assertTrue(
          got.contains(
              "\"delegatedTo\":[\"did:intyga:sre-a\",\"did:intyga:sre-c\",\"did:intyga:sre-😀\",\"did:intyga:sre-�\"]"),
          "delegatedTo was not canonicalized as a sorted set: " + got);
    }
  }

  @Test
  void offlineKindsNeverCollide() {
    JsonNode doc = load();
    for (JsonNode c : doc.get("offlineIntentPayloads")) {
      JsonNode in = c.get("input");
      String offline = Canonical.canonicalOfflineIntentPayload(
          in.get("target").asText(), in.get("actionType").asText(),
          in.get("actionDescription").asText(), paramsOf(in), requesterOf(in), requirementOf(in),
          in.get("nonce").asText(), in.get("challengedAt").asText(), in.get("expiresAt").asText());
      String intent = Canonical.canonicalIntentPayload(
          in.get("target").asText(), in.get("actionType").asText(),
          in.get("actionDescription").asText(), paramsOf(in), requesterOf(in), requirementOf(in),
          in.get("nonce").asText(), in.get("expiresAt").asText());
      assertNotEquals(intent, offline, "offline and intent payloads collide");
    }
  }

  @Test
  void sharedQuorumReceiptVectors() {
    JsonNode doc = load();
    JsonNode suite = doc.get("quorumReceipts");
    assertTrue(suite != null && suite.get("cases").size() > 0,
        "canonical-vectors.json carries no quorumReceipts cases");
    ApproverTrustAnchor anchor = didAnchor(suite.get("approvers"));
    for (JsonNode c : suite.get("cases")) {
      ApprovalReceipt receipt = Records.JSON.convertValue(c.get("receipt"), ApprovalReceipt.class);
      VerifyResult res =
          Verify.verifyApprovalReceipt(receipt, expectationFor(receipt, anchor), VerifyOptions.defaults());
      String name = c.get("name").asText();
      assertEquals(c.get("expectOk").asBoolean(), res.ok(), name + " (reason=" + res.reason() + ")");
      if (c.hasNonNull("expectSigners")) {
        List<String> want =
            Records.JSON.convertValue(c.get("expectSigners"), new TypeReference<List<String>>() {});
        assertEquals(sortedCsv(want), sortedCsv(res.signers()), name + ": signers");
      }
      if (!c.get("expectOk").asBoolean() && c.hasNonNull("expectReasonIncludes")) {
        String needle = c.get("expectReasonIncludes").asText();
        assertTrue(res.reason() != null && res.reason().contains(needle),
            name + ": reason " + res.reason() + " does not include " + needle);
      }
    }
  }

  @Test
  void sharedOfflineReceiptVectors() {
    JsonNode doc = load();
    JsonNode cases = doc.get("offlineReceipts");
    assertTrue(cases != null && cases.size() > 0,
        "canonical-vectors.json carries no offlineReceipts cases");
    ApproverTrustAnchor anchor = ApproverTrustAnchor.ofPublicKeys(
        List.of(doc.get("signerKey").get("spkiB64").asText()));
    for (JsonNode c : cases) {
      ApprovalReceipt receipt = Records.JSON.convertValue(c.get("receipt"), ApprovalReceipt.class);
      Expected expected = expectationFor(receipt, anchor);
      String name = c.get("name").asText();
      VerifyResult withOptIn = Verify.verifyApprovalReceipt(
          receipt, expected, VerifyOptions.builder().allowOffline(true).build());
      assertEquals(c.get("expectOkWithOptIn").asBoolean(), withOptIn.ok(),
          name + " (reason=" + withOptIn.reason() + ")");
      // Optional in the vector file — absent means "not asserted", matching the Go suite.
      if (c.path("refusedWithoutOptIn").asBoolean(false)) {
        assertFalse(
            Verify.verifyApprovalReceipt(receipt, expected, VerifyOptions.defaults()).ok(),
            name + " must be refused without the offline opt-in");
      }
    }
  }

  @Test
  void sharedDelegationReceiptVectors() {
    JsonNode doc = load();
    JsonNode suite = doc.get("delegationReceipts");
    assertTrue(suite != null && suite.get("cases").size() > 0,
        "canonical-vectors.json carries no delegationReceipts cases");
    ApproverTrustAnchor anchor = didAnchor(suite.get("approvers"));
    for (JsonNode c : suite.get("cases")) {
      ApprovalReceipt receipt = Records.JSON.convertValue(c.get("receipt"), ApprovalReceipt.class);
      DelegationVerification out =
          Verify.verifyDelegation(receipt, expectationFor(receipt, anchor), VerifyOptions.defaults());
      String name = c.get("name").asText();
      assertEquals(c.get("expectOk").asBoolean(), out.result().ok(),
          name + " (reason=" + out.result().reason() + ")");
      if (!c.get("expectOk").asBoolean()) {
        assertNull(out.delegation(), name + ": a refused delegation must not return a VerifiedDelegation");
        continue;
      }
      assertNotNull(out.delegation(), name + ": accepted delegation is missing its VerifiedDelegation");
      List<String> want =
          Records.JSON.convertValue(c.get("delegatedTo"), new TypeReference<List<String>>() {});
      assertEquals(sortedCsv(want), sortedCsv(out.delegation().delegatedTo()), name + ": delegatedTo");
      assertEquals(c.get("delegatedQuorum").asInt(), out.delegation().delegatedQuorum(),
          name + ": delegatedQuorum");
    }
  }
}
