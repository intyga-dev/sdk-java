package com.intyga.verify;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * Drives packages/mcp-schemas/vectors/webauthn-vector.json — the committed passkey assertion the
 * TS/Go/Rust suites also verify. The negative cases matter more than the positive one: an assertion
 * that verifies without origin/RP-ID pinning is one harvested at any relying party.
 */
class WebAuthnVectorTest {

  private record Vector(String rpId, String origin, ApprovalReceipt receipt, Expected expected) {}

  private static Vector load() {
    JsonNode doc;
    try {
      doc = Records.JSON.readTree(
          Files.readString(Path.of("vectors", "webauthn-vector.json")));
    } catch (IOException e) {
      throw new IllegalStateException("read webauthn vector: " + e.getMessage(), e);
    }
    ApprovalReceipt receipt = Records.JSON.convertValue(doc.get("receipt"), ApprovalReceipt.class);
    JsonNode exp = doc.get("expected");
    // The trust anchor is REQUIRED. For a golden vector the committed file is the enrollment
    // record, so pinning its key is the legitimate resolution step — it still comes from outside
    // the verifier.
    Expected expected = new Expected(
        exp.get("target").asText(),
        exp.get("nonce").asText(),
        exp.get("actionType").asText(),
        Records.JSON.convertValue(exp.get("params"), new TypeReference<Map<String, Object>>() {}),
        ApproverTrustAnchor.ofPublicKeys(
            List.of(receipt.signerPublicKey() == null ? "" : receipt.signerPublicKey())));
    return new Vector(doc.get("rpId").asText(), doc.get("origin").asText(), receipt, expected);
  }

  private static VerifyOptions pinned(Vector v) {
    return VerifyOptions.builder().expectedOrigin(v.origin()).expectedRpId(v.rpId()).build();
  }

  @Test
  void validVectorVerifies() {
    Vector v = load();
    VerifyResult res = Verify.verifyApprovalReceipt(v.receipt(), v.expected(), pinned(v));
    assertTrue(res.ok(), "valid WebAuthn receipt should verify, got reason=" + res.reason());
  }

  @Test
  void rejectsWrongOrigin() {
    Vector v = load();
    VerifyResult res = Verify.verifyApprovalReceipt(
        v.receipt(),
        v.expected(),
        VerifyOptions.builder()
            .expectedOrigin("https://evil.example.com")
            .expectedRpId(v.rpId())
            .build());
    assertFalse(res.ok(), "assertion for a different origin must not verify");
  }

  @Test
  void rejectsWrongRpId() {
    Vector v = load();
    VerifyResult res = Verify.verifyApprovalReceipt(
        v.receipt(),
        v.expected(),
        VerifyOptions.builder()
            .expectedOrigin(v.origin())
            .expectedRpId("evil.example.com")
            .build());
    assertFalse(res.ok(), "assertion for a different RP ID must not verify");
  }

  @Test
  void failsClosedWithoutPinning() {
    Vector v = load();
    VerifyResult res =
        Verify.verifyApprovalReceipt(v.receipt(), v.expected(), VerifyOptions.defaults());
    assertFalse(res.ok(), "WebAuthn receipt must fail closed without expectedOrigin/expectedRpId");
  }

  @Test
  void rejectsForgedSignature() {
    Vector v = load();
    ApprovalReceipt r = v.receipt();
    ApprovalReceipt forged = new ApprovalReceipt(
        r.canonicalPayload(), r.target(), r.actionType(), r.actionDescription(), r.params(),
        r.signatures(), r.signerDid(), r.signerPublicKey(),
        "Zm9yZ2VkLXNpZ25hdHVyZS10b3RhbC1nYXJiYWdl", r.sigAlg(), r.authenticatorData(),
        r.clientDataJSON(), r.requester(), r.verificationCode());
    assertFalse(
        Verify.verifyApprovalReceipt(forged, v.expected(), pinned(v)).ok(),
        "forged WebAuthn signature must not verify");
  }

  @Test
  void rejectsTamperedParams() {
    Vector v = load();
    Expected tampered = new Expected(
        v.expected().target(),
        v.expected().nonce(),
        v.expected().actionType(),
        Map.of("amount", 999999),
        v.expected().approvers());
    assertFalse(
        Verify.verifyApprovalReceipt(v.receipt(), tampered, pinned(v)).ok(),
        "tampered params must not verify");
  }
}
