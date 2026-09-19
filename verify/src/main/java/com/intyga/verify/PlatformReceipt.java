package com.intyga.verify;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;

/** A DIV §5c hash-only platform receipt. Display copies are never trust inputs. */
public record PlatformReceipt(
    String canonicalPayload,
    String payloadHash,
    String rpId,
    Subject subject,
    String signedAt,
    String expiresAt,
    String nonce,
    List<ApprovalWitness> signatures,
    String signerDid,
    String signerPublicKey,
    String signature,
    String sigAlg,
    String authenticatorData,
    String clientDataJSON,
    String verificationCode) {
  public record Subject(String externalId) {}

  public static PlatformReceipt parse(String json) {
    try { return Records.JSON.readValue(json, PlatformReceipt.class); }
    catch (JsonProcessingException e) { throw new IllegalArgumentException("platform receipt is not valid JSON", e); }
  }

  public static PlatformReceipt parse(JsonNode json) {
    return Records.JSON.convertValue(json, PlatformReceipt.class);
  }
}
