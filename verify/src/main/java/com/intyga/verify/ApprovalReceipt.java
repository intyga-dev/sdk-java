package com.intyga.verify;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import java.util.List;
import java.util.Map;

/**
 * A DIV Proof Envelope: the signed canonical payload plus the signature metadata needed to verify
 * it (extended with the WebAuthn assertion components). {@code target} and {@code actionType} are
 * display/telemetry only — the relying party asserts its own in {@link Expected}.
 *
 * <p>{@code signatures} carries EVERY witness — one entry per approver; empty for AUTO_APPROVED,
 * which has no human signature. When absent, the legacy single-signature fields are used.
 */
public record ApprovalReceipt(
    String canonicalPayload,
    String target,
    String actionType,
    String actionDescription,
    Map<String, Object> params,
    List<ApprovalWitness> signatures,
    String signerDid,
    String signerPublicKey,
    String signature,
    String sigAlg,
    String authenticatorData,
    String clientDataJSON,
    RequesterIdentity requester,
    String verificationCode) {

  /** Parses a receipt from its JSON text (e.g. the raw receipt an SDK client returns). */
  public static ApprovalReceipt parse(String json) {
    try {
      return Records.JSON.readValue(json, ApprovalReceipt.class);
    } catch (JsonProcessingException e) {
      throw new IllegalArgumentException("receipt is not valid JSON: " + e.getMessage(), e);
    }
  }

  /** Parses a receipt from an already-parsed JSON tree (e.g. sdk-java's {@code ApprovalResult.receipt()}). */
  public static ApprovalReceipt parse(JsonNode json) {
    return Records.JSON.convertValue(json, ApprovalReceipt.class);
  }
}
