package com.intyga.sdk;

import com.fasterxml.jackson.databind.JsonNode;

/**
 * Current state of a challenge.
 *
 * @param status the lifecycle state; only {@link ApprovalStatus#APPROVED} permits execution
 * @param signatureHash hash of the approver's signature, when resolved; null otherwise
 * @param receipt the signed approval receipt as raw JSON, when resolved; null otherwise. Verify it
 *     offline with {@code com.intyga.verify.ApprovalReceipt.parse(receipt)} followed by
 *     {@code com.intyga.verify.Verify.verifyApprovalReceipt(...)}. It stays raw here so the exact
 *     bytes the gateway sent reach the verifier without a re-serialization step in between.
 * @param nonce the challenge this result belongs to. Set by {@link IntygaClient#requireApproval} so
 *     callers can pass it as the expected nonce to an offline verifier and record it as redeemed
 *     for their own single-use check; null on a bare {@link IntygaClient#status} call.
 * @param execution DEWP §4.7 execution evidence for a CONSUMED approval whose dispatch was reported
 *     ({@code status, dispatchedAt, evidenceDeadline, evidence[]}); null otherwise. Confirmed or
 *     contradicted come only from statements a registered evidence source signed — what it
 *     observed, not proof of what physically happened.
 */
public record ApprovalResult(
    ApprovalStatus status,
    String signatureHash,
    JsonNode receipt,
    String nonce,
    JsonNode agentContext,
    JsonNode execution) {

  public ApprovalResult(
      ApprovalStatus status, String signatureHash, JsonNode receipt, String nonce, JsonNode agentContext) {
    this(status, signatureHash, receipt, nonce, agentContext, null);
  }

  public ApprovalResult(ApprovalStatus status, String signatureHash, JsonNode receipt, String nonce) {
    this(status, signatureHash, receipt, nonce, null, null);
  }

  ApprovalResult withChallenge(String nonce, JsonNode context) {
    return new ApprovalResult(status, signatureHash, receipt, nonce, context, execution);
  }

  ApprovalResult withNonce(String nonce) {
    return new ApprovalResult(status, signatureHash, receipt, nonce, agentContext, execution);
  }
}
