package com.intyga.verify;

/** Caller-owned expectations for a platform receipt. */
public record PlatformExpected(
    ApproverTrustAnchor approvers,
    String payloadHash,
    String rpId,
    String nonce,
    String subjectExternalId,
    String tenantId) {
  public PlatformExpected(ApproverTrustAnchor approvers, String payloadHash, String rpId,
      String nonce, String subjectExternalId) {
    this(approvers, payloadHash, rpId, nonce, subjectExternalId, null);
  }
}
