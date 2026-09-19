package com.intyga.verify;

/** Caller-owned expectations for a platform receipt. */
public record PlatformExpected(
    ApproverTrustAnchor approvers,
    String payloadHash,
    String rpId,
    String nonce,
    String subjectExternalId) {}
