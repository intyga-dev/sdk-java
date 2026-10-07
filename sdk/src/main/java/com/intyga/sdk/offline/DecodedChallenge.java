package com.intyga.sdk.offline;

import com.intyga.verify.ApprovalRequirement;
import com.intyga.verify.RequesterIdentity;
import java.util.Map;

/**
 * A {@code DIV1:} envelope, decoded and proven canonical — what an approver's signing tool shows
 * before asking for confirmation. Show all of it, and have the approver confirm {@code
 * verificationCode} with the operator, before signing (DIV §5a.8).
 */
public record DecodedChallenge(
    String canonicalPayload,
    String verificationCode,
    String target,
    String actionType,
    String display,
    Map<String, Object> params,
    RequesterIdentity requester,
    ApprovalRequirement requirement,
    String nonce,
    String challengedAt,
    String expiresAt) {}
