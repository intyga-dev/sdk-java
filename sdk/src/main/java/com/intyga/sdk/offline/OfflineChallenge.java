package com.intyga.sdk.offline;

import com.intyga.verify.ApprovalRequirement;
import com.intyga.verify.RequesterIdentity;
import java.util.List;
import java.util.Map;

/**
 * A locally generated offline challenge, ready to hand to the approvers.
 *
 * @param nonce generated HERE, by the party that will redeem it (DIV §5a.2) — nobody else can
 *     enforce its single use
 * @param canonicalPayload the exact bytes (UTF-8) the approvers sign
 * @param verificationCode the short code each approver MUST read back to the operator before
 *     signing (DIV §5a.8)
 * @param envelope {@code DIV1:<base64url>} — what travels to the approver, by QR or copy-paste
 * @param challengedAt {@code toISOString()} form
 * @param expiresAt {@code toISOString()} form
 * @param requirement the signed requirement — from the trust bundle, never from the caller
 * @param approverDids which approvers are eligible, per the bundle rule (or the delegation) that
 *     produced {@code requirement}
 */
public record OfflineChallenge(
    String nonce,
    String canonicalPayload,
    String verificationCode,
    String envelope,
    String challengedAt,
    String expiresAt,
    String target,
    String actionType,
    String display,
    Map<String, Object> params,
    RequesterIdentity requester,
    ApprovalRequirement requirement,
    List<String> approverDids) {}
