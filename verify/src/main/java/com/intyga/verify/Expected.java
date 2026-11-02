package com.intyga.verify;

import java.util.List;
import java.util.Map;

/**
 * Expected context when verifying a receipt. {@code target} and {@code nonce} are asserted from the
 * relying party's own state — never read from the receipt (DIV Target Isolation + replay binding).
 *
 * <p>{@code approvers} is REQUIRED. Verification uses a key YOU resolve, never the receipt's
 * embedded key: a receipt checked against its own key proves only internal consistency, and per the
 * DIV threat model anyone able to hand you a receipt could have minted that keypair.
 *
 * <p>{@code requirement} is STRONGLY RECOMMENDED: the minimum requirement YOUR approval rule demands
 * (see {@link RequirementFloor}). Null keeps the legacy behaviour, which enforces only the quorum the
 * signers themselves stated. Under a delegation pass the ORDINARY rule — the delegated quorum must
 * already be at least as strict (DIV §5a.5). {@code verifyDelegation} applies it to the sealing
 * requirement.
 *
 * <p>{@code enrolledDeviceKeys} are the enrolled approver device keys YOU trust (base64 SPKI or
 * COSE), from your own enrollment records — e.g. a console trust-anchor export's
 * {@code enrolledDeviceKeys}. Consulted only when the signed requirement sets
 * {@code requireEnrolledDevice}: then a witness counts only if it is ES256 and verified under one of
 * these keys, and verification is refused without the list (DIV §4.3.2). Each key must ALSO be a
 * trusted approver key for its signer in {@code approvers}; this list narrows, it never adds trust.
 */
public record Expected(
    String target,
    String nonce,
    String actionType,
    Map<String, Object> params,
    ApproverTrustAnchor approvers,
    Map<String, Object> agentContext,
    RequirementFloor requirement,
    String tenantId,
    String requesterDid,
    List<String> enrolledDeviceKeys) {
  /** Source-compatible constructor for callers predating {@code enrolledDeviceKeys}. */
  public Expected(String target, String nonce, String actionType, Map<String, Object> params,
      ApproverTrustAnchor approvers, Map<String, Object> agentContext, RequirementFloor requirement,
      String tenantId, String requesterDid) {
    this(target, nonce, actionType, params, approvers, agentContext, requirement, tenantId, requesterDid, null);
  }

  public Expected(String target, String nonce, String actionType, Map<String, Object> params,
      ApproverTrustAnchor approvers) {
    this(target, nonce, actionType, params, approvers, null, null, null, null);
  }

  public Expected(String target, String nonce, String actionType, Map<String, Object> params,
      ApproverTrustAnchor approvers, Map<String, Object> agentContext) {
    this(target, nonce, actionType, params, approvers, agentContext, null, null, null);
  }

  public Expected(String target, String nonce, String actionType, Map<String, Object> params,
      ApproverTrustAnchor approvers, Map<String, Object> agentContext, RequirementFloor requirement) {
    this(target, nonce, actionType, params, approvers, agentContext, requirement, null, null);
  }

  /** This expectation with the relying party's requirement floor (DIV §5 step 3d). */
  public Expected withRequirement(RequirementFloor floor) {
    return new Expected(target, nonce, actionType, params, approvers, agentContext, floor, tenantId, requesterDid,
        enrolledDeviceKeys);
  }

  /** This expectation with a caller-owned tenant binding (DIV v2). */
  public Expected withTenantId(String value) {
    return new Expected(target, nonce, actionType, params, approvers, agentContext, requirement, value, requesterDid,
        enrolledDeviceKeys);
  }

  /**
   * This expectation with your enrolled approver device keys (DIV §4.3.2). The list is copied; a
   * null entry is kept so the verifier can refuse it as malformed rather than drop it.
   */
  public Expected withEnrolledDeviceKeys(List<String> keys) {
    return new Expected(target, nonce, actionType, params, approvers, agentContext, requirement, tenantId,
        requesterDid, keys == null ? null : java.util.Collections.unmodifiableList(new java.util.ArrayList<>(keys)));
  }

  /** This expectation with the independently asserted requester identity. */
  public Expected withRequesterDid(String value) {
    return new Expected(target, nonce, actionType, params, approvers, agentContext, requirement, tenantId, value,
        enrolledDeviceKeys);
  }
}
