package com.intyga.verify;

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
 */
public record Expected(
    String target,
    String nonce,
    String actionType,
    Map<String, Object> params,
    ApproverTrustAnchor approvers,
    Map<String, Object> agentContext,
    RequirementFloor requirement) {
  public Expected(String target, String nonce, String actionType, Map<String, Object> params,
      ApproverTrustAnchor approvers) {
    this(target, nonce, actionType, params, approvers, null, null);
  }

  public Expected(String target, String nonce, String actionType, Map<String, Object> params,
      ApproverTrustAnchor approvers, Map<String, Object> agentContext) {
    this(target, nonce, actionType, params, approvers, agentContext, null);
  }

  /** This expectation with the relying party's requirement floor (DIV §5 step 3d). */
  public Expected withRequirement(RequirementFloor floor) {
    return new Expected(target, nonce, actionType, params, approvers, agentContext, floor);
  }
}
