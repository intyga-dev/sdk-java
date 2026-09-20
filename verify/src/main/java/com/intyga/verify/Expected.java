package com.intyga.verify;

import java.util.Map;

/**
 * Expected context when verifying a receipt. {@code target} and {@code nonce} are asserted from the
 * relying party's own state — never read from the receipt (DIV Target Isolation + replay binding).
 *
 * <p>{@code approvers} is REQUIRED. Verification uses a key YOU resolve, never the receipt's
 * embedded key: a receipt checked against its own key proves only internal consistency, and per the
 * DIV threat model anyone able to hand you a receipt could have minted that keypair.
 */
public record Expected(
    String target,
    String nonce,
    String actionType,
    Map<String, Object> params,
    ApproverTrustAnchor approvers,
    Map<String, Object> agentContext) {
  public Expected(String target, String nonce, String actionType, Map<String, Object> params,
      ApproverTrustAnchor approvers) {
    this(target, nonce, actionType, params, approvers, null);
  }
}
