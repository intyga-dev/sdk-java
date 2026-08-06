package com.intyga.verify;

import java.util.List;
import java.util.Map;

/**
 * A delegation whose own signature, quorum and window have been checked by
 * {@link Verify#verifyDelegation}. It is an INPUT to a later approval check, never a substitute for
 * one. {@code delegatedTo} is deduplicated; {@code nonce} is the delegation's OWN nonce — for the
 * audit trail, never for authorization.
 */
public record VerifiedDelegation(
    List<String> delegatedTo,
    int delegatedQuorum,
    String target,
    String actionType,
    Map<String, Object> params,
    String nonce,
    List<String> signers,
    String expiresAt) {}
