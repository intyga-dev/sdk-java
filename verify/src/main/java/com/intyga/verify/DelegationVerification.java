package com.intyga.verify;

/**
 * Result pair of {@link Verify#verifyDelegation}: the outcome, and — only when {@code
 * result().ok()} — the {@link VerifiedDelegation} to pass as {@code VerifyOptions.delegation} when
 * verifying the offline approval signed by the delegated operators.
 */
public record DelegationVerification(VerifyResult result, VerifiedDelegation delegation) {}
