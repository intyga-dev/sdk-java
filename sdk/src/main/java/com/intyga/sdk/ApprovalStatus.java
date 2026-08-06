package com.intyga.sdk;

/**
 * Lifecycle state of a challenge.
 *
 * <p>{@link #CONSUMED} means the approval was real but has ALREADY BEEN REDEEMED — single-use is
 * enforced by the gateway. Treat it as not authorized: only {@link #APPROVED} permits execution.
 */
public enum ApprovalStatus {
  APPROVED,
  CONSUMED,
  DENIED,
  EXPIRED,
  PENDING
}
