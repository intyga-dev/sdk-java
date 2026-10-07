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
  PENDING,
  /**
   * An OFFLINE APPROVAL authorized this — real human signatures, collected out of band at incident
   * time because the gateway could not be reached (DIV §5a). Only {@link IntygaClient#requireApproval}
   * with per-call offline options ever returns it.
   *
   * <p>Deliberately NOT {@link #APPROVED}: the usual guard is {@code if (r.status() != APPROVED)
   * throw}, so a distinct status means adding offline approval to an existing service cannot
   * silently start permitting things — handling it is a conscious change at the call site.
   */
  OFFLINE_APPROVED
}
