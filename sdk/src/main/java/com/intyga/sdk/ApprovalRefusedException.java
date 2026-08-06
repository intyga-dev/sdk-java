package com.intyga.sdk;

/**
 * The human said no — or the wait ended without a yes ({@code DENIED}, {@code EXPIRED},
 * {@code CONSUMED}). Thrown by {@link IntygaClient#requireApprovalOrThrow} so a refusal propagates
 * as an exception and can never be mistaken for a successful tool/handler result.
 */
public final class ApprovalRefusedException extends IntygaException {
  private final ApprovalStatus status;

  public ApprovalRefusedException(ApprovalStatus status, String message) {
    super(message);
    this.status = status;
  }

  /** The terminal challenge status that caused the refusal. */
  public ApprovalStatus status() {
    return status;
  }
}
