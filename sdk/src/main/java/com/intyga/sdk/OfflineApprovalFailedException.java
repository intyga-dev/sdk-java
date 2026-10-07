package com.intyga.sdk;

/**
 * The gateway could not be asked AND the offline approval the caller opted in to did not complete
 * (no rule for the action, too few valid signatures, a stale bundle, a nonce already redeemed…).
 * The cause is the original transport failure; {@link #reason()} is the offline refusal.
 */
public final class OfflineApprovalFailedException extends IntygaException {
  private final String reason;

  public OfflineApprovalFailedException(String message, String reason, Throwable cause) {
    super(message, cause);
    this.reason = reason;
  }

  /** Why the offline approval was refused. */
  public String reason() {
    return reason;
  }
}
