package com.intyga.verify;

import java.util.List;

/**
 * The approval policy in force, frozen at challenge creation and SIGNED into the intent payload.
 * Without it in the signed bytes a 3-of-3 hardware-pinned receipt is indistinguishable from a
 * 1-of-1 one, so a relying party would have to trust the gateway for the policy.
 *
 * <p>Offline checkability differs per field: requiredApprovals and requesterCannotApprove are fully
 * verifiable; requireHardwareKey only partially (an assertion proves WebAuthn, not the
 * authenticator model); allowedAaguids not at all — but a non-empty allowlist is refused exactly like
 * requireHardwareKey for bare-key and offline witnesses. signerClass is partially checkable — but the
 * verifier's own rule is absolute: refuse any value it does not recognize ("human" is the only
 * class defined today, DIV §4.3.2).
 */
public record ApprovalRequirement(
    int requiredApprovals,
    boolean requireHardwareKey,
    List<String> allowedAaguids,
    boolean requesterCannotApprove,
    String signerClass) {

  /**
   * requireHardwareKey, or a non-empty allowedAaguids model allowlist. A bare key satisfies neither
   * and neither can be met offline (DIV §4.3.2), so every check treats them alike.
   */
  public boolean requiresHardwareCredential() {
    return requireHardwareKey || (allowedAaguids != null && !allowedAaguids.isEmpty());
  }
}
