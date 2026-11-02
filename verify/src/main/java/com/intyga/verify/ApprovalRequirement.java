package com.intyga.verify;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
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
 *
 * <p>{@code requireEnrolledDevice} (DIV §4.3.2 "Enrolled approver devices") is {@code null} when
 * absent — the only state that leaves every historical payload's bytes unchanged — and is signed
 * only when {@code TRUE}, as the literal {@code true}. A receipt carrying any other value binds as
 * {@code FALSE} and is refused as malformed; a builder given {@code FALSE} omits the field. It is
 * defined for ordinary intents only, never with a hardware requirement.
 */
public record ApprovalRequirement(
    int requiredApprovals,
    boolean requireHardwareKey,
    List<String> allowedAaguids,
    boolean requesterCannotApprove,
    String signerClass,
    // A present JSON null binds as [""], never null: see NullIsMalformed.
    @JsonDeserialize(using = NullIsMalformed.DidList.class) List<String> excludedSignerDids,
    // Absent → null, true → TRUE, any other present value → FALSE (malformed): see NullIsMalformed.
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonDeserialize(using = NullIsMalformed.EnrolledDevice.class) Boolean requireEnrolledDevice) {

  /** Source-compatible constructor for pre-extension callers. */
  public ApprovalRequirement(int requiredApprovals, boolean requireHardwareKey,
      List<String> allowedAaguids, boolean requesterCannotApprove, String signerClass) {
    this(requiredApprovals, requireHardwareKey, allowedAaguids, requesterCannotApprove,
        signerClass, null, null);
  }

  /** Source-compatible constructor for callers predating {@code requireEnrolledDevice}. */
  public ApprovalRequirement(int requiredApprovals, boolean requireHardwareKey,
      List<String> allowedAaguids, boolean requesterCannotApprove, String signerClass,
      List<String> excludedSignerDids) {
    this(requiredApprovals, requireHardwareKey, allowedAaguids, requesterCannotApprove,
        signerClass, excludedSignerDids, null);
  }

  /**
   * requireHardwareKey, or a non-empty allowedAaguids model allowlist. A bare key satisfies neither
   * and neither can be met offline (DIV §4.3.2), so every check treats them alike.
   */
  public boolean requiresHardwareCredential() {
    return requireHardwareKey || (allowedAaguids != null && !allowedAaguids.isEmpty());
  }

  /** Whether the requirement demands an enrolled approver device ({@code requireEnrolledDevice} is TRUE). */
  public boolean requiresEnrolledDevice() {
    return Boolean.TRUE.equals(requireEnrolledDevice);
  }
}
