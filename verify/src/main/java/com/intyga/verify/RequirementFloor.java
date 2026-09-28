package com.intyga.verify;

/**
 * The MINIMUM approval requirement the relying party's own policy demands for this action (DIV §5
 * step 3d).
 *
 * <p>The signed requirement is authored by whoever composed the bytes the approvers signed — the
 * issuer, or any one approver composing their own payload — so its signature protects it against
 * third parties but NOT against the signers the quorum constrains. Without a floor a verifier proves
 * only the signers' OWN stated quorum: an approver who is also the requester can sign
 * {@code {requiredApprovals: 1, requesterCannotApprove: false}} alone and it verifies.
 *
 * <p>Only strictly weaker signed values are refused; an equal or stricter one passes and the SIGNED
 * value is then enforced. {@code allowedAaguids} is not floored — express that as
 * {@code requireHardwareKey}.
 *
 * @param requiredApprovals integer ≥ 1; the signed requiredApprovals must be at least this
 * @param requesterCannotApprove when true, the signed requirement must also forbid the requester approving
 * @param requireHardwareKey when true, the signed requirement must also demand a hardware key
 */
public record RequirementFloor(
    int requiredApprovals, boolean requesterCannotApprove, boolean requireHardwareKey) {

  /** The reason stem every port uses for a signed requirement below the caller's floor. */
  public static final String WEAKER_REASON =
      "signed requirement is weaker than the relying party's policy";

  /** A quorum-only floor. */
  public static RequirementFloor ofQuorum(int requiredApprovals) {
    return new RequirementFloor(requiredApprovals, false, false);
  }

  /**
   * DIV §5 step 3d. Returns null when {@code floor} is null (no floor supplied — legacy behaviour) or
   * the signed requirement meets it; otherwise the refusal reason. A malformed floor fails CLOSED
   * rather than silently meaning "no floor".
   */
  static String problem(ApprovalRequirement signed, RequirementFloor floor) {
    if (floor == null) return null;
    if (floor.requiredApprovals() < 1) {
      return "expected.requirement is malformed: requiredApprovals must be an integer of at least 1";
    }
    if (signed.requiredApprovals() < floor.requiredApprovals()) {
      return WEAKER_REASON + ": it requires " + signed.requiredApprovals() + " approval(s), the policy "
          + floor.requiredApprovals() + " (DIV §5 step 3d)";
    }
    if (floor.requesterCannotApprove() && !signed.requesterCannotApprove()) {
      return WEAKER_REASON + ": it does not forbid the requester approving (DIV §5 step 3d)";
    }
    if (floor.requireHardwareKey() && !signed.requireHardwareKey()) {
      return WEAKER_REASON + ": it does not require a hardware key (DIV §5 step 3d)";
    }
    return null;
  }
}
