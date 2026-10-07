package com.intyga.sdk.offline;

import com.intyga.verify.ApprovalRequirement;
import java.util.List;

/**
 * What {@link TrustBundle#requirementFor} resolved for one action.
 *
 * @param requirement {@code { requiredApprovals: max(1, n), requireHardwareKey, allowedAaguids,
 *     requesterCannotApprove, signerClass: "human" }} — the requirement an offline challenge signs
 * @param approverDids which approvers the selected rule makes eligible
 */
public record ResolvedRequirement(ApprovalRequirement requirement, List<String> approverDids) {}
