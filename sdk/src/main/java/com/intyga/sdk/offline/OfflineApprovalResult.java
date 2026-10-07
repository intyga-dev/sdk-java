package com.intyga.sdk.offline;

import com.intyga.verify.ApprovalReceipt;
import java.util.List;

/**
 * Outcome of {@link OfflineApproval#useOfflineApproval}. When {@code ok}: the verified receipt, the
 * redeemed nonce, who actually signed (verified against the trust bundle, sorted), and the
 * delegation's own nonce when a delegation supplied the approver set (null otherwise).
 */
public record OfflineApprovalResult(
    boolean ok,
    String reason,
    ApprovalReceipt receipt,
    String nonce,
    List<String> signers,
    String viaDelegation) {
  static OfflineApprovalResult refuse(String reason) {
    return new OfflineApprovalResult(false, reason, null, null, null, null);
  }
}
