package com.intyga.verify;

import java.util.List;

/**
 * Verification outcome. {@code autoApproved} reports that the receipt was pre-approved by policy
 * and carries no human signature, on both the accepted and the refused path. {@code signers} lists
 * the distinct approver IDENTITIES whose signatures verified, sorted, on the accepted signature
 * path only — empty for AUTO_APPROVED and on every refusal.
 */
public record VerifyResult(boolean ok, String reason, boolean autoApproved, List<String> signers) {

  static VerifyResult refuse(String reason) {
    return new VerifyResult(false, reason, false, List.of());
  }

  static VerifyResult refuseAutoApproved(String reason) {
    return new VerifyResult(false, reason, true, List.of());
  }

  static VerifyResult acceptAutoApproved() {
    return new VerifyResult(true, null, true, List.of());
  }

  static VerifyResult accept(List<String> signers) {
    return new VerifyResult(true, null, false, signers);
  }
}
