package com.intyga.sdk.offline;

import com.intyga.verify.ApprovalWitness;

/** Outcome of {@link OfflineApproval#decodeSignatureEnvelope}: {@code witness} exactly when {@code ok}. */
public record SignatureEnvelopeResult(boolean ok, String reason, ApprovalWitness witness) {
  static SignatureEnvelopeResult refuse(String reason) {
    return new SignatureEnvelopeResult(false, reason, null);
  }
}
