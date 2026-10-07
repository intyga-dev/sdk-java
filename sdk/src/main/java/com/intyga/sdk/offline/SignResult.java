package com.intyga.sdk.offline;

/**
 * Outcome of {@link OfflineApproval#signChallengeEnvelope}: when {@code ok}, the {@code SIG1:}
 * envelope to send back to the operator and the challenge that was signed.
 */
public record SignResult(boolean ok, String reason, String envelope, DecodedChallenge challenge) {
  static SignResult refuse(String reason) {
    return new SignResult(false, reason, null, null);
  }
}
