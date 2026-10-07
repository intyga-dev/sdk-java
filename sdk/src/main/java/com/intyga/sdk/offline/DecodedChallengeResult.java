package com.intyga.sdk.offline;

/** Outcome of {@link OfflineApproval#decodeChallengeEnvelope}: {@code challenge} exactly when {@code ok}. */
public record DecodedChallengeResult(boolean ok, String reason, DecodedChallenge challenge) {
  static DecodedChallengeResult refuse(String reason) {
    return new DecodedChallengeResult(false, reason, null);
  }
}
