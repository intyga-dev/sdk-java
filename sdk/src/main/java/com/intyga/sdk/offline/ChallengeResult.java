package com.intyga.sdk.offline;

/** Outcome of {@link OfflineApproval#createOfflineChallenge}: {@code challenge} exactly when {@code ok}. */
public record ChallengeResult(boolean ok, String reason, OfflineChallenge challenge) {
  static ChallengeResult refuse(String reason) {
    return new ChallengeResult(false, reason, null);
  }
}
