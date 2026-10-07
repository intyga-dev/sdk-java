package com.intyga.sdk.offline;

/**
 * Outcome of verifying, loading or freshness-checking a trust bundle. Never a partial success:
 * {@code bundle} is set exactly when {@code ok}, and {@code reason} exactly when not.
 */
public record TrustBundleResult(boolean ok, String reason, TrustBundle bundle) {
  static TrustBundleResult refuse(String reason) {
    return new TrustBundleResult(false, reason, null);
  }

  static TrustBundleResult accept(TrustBundle bundle) {
    return new TrustBundleResult(true, null, bundle);
  }
}
