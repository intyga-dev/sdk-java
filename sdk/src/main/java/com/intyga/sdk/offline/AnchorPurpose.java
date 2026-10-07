package com.intyga.sdk.offline;

/**
 * What a trust-bundle anchor will verify, and so which keys it admits.
 *
 * <p>{@link #ORDINARY} admits {@code publicKeys} only, and is what a delegation (or an ordinary
 * intent) is checked against. {@link #OFFLINE_INTENT} also admits {@code offlinePublicKeys}, and is
 * only for verifying a {@code div-offline-intent} proof: a bare offline key that could seal a
 * delegation would hand its holder the approval authority the delegation transfers (DIV §5a.4).
 */
public enum AnchorPurpose {
  /** {@code "ordinary"} in the reference. The default. */
  ORDINARY,
  /** {@code "offline-intent"} in the reference. */
  OFFLINE_INTENT
}
