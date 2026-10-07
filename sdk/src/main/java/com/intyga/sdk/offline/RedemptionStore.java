package com.intyga.sdk.offline;

/**
 * Records which offline nonces this relying party has already redeemed.
 *
 * <p>Single use is inherently stateful and LOCAL (DIV §5 steps 9–10). Because the relying party
 * generates its own nonce, single use within it is fully enforceable — unlike a pre-signed token,
 * which two relying parties could each redeem unaware.
 */
@FunctionalInterface
public interface RedemptionStore {
  /** Claim {@code nonce}. MUST be atomic, and MUST return false if it was already claimed. */
  boolean redeem(String nonce);
}
